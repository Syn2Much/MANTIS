"""MySQL honeypot service - raw asyncio protocol with handshake and query capture."""

import asyncio
import hashlib
import os
import struct

from ..models import EventType
from . import BaseHoneypotService


def _build_handshake_packet(version: str) -> bytes:
    """Build MySQL initial handshake packet (protocol v10)."""
    protocol_version = b"\x0a"
    server_version = version.encode() + b"\x00"
    connection_id = struct.pack("<I", 1)
    # Auth plugin data part 1 (8 bytes scramble)
    salt1 = os.urandom(8)
    filler = b"\x00"
    # Capability flags (lower 2 bytes)
    cap_lower = struct.pack("<H", 0xF7FF)
    charset = b"\x21"  # utf8
    status = struct.pack("<H", 0x0002)
    # Capability flags (upper 2 bytes)
    cap_upper = struct.pack("<H", 0x0081)
    # Length of auth plugin data
    auth_len = b"\x15"  # 21
    reserved = b"\x00" * 10
    # Auth plugin data part 2 (at least 13 bytes)
    salt2 = os.urandom(12) + b"\x00"
    auth_plugin = b"mysql_native_password\x00"

    payload = (protocol_version + server_version + connection_id + salt1 +
               filler + cap_lower + charset + status + cap_upper + auth_len +
               reserved + salt2 + auth_plugin)

    # MySQL packet: 3-byte length + 1-byte sequence
    length = struct.pack("<I", len(payload))[:3]
    sequence = b"\x00"
    return length + sequence + payload


def _build_ok_packet(seq: int) -> bytes:
    """Build MySQL OK packet."""
    payload = b"\x00\x00\x00\x02\x00\x00\x00"
    length = struct.pack("<I", len(payload))[:3]
    return length + bytes([seq]) + payload


def _build_err_packet(seq: int, code: int, msg: str) -> bytes:
    """Build MySQL ERR packet."""
    payload = b"\xff" + struct.pack("<H", code) + b"#28000" + msg.encode()
    length = struct.pack("<I", len(payload))[:3]
    return length + bytes([seq]) + payload


def _build_result_set(seq: int, columns: list[str], rows: list[list[str]]) -> bytes:
    """Build a simple MySQL result set."""
    packets = []

    def _make_packet(seq_num, data):
        length = struct.pack("<I", len(data))[:3]
        return length + bytes([seq_num % 256]) + data

    # Column count
    packets.append(_make_packet(seq, bytes([len(columns)])))
    seq += 1

    # Column definitions
    for col_name in columns:
        col_def = (b"\x03def"  # catalog
                   + b"\x00"    # schema
                   + b"\x00"    # table
                   + b"\x00"    # org_table
                   + bytes([len(col_name)]) + col_name.encode()  # name
                   + b"\x00"    # org_name
                   + b"\x0c"    # filler
                   + b"\x21\x00"  # charset
                   + struct.pack("<I", 255)  # column length
                   + b"\xfd"    # type: VARCHAR
                   + b"\x01\x00"  # flags
                   + b"\x00"    # decimals
                   + b"\x00\x00")  # filler
        packets.append(_make_packet(seq, col_def))
        seq += 1

    # EOF
    packets.append(_make_packet(seq, b"\xfe\x00\x00\x02\x00"))
    seq += 1

    # Rows
    for row in rows:
        row_data = b""
        for val in row:
            encoded = val.encode()
            row_data += bytes([len(encoded)]) + encoded
        packets.append(_make_packet(seq, row_data))
        seq += 1

    # EOF
    packets.append(_make_packet(seq, b"\xfe\x00\x00\x02\x00"))

    return b"".join(packets)


class MySQLHoneypot(BaseHoneypotService):
    service_name = "mysql"

    async def start(self):
        port = self.config.port
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", port,
        )
        self.logger.info("MySQL honeypot listening on port %d", port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        try:
            version = self.config.banner or "5.7.42-0ubuntu0.18.04.1"
            handshake = _build_handshake_packet(version)
            writer.write(handshake)
            await writer.drain()

            # Read auth response
            auth_data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if len(auth_data) < 4:
                return

            # Parse auth response
            username = ""
            try:
                # Skip packet header (4 bytes) + capability flags (4) + max packet (4) + charset (1) + reserved (23)
                offset = 4 + 4 + 4 + 1 + 23
                if offset < len(auth_data):
                    end = auth_data.index(b"\x00", offset)
                    username = auth_data[offset:end].decode("utf-8", errors="replace")
            except (ValueError, IndexError):
                username = "<parse_error>"

            await self._log(session, EventType.AUTH_ATTEMPT, {
                "username": username,
                "auth_data_len": len(auth_data),
            })

            # Send OK (accept all logins)
            writer.write(_build_ok_packet(2))
            await writer.drain()

            # Handle queries
            seq = 0
            while True:
                try:
                    header = await asyncio.wait_for(reader.readexactly(4), timeout=120)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                pkt_len = struct.unpack("<I", header[:3] + b"\x00")[0]
                seq = header[3]

                if pkt_len == 0:
                    break

                try:
                    body = await asyncio.wait_for(reader.readexactly(pkt_len), timeout=10)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                cmd = body[0]

                if cmd == 0x01:  # COM_QUIT
                    break

                elif cmd == 0x03:  # COM_QUERY
                    query = body[1:].decode("utf-8", errors="replace")
                    await self._log(session, EventType.QUERY, {
                        "query": query,
                        "username": username,
                    })

                    query_upper = query.strip().upper()

                    if query_upper.startswith("SELECT @@VERSION"):
                        result = _build_result_set(seq + 1, ["@@version"], [[version]])
                        writer.write(result)
                    elif query_upper.startswith("SELECT DATABASE"):
                        result = _build_result_set(seq + 1, ["database()"], [["mysql"]])
                        writer.write(result)
                    elif query_upper.startswith("SHOW DATABASES"):
                        result = _build_result_set(seq + 1, ["Database"], [
                            ["information_schema"], ["mysql"], ["performance_schema"],
                            ["production_db"], ["user_data"],
                        ])
                        writer.write(result)
                    elif query_upper.startswith("SHOW TABLES"):
                        result = _build_result_set(seq + 1, ["Tables_in_production_db"], [
                            ["users"], ["orders"], ["payments"], ["sessions"], ["api_keys"],
                        ])
                        writer.write(result)
                    elif query_upper.startswith("SELECT") or query_upper.startswith("DESCRIBE"):
                        # Empty result set
                        result = _build_result_set(seq + 1, ["result"], [])
                        writer.write(result)
                    else:
                        writer.write(_build_ok_packet(seq + 1))

                    await writer.drain()

                elif cmd == 0x02:  # COM_INIT_DB
                    db_name = body[1:].decode("utf-8", errors="replace")
                    await self._log(session, EventType.COMMAND, {
                        "command": f"USE {db_name}"
                    })
                    writer.write(_build_ok_packet(seq + 1))
                    await writer.drain()

                elif cmd == 0x0e:  # COM_PING
                    writer.write(_build_ok_packet(seq + 1))
                    await writer.drain()

                else:
                    writer.write(_build_ok_packet(seq + 1))
                    await writer.drain()

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("MySQL session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
