"""MongoDB honeypot service - wire protocol with isMaster, auth capture, and query logging."""

import asyncio
import os
import struct
import time

from ..models import EventType
from . import BaseHoneypotService

# MongoDB wire protocol opcodes
OP_REPLY = 1
OP_QUERY = 2004
OP_MSG = 2013

# Minimal BSON helpers

def _bson_encode(doc: dict) -> bytes:
    """Encode a simple dictionary to BSON (supports str, int, float, bool, list, dict, None)."""
    elements = b""
    for key, value in doc.items():
        key_bytes = key.encode("utf-8") + b"\x00"
        if isinstance(value, str):
            encoded = value.encode("utf-8") + b"\x00"
            elements += b"\x02" + key_bytes + struct.pack("<i", len(encoded)) + encoded
        elif isinstance(value, bool):
            elements += b"\x08" + key_bytes + (b"\x01" if value else b"\x00")
        elif isinstance(value, int):
            if -2**31 <= value < 2**31:
                elements += b"\x10" + key_bytes + struct.pack("<i", value)
            else:
                elements += b"\x12" + key_bytes + struct.pack("<q", value)
        elif isinstance(value, float):
            elements += b"\x01" + key_bytes + struct.pack("<d", value)
        elif isinstance(value, dict):
            sub = _bson_encode(value)
            elements += b"\x03" + key_bytes + sub
        elif isinstance(value, list):
            # Encode list as BSON array (keys are string indices)
            arr_doc = {str(i): v for i, v in enumerate(value)}
            sub = _bson_encode(arr_doc)
            elements += b"\x04" + key_bytes + sub
        elif value is None:
            elements += b"\x0a" + key_bytes
        else:
            encoded = str(value).encode("utf-8") + b"\x00"
            elements += b"\x02" + key_bytes + struct.pack("<i", len(encoded)) + encoded

    doc_bytes = elements + b"\x00"
    return struct.pack("<i", len(doc_bytes) + 4) + doc_bytes


def _bson_decode_simple(data: bytes) -> dict:
    """Decode basic BSON fields (strings, ints, bools). Best-effort."""
    result = {}
    if len(data) < 5:
        return result
    try:
        doc_len = struct.unpack_from("<i", data, 0)[0]
        pos = 4
        while pos < min(doc_len - 1, len(data) - 1):
            elem_type = data[pos]
            pos += 1
            # Read key (C-string)
            key_end = data.index(b"\x00", pos)
            key = data[pos:key_end].decode("utf-8", errors="replace")
            pos = key_end + 1

            if elem_type == 0x01:  # double
                result[key] = struct.unpack_from("<d", data, pos)[0]
                pos += 8
            elif elem_type == 0x02:  # string
                str_len = struct.unpack_from("<i", data, pos)[0]
                pos += 4
                result[key] = data[pos:pos + str_len - 1].decode("utf-8", errors="replace")
                pos += str_len
            elif elem_type == 0x03:  # document
                sub_len = struct.unpack_from("<i", data, pos)[0]
                result[key] = _bson_decode_simple(data[pos:pos + sub_len])
                pos += sub_len
            elif elem_type == 0x04:  # array
                sub_len = struct.unpack_from("<i", data, pos)[0]
                result[key] = _bson_decode_simple(data[pos:pos + sub_len])
                pos += sub_len
            elif elem_type == 0x08:  # boolean
                result[key] = data[pos] != 0
                pos += 1
            elif elem_type == 0x10:  # int32
                result[key] = struct.unpack_from("<i", data, pos)[0]
                pos += 4
            elif elem_type == 0x12:  # int64
                result[key] = struct.unpack_from("<q", data, pos)[0]
                pos += 8
            elif elem_type == 0x0a:  # null
                result[key] = None
            else:
                break  # Unknown type, stop parsing
    except Exception:
        pass
    return result


def _build_op_reply(request_id: int, response_to: int, doc: dict) -> bytes:
    """Build OP_REPLY message."""
    bson_doc = _bson_encode(doc)
    # OP_REPLY body: responseFlags(4) + cursorID(8) + startingFrom(4) + numberReturned(4) + documents
    body = struct.pack("<i", 0)  # responseFlags
    body += struct.pack("<q", 0)  # cursorID
    body += struct.pack("<i", 0)  # startingFrom
    body += struct.pack("<i", 1)  # numberReturned
    body += bson_doc

    # Message header: length(4) + requestID(4) + responseTo(4) + opCode(4)
    header = struct.pack("<iiii", 16 + len(body), request_id + 1, request_id, OP_REPLY)
    return header + body


def _build_op_msg(request_id: int, doc: dict) -> bytes:
    """Build OP_MSG response."""
    bson_doc = _bson_encode(doc)
    # OP_MSG: flagBits(4) + section kind 0 (1 byte) + BSON doc
    body = struct.pack("<I", 0)  # flagBits
    body += b"\x00"  # section kind 0 (body)
    body += bson_doc

    header = struct.pack("<iiii", 16 + len(body), request_id + 1, request_id, OP_MSG)
    return header + body


class MongoDBHoneypot(BaseHoneypotService):
    service_name = "mongodb"

    async def start(self):
        port = self.config.port
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", port,
        )
        self.logger.info("MongoDB honeypot listening on port %d", port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        version = self.config.banner or "6.0.12"

        try:
            while True:
                # Read message header (16 bytes)
                try:
                    header_data = await asyncio.wait_for(reader.readexactly(16), timeout=60)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                msg_len, request_id, response_to, opcode = struct.unpack("<iiii", header_data)

                body_len = msg_len - 16
                if body_len <= 0 or body_len > 65536:
                    break

                try:
                    body = await asyncio.wait_for(reader.readexactly(body_len), timeout=10)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                if opcode == OP_QUERY:
                    await self._handle_op_query(session, writer, request_id, body, version)

                elif opcode == OP_MSG:
                    await self._handle_op_msg(session, writer, request_id, body, version)

                else:
                    await self._log(session, EventType.COMMAND, {
                        "opcode": opcode, "body_len": body_len,
                    })

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("MongoDB session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_op_query(self, session, writer, request_id, body, version):
        """Handle legacy OP_QUERY (used by older drivers for isMaster/hello)."""
        try:
            # flags(4) + fullCollectionName (cstring) + numberToSkip(4) + numberToReturn(4) + query BSON
            flags = struct.unpack_from("<i", body, 0)[0]
            coll_end = body.index(b"\x00", 4)
            collection = body[4:coll_end].decode("utf-8", errors="replace")
            offset = coll_end + 1 + 8  # skip numberToSkip + numberToReturn
            query_doc = _bson_decode_simple(body[offset:])
        except Exception:
            query_doc = {}
            collection = ""

        await self._log(session, EventType.QUERY, {
            "protocol": "OP_QUERY",
            "collection": collection,
            "query": str(query_doc)[:2048],
        })

        # Respond to isMaster / hello
        if "isMaster" in query_doc or "ismaster" in query_doc or "hello" in query_doc:
            resp_doc = self._ismaster_response(version)
            writer.write(_build_op_reply(request_id, request_id, resp_doc))
            await writer.drain()
        else:
            resp_doc = {"ok": 1.0}
            writer.write(_build_op_reply(request_id, request_id, resp_doc))
            await writer.drain()

    async def _handle_op_msg(self, session, writer, request_id, body, version):
        """Handle OP_MSG (modern wire protocol)."""
        try:
            flag_bits = struct.unpack_from("<I", body, 0)[0]
            # Section kind at offset 4
            section_kind = body[4]
            if section_kind == 0:
                doc = _bson_decode_simple(body[5:])
            else:
                doc = {}
        except Exception:
            doc = {}

        await self._log(session, EventType.QUERY, {
            "protocol": "OP_MSG",
            "command": str(doc)[:2048],
        })

        # Check for specific commands
        if "isMaster" in doc or "ismaster" in doc or "hello" in doc:
            resp = self._ismaster_response(version)
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "saslStart" in doc:
            # SCRAM auth start - capture mechanism and payload
            mechanism = doc.get("mechanism", "")
            await self._log(session, EventType.AUTH_ATTEMPT, {
                "stage": "saslStart",
                "mechanism": mechanism,
                "db": doc.get("$db", ""),
            })
            # Send a fake conversation reply
            resp = {
                "conversationId": 1,
                "done": False,
                "payload": "",
                "ok": 1.0,
            }
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "saslContinue" in doc:
            await self._log(session, EventType.AUTH_ATTEMPT, {
                "stage": "saslContinue",
                "conversationId": doc.get("conversationId", 0),
            })
            resp = {
                "conversationId": 1,
                "done": True,
                "payload": "",
                "ok": 1.0,
            }
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "authenticate" in doc:
            await self._log(session, EventType.AUTH_ATTEMPT, {
                "username": doc.get("user", ""),
                "mechanism": doc.get("mechanism", ""),
                "db": doc.get("$db", ""),
            })
            resp = {"ok": 1.0}
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "listDatabases" in doc:
            resp = {
                "databases": [
                    {"name": "admin", "sizeOnDisk": 40960, "empty": False},
                    {"name": "config", "sizeOnDisk": 36864, "empty": False},
                    {"name": "local", "sizeOnDisk": 73728, "empty": False},
                    {"name": "production", "sizeOnDisk": 2621440, "empty": False},
                    {"name": "users", "sizeOnDisk": 524288, "empty": False},
                ],
                "totalSize": 3297280,
                "ok": 1.0,
            }
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "listCollections" in doc:
            resp = {
                "ok": 1.0,
            }
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "find" in doc or "aggregate" in doc:
            resp = {
                "cursor": {"firstBatch": [], "id": 0, "ns": "test.collection"},
                "ok": 1.0,
            }
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "ping" in doc:
            resp = {"ok": 1.0}
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "buildInfo" in doc or "buildinfo" in doc:
            resp = {
                "version": version,
                "gitVersion": "abc123",
                "modules": [],
                "sysInfo": "deprecated",
                "ok": 1.0,
            }
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        elif "serverStatus" in doc:
            resp = {
                "host": "db-prod-01:27017",
                "version": version,
                "uptime": 432000,
                "connections": {"current": 42, "available": 51158, "totalCreated": 18234},
                "ok": 1.0,
            }
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

        else:
            resp = {"ok": 1.0}
            writer.write(_build_op_msg(request_id, resp))
            await writer.drain()

    def _ismaster_response(self, version: str) -> dict:
        return {
            "ismaster": True,
            "maxBsonObjectSize": 16777216,
            "maxMessageSizeBytes": 48000000,
            "maxWriteBatchSize": 100000,
            "localTime": int(time.time()),
            "minWireVersion": 0,
            "maxWireVersion": 21,
            "readOnly": False,
            "ok": 1.0,
        }
