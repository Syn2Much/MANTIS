"""SMB honeypot - SMB1/SMB2 negotiate + NTLMSSP auth capture."""

import asyncio
import os
import struct
from datetime import datetime

from ..models import EventType
from . import BaseHoneypotService

# SMB constants
SMB1_MAGIC = b"\xffSMB"
SMB2_MAGIC = b"\xfeSMB"

# NTLMSSP constants
NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
NTLMSSP_NEGOTIATE = 1
NTLMSSP_CHALLENGE = 2
NTLMSSP_AUTH = 3


def _build_smb2_negotiate_response() -> bytes:
    """Build SMB2 Negotiate Response."""
    # SMB2 header (64 bytes)
    header = bytearray(64)
    header[0:4] = SMB2_MAGIC
    struct.pack_into("<H", header, 4, 64)     # StructureSize
    header[6:8] = b"\x00\x00"                 # CreditCharge
    struct.pack_into("<I", header, 8, 0)      # Status: SUCCESS
    struct.pack_into("<H", header, 12, 0)     # Command: NEGOTIATE
    struct.pack_into("<H", header, 14, 1)     # CreditResponse
    struct.pack_into("<I", header, 16, 0)     # Flags: Response
    struct.pack_into("<I", header, 20, 0)     # NextCommand
    struct.pack_into("<Q", header, 24, 0)     # MessageId
    struct.pack_into("<I", header, 36, 0)     # TreeId
    struct.pack_into("<Q", header, 40, 0)     # SessionId
    header[48:64] = b"\x00" * 16             # Signature

    # SMB2 Negotiate Response body
    body = bytearray(65)
    struct.pack_into("<H", body, 0, 65)       # StructureSize
    struct.pack_into("<H", body, 2, 0)        # SecurityMode: signing enabled
    struct.pack_into("<H", body, 4, 0x0311)   # DialectRevision: SMB 3.1.1
    struct.pack_into("<H", body, 6, 0)        # NegotiateContextCount
    body[8:24] = os.urandom(16)               # ServerGuid
    struct.pack_into("<I", body, 24, 0x2F)    # Capabilities
    struct.pack_into("<I", body, 28, 65536)   # MaxTransactSize
    struct.pack_into("<I", body, 32, 65536)   # MaxReadSize
    struct.pack_into("<I", body, 36, 65536)   # MaxWriteSize
    # SystemTime and ServerStartTime (8 bytes each)
    body[40:56] = b"\x00" * 16
    # SecurityBufferOffset and Length (will be filled)
    struct.pack_into("<H", body, 56, 128)     # SecurityBufferOffset (header + body)
    struct.pack_into("<H", body, 58, 0)       # SecurityBufferLength

    # Combine: NetBIOS length prefix + header + body
    packet = bytes(header) + bytes(body)
    netbios = struct.pack(">I", len(packet))
    return netbios + packet


def _build_ntlmssp_challenge() -> bytes:
    """Build NTLMSSP Challenge (Type 2) message."""
    server_challenge = os.urandom(8)
    target_name = "WORKGROUP".encode("utf-16-le")

    msg = bytearray()
    msg += NTLMSSP_SIGNATURE
    msg += struct.pack("<I", NTLMSSP_CHALLENGE)

    # Target name fields (offset filled after)
    target_name_offset = 56  # Fixed offset
    msg += struct.pack("<HHI", len(target_name), len(target_name), target_name_offset)

    # Negotiate flags
    flags = 0x00028233
    msg += struct.pack("<I", flags)

    # Server challenge
    msg += server_challenge

    # Reserved (8 bytes)
    msg += b"\x00" * 8

    # Target info fields (empty for simplicity)
    msg += struct.pack("<HHI", 0, 0, 0)

    # Pad to offset, then target name
    while len(msg) < target_name_offset:
        msg += b"\x00"
    msg += target_name

    return bytes(msg)


def _build_smb2_session_setup_response(ntlmssp_payload: bytes, session_id: int = 1, status: int = 0xC0000016) -> bytes:
    """Build SMB2 Session Setup Response with NTLMSSP token."""
    # Wrap NTLMSSP in GSS-API/SPNEGO
    spnego = _wrap_ntlmssp_in_spnego(ntlmssp_payload)

    header = bytearray(64)
    header[0:4] = SMB2_MAGIC
    struct.pack_into("<H", header, 4, 64)
    struct.pack_into("<I", header, 8, status)     # STATUS_MORE_PROCESSING_REQUIRED
    struct.pack_into("<H", header, 12, 1)         # Command: SESSION_SETUP
    struct.pack_into("<H", header, 14, 1)
    struct.pack_into("<I", header, 16, 1)         # Flags: Response
    struct.pack_into("<Q", header, 40, session_id)

    # Session Setup Response body
    body = bytearray(8)
    struct.pack_into("<H", body, 0, 9)            # StructureSize
    struct.pack_into("<H", body, 2, 0)            # SessionFlags
    sec_offset = 64 + 8
    struct.pack_into("<H", body, 4, sec_offset)   # SecurityBufferOffset
    struct.pack_into("<H", body, 6, len(spnego))  # SecurityBufferLength

    packet = bytes(header) + bytes(body) + spnego
    netbios = struct.pack(">I", len(packet))
    return netbios + packet


def _wrap_ntlmssp_in_spnego(ntlmssp: bytes) -> bytes:
    """Minimal SPNEGO wrapper for NTLMSSP token."""
    # Simple ASN.1 wrapper
    inner = b"\x04" + _asn1_length(len(ntlmssp)) + ntlmssp
    seq = b"\xa0" + _asn1_length(len(inner)) + inner
    resp = b"\xa1" + _asn1_length(len(seq) + 3) + b"\x30" + _asn1_length(len(seq) + 1) + b"\xa0" + _asn1_length(0) + seq
    return resp


def _asn1_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    else:
        return bytes([0x82]) + struct.pack(">H", length)


def _parse_ntlmssp_auth(data: bytes) -> dict:
    """Parse NTLMSSP Type 3 (Auth) message to extract credentials."""
    result = {}
    try:
        # Find NTLMSSP signature
        idx = data.find(NTLMSSP_SIGNATURE)
        if idx < 0:
            return result

        base = idx
        msg_type = struct.unpack_from("<I", data, base + 8)[0]
        if msg_type != NTLMSSP_AUTH:
            return result

        def _read_field(offset):
            length = struct.unpack_from("<H", data, base + offset)[0]
            buf_offset = struct.unpack_from("<I", data, base + offset + 4)[0]
            if length > 0 and base + buf_offset + length <= len(data):
                return data[base + buf_offset:base + buf_offset + length]
            return b""

        # LmChallengeResponse at offset 12
        lm_response = _read_field(12)
        # NtChallengeResponse at offset 20
        nt_response = _read_field(20)
        # Domain at offset 28
        domain = _read_field(28)
        # User at offset 36
        user = _read_field(36)
        # Workstation at offset 44
        workstation = _read_field(44)

        result["domain"] = domain.decode("utf-16-le", errors="replace") if domain else ""
        result["username"] = user.decode("utf-16-le", errors="replace") if user else ""
        result["workstation"] = workstation.decode("utf-16-le", errors="replace") if workstation else ""
        result["nt_response_len"] = len(nt_response)
        result["lm_response_len"] = len(lm_response)

        if nt_response:
            result["nt_hash"] = nt_response.hex()
        if lm_response:
            result["lm_hash"] = lm_response.hex()

    except Exception:
        pass
    return result


class SMBHoneypot(BaseHoneypotService):
    service_name = "smb"

    async def start(self):
        port = self.config.port
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", port,
        )
        self.logger.info("SMB honeypot listening on port %d", port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        try:
            while True:
                # Read NetBIOS header (4 bytes)
                try:
                    nb_header = await asyncio.wait_for(reader.readexactly(4), timeout=30)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                pkt_len = struct.unpack(">I", nb_header)[0]
                if pkt_len > 65536 or pkt_len < 4:
                    break

                try:
                    pkt_data = await asyncio.wait_for(reader.readexactly(pkt_len), timeout=10)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                # Check for SMB magic
                if pkt_data[:4] == SMB1_MAGIC:
                    cmd = pkt_data[4] if len(pkt_data) > 4 else 0
                    if cmd == 0x72:  # SMB1 Negotiate
                        await self._log(session, EventType.REQUEST, {
                            "smb_version": "SMB1",
                            "command": "NEGOTIATE",
                        })
                        # Respond with SMB2 negotiate to upgrade
                        writer.write(_build_smb2_negotiate_response())
                        await writer.drain()
                    else:
                        break

                elif pkt_data[:4] == SMB2_MAGIC:
                    if len(pkt_data) < 20:
                        break
                    command = struct.unpack_from("<H", pkt_data, 12)[0]

                    if command == 0:  # NEGOTIATE
                        await self._log(session, EventType.REQUEST, {
                            "smb_version": "SMB2",
                            "command": "NEGOTIATE",
                        })
                        writer.write(_build_smb2_negotiate_response())
                        await writer.drain()

                    elif command == 1:  # SESSION_SETUP
                        # Check for NTLMSSP in the packet
                        ntlmssp_idx = pkt_data.find(NTLMSSP_SIGNATURE)
                        if ntlmssp_idx >= 0:
                            msg_type_offset = ntlmssp_idx + 8
                            if msg_type_offset + 4 <= len(pkt_data):
                                msg_type = struct.unpack_from("<I", pkt_data, msg_type_offset)[0]

                                if msg_type == NTLMSSP_NEGOTIATE:
                                    # Type 1 → Send Challenge (Type 2)
                                    challenge = _build_ntlmssp_challenge()
                                    resp = _build_smb2_session_setup_response(
                                        challenge, session_id=1, status=0xC0000016
                                    )
                                    writer.write(resp)
                                    await writer.drain()
                                    await self._log(session, EventType.REQUEST, {
                                        "smb_version": "SMB2",
                                        "command": "SESSION_SETUP",
                                        "ntlmssp": "NEGOTIATE",
                                    })

                                elif msg_type == NTLMSSP_AUTH:
                                    # Type 3 → Parse credentials
                                    creds = _parse_ntlmssp_auth(pkt_data)
                                    await self._log(session, EventType.NTLM_AUTH, {
                                        **creds,
                                        "message": "NTLM authentication captured",
                                    })
                                    # Send success
                                    resp = _build_smb2_session_setup_response(
                                        b"", session_id=1, status=0
                                    )
                                    writer.write(resp)
                                    await writer.drain()
                                    break
                                else:
                                    break
                        else:
                            break
                    else:
                        break
                else:
                    break

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("SMB session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
