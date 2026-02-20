"""VNC honeypot service - RFB protocol handshake with VNC auth challenge and password capture."""

import asyncio
import os
import struct

from ..models import EventType
from . import BaseHoneypotService

# RFB protocol versions
RFB_VERSION_38 = b"RFB 003.008\n"
RFB_VERSION_37 = b"RFB 003.007\n"

# Security types
SEC_NONE = 1
SEC_VNC_AUTH = 2

# VNC Auth uses a 16-byte random challenge
VNC_CHALLENGE_LEN = 16


class VNCHoneypot(BaseHoneypotService):
    service_name = "vnc"

    async def start(self):
        port = self.config.port
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", port,
        )
        self.logger.info("VNC honeypot listening on port %d", port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        try:
            # Step 1: Server sends ProtocolVersion
            server_version = RFB_VERSION_38
            writer.write(server_version)
            await writer.drain()

            # Step 2: Client responds with their version
            try:
                client_version = await asyncio.wait_for(reader.read(12), timeout=30)
            except asyncio.TimeoutError:
                return
            if not client_version:
                return

            client_ver_str = client_version.decode("ascii", errors="replace").strip()
            await self._log(session, EventType.REQUEST, {
                "client_rfb_version": client_ver_str,
            })

            # Step 3: Server sends security types
            # Offer VNC Authentication (type 2)
            writer.write(bytes([1, SEC_VNC_AUTH]))  # 1 type, VNC Auth
            await writer.drain()

            # Step 4: Client selects security type
            try:
                selected = await asyncio.wait_for(reader.readexactly(1), timeout=15)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                return

            sec_type = selected[0]
            await self._log(session, EventType.REQUEST, {
                "selected_security_type": sec_type,
            })

            if sec_type == SEC_VNC_AUTH:
                # Step 5: VNC Authentication - send 16-byte challenge
                challenge = os.urandom(VNC_CHALLENGE_LEN)
                writer.write(challenge)
                await writer.drain()

                # Step 6: Client responds with DES-encrypted challenge (16 bytes)
                try:
                    response = await asyncio.wait_for(reader.readexactly(16), timeout=30)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    return

                await self._log(session, EventType.AUTH_ATTEMPT, {
                    "challenge": challenge.hex(),
                    "response": response.hex(),
                    "message": "VNC auth challenge/response captured (DES-encrypted password)",
                })

                # Step 7: Send SecurityResult - accept to keep the session alive
                # 0 = OK, 1 = Failed
                writer.write(struct.pack(">I", 0))  # SecurityResult OK
                await writer.drain()

                # Step 8: ClientInit - client sends shared flag
                try:
                    client_init = await asyncio.wait_for(reader.readexactly(1), timeout=15)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    return

                shared_flag = client_init[0]

                # Step 9: ServerInit - send fake framebuffer info
                fb_width = 1024
                fb_height = 768
                server_init = struct.pack(">HH", fb_width, fb_height)

                # Pixel format (16 bytes)
                pixel_format = struct.pack(
                    ">BBBBHHH BBB xxx",
                    32,    # bits-per-pixel
                    24,    # depth
                    0,     # big-endian-flag
                    1,     # true-colour-flag
                    255,   # red-max
                    255,   # green-max
                    255,   # blue-max
                    16,    # red-shift
                    8,     # green-shift
                    0,     # blue-shift
                )
                server_init += pixel_format

                # Desktop name
                desktop_name = (self.config.banner or "prod-workstation:0").encode("utf-8")
                server_init += struct.pack(">I", len(desktop_name))
                server_init += desktop_name

                writer.write(server_init)
                await writer.drain()

                await self._log(session, EventType.COMMAND, {
                    "stage": "connected",
                    "shared_flag": shared_flag,
                    "desktop_name": desktop_name.decode(),
                    "framebuffer": f"{fb_width}x{fb_height}",
                })

                # Keep reading client messages until disconnect
                while True:
                    try:
                        msg_type_data = await asyncio.wait_for(reader.read(1), timeout=120)
                    except asyncio.TimeoutError:
                        break
                    if not msg_type_data:
                        break

                    msg_type = msg_type_data[0]

                    if msg_type == 0:  # SetPixelFormat
                        try:
                            await reader.readexactly(19)  # padding(3) + pixel-format(16)
                        except asyncio.IncompleteReadError:
                            break
                    elif msg_type == 2:  # SetEncodings
                        try:
                            padding_and_count = await reader.readexactly(3)
                            num_encodings = struct.unpack(">H", padding_and_count[1:3])[0]
                            await reader.readexactly(num_encodings * 4)
                        except asyncio.IncompleteReadError:
                            break
                    elif msg_type == 3:  # FramebufferUpdateRequest
                        try:
                            await reader.readexactly(9)  # incremental(1)+x(2)+y(2)+w(2)+h(2)
                        except asyncio.IncompleteReadError:
                            break
                        # Send empty FramebufferUpdate
                        writer.write(struct.pack(">BxH", 0, 0))  # type=0, padding, 0 rectangles
                        await writer.drain()
                    elif msg_type == 4:  # KeyEvent
                        try:
                            key_data = await reader.readexactly(7)
                            down_flag = key_data[0]
                            key_sym = struct.unpack(">I", key_data[3:7])[0]
                            await self._log(session, EventType.COMMAND, {
                                "input_type": "key",
                                "key_sym": key_sym,
                                "down": bool(down_flag),
                            })
                        except asyncio.IncompleteReadError:
                            break
                    elif msg_type == 5:  # PointerEvent
                        try:
                            await reader.readexactly(5)  # button-mask(1)+x(2)+y(2)
                        except asyncio.IncompleteReadError:
                            break
                    elif msg_type == 6:  # ClientCutText
                        try:
                            header = await reader.readexactly(7)
                            text_len = struct.unpack(">I", header[3:7])[0]
                            if text_len > 0 and text_len < 65536:
                                text_data = await reader.readexactly(text_len)
                                await self._log(session, EventType.COMMAND, {
                                    "input_type": "clipboard",
                                    "text": text_data.decode("latin-1", errors="replace")[:4096],
                                })
                        except asyncio.IncompleteReadError:
                            break
                    else:
                        # Unknown message type, try to drain
                        try:
                            await reader.read(1024)
                        except Exception:
                            break

            elif sec_type == SEC_NONE:
                # No authentication - just accept
                writer.write(struct.pack(">I", 0))  # SecurityResult OK
                await writer.drain()
                await self._log(session, EventType.AUTH_ATTEMPT, {
                    "message": "Client connected with no authentication",
                })

            else:
                await self._log(session, EventType.REQUEST, {
                    "message": f"Unknown security type selected: {sec_type}",
                })

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("VNC session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
