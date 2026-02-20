"""SMTP honeypot service - captures credentials, sender/recipient info, and email data."""

import asyncio
import base64
from ..models import EventType
from . import BaseHoneypotService


class SMTPHoneypot(BaseHoneypotService):
    service_name = "smtp"

    async def start(self):
        port = self.config.port
        banner = self.config.banner or "220 mail.example.com ESMTP Postfix (Ubuntu)"
        self._server = await asyncio.start_server(
            lambda r, w: self._handle_client(r, w, banner),
            "0.0.0.0", port,
        )
        self.logger.info("SMTP honeypot listening on port %d", port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, banner: str):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        mail_from = ""
        rcpt_to = []
        auth_username = ""
        auth_state = None  # None, "wait_user", "wait_pass"

        try:
            writer.write(f"{banner}\r\n".encode())
            await writer.drain()

            while True:
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=60)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                # Handle AUTH state machine (base64 encoded user/pass)
                if auth_state == "wait_user":
                    try:
                        auth_username = base64.b64decode(line).decode("utf-8", errors="replace")
                    except Exception:
                        auth_username = line
                    writer.write(b"334 UGFzc3dvcmQ6\r\n")  # "Password:" base64
                    await writer.drain()
                    auth_state = "wait_pass"
                    continue

                if auth_state == "wait_pass":
                    try:
                        password = base64.b64decode(line).decode("utf-8", errors="replace")
                    except Exception:
                        password = line
                    await self._log(session, EventType.AUTH_ATTEMPT, {
                        "username": auth_username,
                        "password": password,
                        "mechanism": "LOGIN",
                    })
                    writer.write(b"235 2.7.0 Authentication successful\r\n")
                    await writer.drain()
                    auth_state = None
                    continue

                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "HELO":
                    await self._log(session, EventType.COMMAND, {
                        "command": "HELO", "hostname": arg,
                    })
                    writer.write(f"250 mail.example.com Hello {arg}\r\n".encode())
                    await writer.drain()

                elif cmd == "EHLO":
                    await self._log(session, EventType.COMMAND, {
                        "command": "EHLO", "hostname": arg,
                    })
                    writer.write(
                        f"250-mail.example.com Hello {arg}\r\n"
                        "250-SIZE 52428800\r\n"
                        "250-8BITMIME\r\n"
                        "250-STARTTLS\r\n"
                        "250-AUTH LOGIN PLAIN CRAM-MD5\r\n"
                        "250-ENHANCEDSTATUSCODES\r\n"
                        "250-PIPELINING\r\n"
                        "250-CHUNKING\r\n"
                        "250 SMTPUTF8\r\n".encode()
                    )
                    await writer.drain()

                elif cmd == "STARTTLS":
                    writer.write(b"454 4.7.0 TLS not available\r\n")
                    await writer.drain()

                elif cmd == "AUTH":
                    auth_parts = arg.split(" ", 1)
                    mechanism = auth_parts[0].upper() if auth_parts else ""

                    if mechanism == "LOGIN":
                        if len(auth_parts) > 1 and auth_parts[1]:
                            # Username provided inline
                            try:
                                auth_username = base64.b64decode(auth_parts[1]).decode("utf-8", errors="replace")
                            except Exception:
                                auth_username = auth_parts[1]
                            writer.write(b"334 UGFzc3dvcmQ6\r\n")
                            await writer.drain()
                            auth_state = "wait_pass"
                        else:
                            writer.write(b"334 VXNlcm5hbWU6\r\n")  # "Username:" base64
                            await writer.drain()
                            auth_state = "wait_user"

                    elif mechanism == "PLAIN":
                        # AUTH PLAIN <base64(authzid\0authcid\0passwd)>
                        plain_data = auth_parts[1] if len(auth_parts) > 1 else ""
                        if plain_data:
                            try:
                                decoded = base64.b64decode(plain_data).decode("utf-8", errors="replace")
                                plain_parts = decoded.split("\x00")
                                username = plain_parts[1] if len(plain_parts) > 1 else ""
                                password = plain_parts[2] if len(plain_parts) > 2 else ""
                            except Exception:
                                username = plain_data
                                password = ""
                            await self._log(session, EventType.AUTH_ATTEMPT, {
                                "username": username,
                                "password": password,
                                "mechanism": "PLAIN",
                            })
                            writer.write(b"235 2.7.0 Authentication successful\r\n")
                            await writer.drain()
                        else:
                            writer.write(b"334\r\n")
                            await writer.drain()
                            auth_state = "wait_user"
                    else:
                        await self._log(session, EventType.AUTH_ATTEMPT, {
                            "mechanism": mechanism, "raw": arg,
                        })
                        writer.write(b"235 2.7.0 Authentication successful\r\n")
                        await writer.drain()

                elif line.upper().startswith("MAIL FROM:"):
                    mail_from = line[10:].strip().strip("<>")
                    await self._log(session, EventType.COMMAND, {
                        "command": "MAIL FROM", "sender": mail_from,
                    })
                    writer.write(b"250 2.1.0 Ok\r\n")
                    await writer.drain()

                elif line.upper().startswith("RCPT TO:"):
                    recipient = line[8:].strip().strip("<>")
                    rcpt_to.append(recipient)
                    await self._log(session, EventType.COMMAND, {
                        "command": "RCPT TO", "recipient": recipient,
                    })
                    writer.write(b"250 2.1.5 Ok\r\n")
                    await writer.drain()

                elif cmd == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()

                    # Read email body until lone "."
                    email_lines = []
                    while True:
                        try:
                            body_line = await asyncio.wait_for(reader.readline(), timeout=30)
                        except asyncio.TimeoutError:
                            break
                        if not body_line:
                            break
                        decoded_line = body_line.decode("utf-8", errors="replace").rstrip("\r\n")
                        if decoded_line == ".":
                            break
                        email_lines.append(decoded_line)
                        if len(email_lines) > 500:
                            break

                    email_body = "\n".join(email_lines[:100])  # Log first 100 lines
                    await self._log(session, EventType.REQUEST, {
                        "command": "DATA",
                        "sender": mail_from,
                        "recipients": rcpt_to,
                        "body_preview": email_body[:4096],
                        "body_lines": len(email_lines),
                    })
                    writer.write(b"250 2.0.0 Ok: queued as FAKE1234\r\n")
                    await writer.drain()

                elif cmd == "RSET":
                    mail_from = ""
                    rcpt_to = []
                    writer.write(b"250 2.0.0 Ok\r\n")
                    await writer.drain()

                elif cmd == "NOOP":
                    writer.write(b"250 2.0.0 Ok\r\n")
                    await writer.drain()

                elif cmd == "VRFY":
                    await self._log(session, EventType.COMMAND, {
                        "command": "VRFY", "address": arg,
                    })
                    writer.write(b"252 2.0.0 Cannot VRFY user\r\n")
                    await writer.drain()

                elif cmd == "EXPN":
                    await self._log(session, EventType.COMMAND, {
                        "command": "EXPN", "list": arg,
                    })
                    writer.write(b"252 2.0.0 Cannot EXPN\r\n")
                    await writer.drain()

                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break

                else:
                    await self._log(session, EventType.COMMAND, {"command": line})
                    writer.write(f"502 5.5.2 Error: command not recognized\r\n".encode())
                    await writer.drain()

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("SMTP session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
