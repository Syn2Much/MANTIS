"""FTP honeypot service using raw asyncio protocol."""

import asyncio
from ..models import EventType
from . import BaseHoneypotService

FAKE_DIR_LISTING = """\
drwxr-xr-x   2 root root  4096 Jan 15 09:30 .
drwxr-xr-x   3 root root  4096 Jan 10 12:00 ..
-rw-r--r--   1 root root  1024 Jan 12 14:22 config.bak
-rw-------   1 root root   256 Jan 14 08:15 credentials.txt
-rw-r--r--   1 root root 51200 Jan 15 09:30 database_dump.sql
drwxr-xr-x   2 root root  4096 Jan 11 16:45 logs
-rwxr-xr-x   1 root root  8192 Jan 13 11:00 backup.sh
"""


class FTPHoneypot(BaseHoneypotService):
    service_name = "ftp"

    async def start(self):
        port = self.config.port
        banner = self.config.banner or "220 FTP Server ready."
        self._server = await asyncio.start_server(
            lambda r, w: self._handle_client(r, w, banner),
            "0.0.0.0", port,
        )
        self.logger.info("FTP honeypot listening on port %d", port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, banner: str):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        username = ""
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

                parts = line.split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "USER":
                    username = arg
                    writer.write(f"331 Password required for {arg}.\r\n".encode())
                    await writer.drain()
                    await self._log(session, EventType.AUTH_ATTEMPT, {
                        "username": arg, "stage": "user"
                    })

                elif cmd == "PASS":
                    await self._log(session, EventType.AUTH_ATTEMPT, {
                        "username": username, "password": arg, "stage": "password"
                    })
                    writer.write(b"230 Login successful.\r\n")
                    await writer.drain()

                elif cmd == "SYST":
                    writer.write(b"215 UNIX Type: L8\r\n")
                    await writer.drain()

                elif cmd == "PWD":
                    writer.write(b'257 "/home/admin" is current directory.\r\n')
                    await writer.drain()

                elif cmd == "TYPE":
                    writer.write(b"200 Type set.\r\n")
                    await writer.drain()

                elif cmd == "PASV":
                    writer.write(b"227 Entering Passive Mode (127,0,0,1,0,0).\r\n")
                    await writer.drain()

                elif cmd == "LIST" or cmd == "NLST":
                    writer.write(b"150 Opening data connection.\r\n")
                    await writer.drain()
                    await self._log(session, EventType.COMMAND, {
                        "command": line, "response": "directory listing"
                    })
                    await asyncio.sleep(0.2)
                    writer.write(b"226 Transfer complete.\r\n")
                    await writer.drain()

                elif cmd == "RETR":
                    await self._log(session, EventType.FILE_TRANSFER, {
                        "direction": "download", "filename": arg
                    })
                    writer.write(b"550 File not available.\r\n")
                    await writer.drain()

                elif cmd == "STOR":
                    await self._log(session, EventType.FILE_TRANSFER, {
                        "direction": "upload", "filename": arg
                    })
                    writer.write(b"150 Ok to send data.\r\n")
                    await writer.drain()
                    # Read some data then close
                    try:
                        await asyncio.wait_for(reader.read(65536), timeout=5)
                    except asyncio.TimeoutError:
                        pass
                    writer.write(b"226 Transfer complete.\r\n")
                    await writer.drain()

                elif cmd == "CWD":
                    await self._log(session, EventType.COMMAND, {
                        "command": line
                    })
                    writer.write(b"250 Directory changed.\r\n")
                    await writer.drain()

                elif cmd == "MKD":
                    await self._log(session, EventType.COMMAND, {"command": line})
                    writer.write(f'257 "{arg}" created.\r\n'.encode())
                    await writer.drain()

                elif cmd == "QUIT":
                    writer.write(b"221 Goodbye.\r\n")
                    await writer.drain()
                    break

                elif cmd == "FEAT":
                    writer.write(b"211-Features:\r\n UTF8\r\n211 End\r\n")
                    await writer.drain()

                elif cmd == "OPTS":
                    writer.write(b"200 OK.\r\n")
                    await writer.drain()

                else:
                    await self._log(session, EventType.COMMAND, {"command": line})
                    writer.write(f"502 Command '{cmd}' not implemented.\r\n".encode())
                    await writer.drain()

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("FTP session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
