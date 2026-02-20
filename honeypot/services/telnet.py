"""Telnet honeypot service with login capture and fake shell."""

import asyncio
from ..models import EventType
from . import BaseHoneypotService

# Subset of SSH FAKE_RESPONSES for the telnet shell
FAKE_RESPONSES = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname": "Linux",
    "uname -a": "Linux gateway-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "hostname": "gateway-01",
    "pwd": "/root",
    "ls": "backup.sh  config.bak  credentials.txt  database_dump.sql  logs",
    "ls -la": """total 68
drwx------  3 root root  4096 Jan 15 09:30 .
drwxr-xr-x 24 root root  4096 Jan 10 12:00 ..
-rw-------  1 root root   256 Jan 14 08:15 .bash_history
-rw-r--r--  1 root root  3106 Jan  5 10:00 .bashrc
-rwxr-xr-x  1 root root  8192 Jan 13 11:00 backup.sh
-rw-r--r--  1 root root  1024 Jan 12 14:22 config.bak
-rw-------  1 root root   256 Jan 14 08:15 credentials.txt
-rw-r--r--  1 root root 51200 Jan 15 09:30 database_dump.sql
drwxr-xr-x  2 root root  4096 Jan 11 16:45 logs""",
    "cat /etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:74:74:sshd:/var/run/sshd:/usr/sbin/nologin""",
    "cat credentials.txt": "admin:P@ssw0rd2024!\ndb_user:mysql_r00t_pw\napi_key:sk-proj-abc123xyz",
    "ifconfig": """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.1.15  netmask 255.255.255.0  broadcast 10.0.1.255
        ether 02:42:0a:00:01:0f  txqueuelen 0  (Ethernet)""",
    "ps aux": """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169316  9212 ?        Ss   Jan10   0:05 /sbin/init
root       456  0.0  0.0  72300  3432 ?        Ss   Jan10   0:00 /usr/sbin/sshd
root      5678  0.0  0.0  21532  1244 pts/0    R+   09:30   0:00 ps aux""",
    "uptime": " 09:30:15 up 5 days, 21:30,  1 user,  load average: 0.08, 0.03, 0.01",
    "env": """SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
USER=root""",
    "df -h": """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   23G   25G  48% /
tmpfs           2.0G     0  2.0G   0% /dev/shm""",
    "w": """ 09:30:15 up 5 days, 21:30,  1 user,  load average: 0.08, 0.03, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    attacker         09:30    0.00s  0.00s  0.00s w""",
    "netstat -tlnp": """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      456/sshd
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      789/telnetd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1234/apache2""",
    "history": """    1  apt update && apt upgrade -y
    2  vim /etc/network/interfaces
    3  systemctl restart networking
    4  cat /var/log/auth.log | tail -50
    5  ./backup.sh""",
}

# Telnet IAC constants
IAC = bytes([255])
WILL = bytes([251])
WONT = bytes([252])
DO = bytes([253])
DONT = bytes([254])
ECHO = bytes([1])
SGA = bytes([3])  # Suppress Go Ahead


class TelnetHoneypot(BaseHoneypotService):
    service_name = "telnet"

    async def start(self):
        port = self.config.port
        banner = self.config.banner or "gateway-01 login: "
        handler = lambda r, w: self._handle_client(r, w, banner)
        self._server = await asyncio.start_server(handler, "0.0.0.0", port)
        self.logger.info("Telnet honeypot listening on port %d", port)

        # Listen on additional ports (e.g. port 23 alongside 2323)
        self._extra_servers = []
        for extra_port in self.config.extra.get("additional_ports", []):
            try:
                srv = await asyncio.start_server(handler, "0.0.0.0", extra_port)
                self._extra_servers.append(srv)
                self.logger.info("Telnet honeypot also listening on port %d", extra_port)
            except OSError as e:
                self.logger.warning("Could not bind telnet to extra port %d: %s", extra_port, e)

    async def _readline(self, reader: asyncio.StreamReader, timeout: float = 60) -> str | None:
        """Read a line, stripping Telnet IAC negotiation sequences."""
        try:
            raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        if not raw:
            return None

        # Strip IAC sequences (3-byte: IAC + CMD + OPTION)
        cleaned = bytearray()
        i = 0
        while i < len(raw):
            if raw[i] == 0xFF and i + 2 < len(raw) and raw[i + 1] in (251, 252, 253, 254):
                i += 3  # Skip IAC + command + option
            elif raw[i] == 0xFF and i + 1 < len(raw) and raw[i + 1] == 0xFF:
                cleaned.append(0xFF)  # Escaped IAC
                i += 2
            else:
                cleaned.append(raw[i])
                i += 1

        return cleaned.decode("utf-8", errors="replace").strip()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, banner: str):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        username = ""
        try:
            # Send system banner
            writer.write(b"\r\nUbuntu 22.04.3 LTS\r\n\r\n")
            await writer.drain()

            # ── Login Phase ──────────────────────────────────────────────
            # Username prompt
            writer.write(banner.encode())
            await writer.drain()
            username = await self._readline(reader, timeout=30)
            if username is None:
                return

            # Password prompt with echo suppression
            writer.write(IAC + WILL + ECHO)  # Suppress echo for password
            await writer.drain()
            writer.write(b"Password: ")
            await writer.drain()
            password = await self._readline(reader, timeout=30)
            writer.write(IAC + WONT + ECHO)  # Re-enable echo
            writer.write(b"\r\n")
            await writer.drain()
            if password is None:
                password = ""

            await self._log(session, EventType.AUTH_ATTEMPT, {
                "username": username,
                "password": password,
            })

            # ── Shell Phase ──────────────────────────────────────────────
            writer.write(b"Last login: Mon Jan 15 08:45:12 2024 from 10.0.1.1\r\n")
            await writer.drain()

            prompt = f"root@gateway-01:~$ "
            writer.write(prompt.encode())
            await writer.drain()

            while True:
                line = await self._readline(reader, timeout=120)
                if line is None:
                    break

                if not line:
                    writer.write(prompt.encode())
                    await writer.drain()
                    continue

                command = line.strip()

                # Log the command
                await self._log(session, EventType.COMMAND, {
                    "command": command,
                    "username": username,
                })

                if command in ("exit", "quit", "logout"):
                    writer.write(b"logout\r\n")
                    await writer.drain()
                    break

                # Look up response
                response = FAKE_RESPONSES.get(command)
                if response is None:
                    # Prefix match
                    for k, v in FAKE_RESPONSES.items():
                        if command.startswith(k.split()[0]):
                            response = v
                            break
                if response is None:
                    if command.startswith("cd "):
                        response = ""
                    elif command.startswith("echo "):
                        response = command[5:]
                    else:
                        response = f"-bash: {command.split()[0]}: command not found"

                if response:
                    # Ensure each line ends with \r\n for telnet
                    for resp_line in response.split("\n"):
                        writer.write((resp_line + "\r\n").encode())
                    await writer.drain()

                writer.write(prompt.encode())
                await writer.drain()

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("Telnet session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
