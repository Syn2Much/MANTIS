"""SSH honeypot using Paramiko with fake shell and command responses."""

import asyncio
import logging
import os
import threading
import uuid

import paramiko

from ..models import EventType
from . import BaseHoneypotService

logger = logging.getLogger("honeypot.ssh")

# Fake command responses for the shell
FAKE_RESPONSES = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname": "Linux",
    "uname -a": "Linux prod-web-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "hostname": "prod-web-01",
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
sys:x:3:3:sys:/dev:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
sshd:x:74:74:sshd:/var/run/sshd:/usr/sbin/nologin""",
    "cat credentials.txt": "admin:P@ssw0rd2024!\ndb_user:mysql_r00t_pw\napi_key:sk-proj-abc123xyz",
    "ifconfig": """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.1.15  netmask 255.255.255.0  broadcast 10.0.1.255
        ether 02:42:0a:00:01:0f  txqueuelen 0  (Ethernet)""",
    "ip addr": """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet 10.0.1.15/24 brd 10.0.1.255 scope global eth0""",
    "ps aux": """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169316  9212 ?        Ss   Jan10   0:05 /sbin/init
root       456  0.0  0.0  72300  3432 ?        Ss   Jan10   0:00 /usr/sbin/sshd
mysql      789  0.1  2.1 1294512 173452 ?      Sl   Jan10   1:23 /usr/sbin/mysqld
www-data  1234  0.0  0.5 356812  42108 ?       S    Jan10   0:12 apache2 -k start
root      5678  0.0  0.0  21532  1244 pts/0    R+   09:30   0:00 ps aux""",
    "netstat -tlnp": """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      456/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1234/apache2
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      789/mysqld
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      1234/apache2""",
    "env": """SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/root
LOGNAME=root
USER=root
LANG=en_US.UTF-8
TERM=xterm-256color""",
    "uptime": " 09:30:15 up 5 days, 21:30,  1 user,  load average: 0.08, 0.03, 0.01",
    "df -h": """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   23G   25G  48% /
tmpfs           2.0G     0  2.0G   0% /dev/shm
/dev/sda2       100G   67G   28G  71% /var/lib/mysql""",
    "w": """ 09:30:15 up 5 days, 21:30,  1 user,  load average: 0.08, 0.03, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    attacker         09:30    0.00s  0.00s  0.00s w""",
    "history": """    1  apt update && apt upgrade -y
    2  mysql -u root -p
    3  vim /etc/apache2/sites-available/000-default.conf
    4  systemctl restart apache2
    5  cat /var/log/auth.log | tail -50
    6  ./backup.sh
    7  scp database_dump.sql backup@10.0.1.100:/backups/""",
}


class HoneypotSSHServer(paramiko.ServerInterface):
    """Paramiko ServerInterface that accepts all auth and provides a shell."""

    def __init__(self, session_info, log_callback):
        self._session = session_info
        self._log = log_callback
        self._event = threading.Event()
        self.username = ""
        self.password = ""

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password
        self._log("auth", {"username": username, "password": password})
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        self._log("auth_pubkey", {
            "username": username,
            "key_type": key.get_name(),
            "key_fingerprint": key.get_fingerprint().hex(),
        })
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self._event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        self._event.set()
        return True


class SSHHoneypot(BaseHoneypotService):
    service_name = "ssh"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._host_key = None
        self._sock_server = None
        self._accept_thread = None
        self._running = False

    def _ensure_host_key(self):
        key_path = ".honeypot_ssh_host_key"
        if os.path.exists(key_path):
            self._host_key = paramiko.RSAKey.from_private_key_file(key_path)
        else:
            self._host_key = paramiko.RSAKey.generate(2048)
            self._host_key.write_private_key_file(key_path)
        self.logger.info("SSH host key ready (fingerprint: %s)", self._host_key.get_fingerprint().hex()[:16])

    async def start(self):
        self._ensure_host_key()
        port = self.config.port
        self._loop = asyncio.get_running_loop()

        # Use a plain socket server so Paramiko gets clean, unmanaged sockets
        import socket
        self._sock_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock_server.bind(("0.0.0.0", port))
        self._sock_server.listen(5)
        self._sock_server.settimeout(1.0)
        self._running = True

        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        self.logger.info("SSH honeypot listening on port %d", port)

    def _accept_loop(self):
        """Accept connections in a thread and hand sockets directly to Paramiko."""
        while self._running:
            try:
                client_sock, addr = self._sock_server.accept()
            except OSError:
                continue
            src_ip, src_port = addr
            t = threading.Thread(
                target=self._handle_client, args=(client_sock, src_ip, src_port),
                daemon=True,
            )
            t.start()

    def _handle_client(self, client_sock, src_ip, src_port):
        """Handle a single SSH client in its own thread."""
        loop = self._loop
        # Create session (async) from this thread
        session = asyncio.run_coroutine_threadsafe(
            self._create_session(src_ip, src_port, self.config.port), loop
        ).result(timeout=10)

        try:
            self._run_ssh_session(client_sock, session, loop)
        except Exception as e:
            self.logger.debug("SSH connection error from %s: %s", src_ip, e)
        finally:
            asyncio.run_coroutine_threadsafe(
                self._end_session(session), loop
            ).result(timeout=10)

    def _run_ssh_session(self, sock_dup, session, loop):
        """Run the SSH session in a thread (Paramiko is blocking)."""
        events_to_log = []

        def sync_log(event_type, data):
            events_to_log.append((event_type, data))

        ssh_server = HoneypotSSHServer(session, sync_log)

        try:
            t = paramiko.Transport(sock_dup)
            t.local_version = self.config.banner or "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
            t.add_server_key(self._host_key)
            t.start_server(server=ssh_server)
        except Exception as e:
            logger.debug("SSH transport error: %s", e)
            sock_dup.close()
            return

        # Flush any auth events
        for etype, data in events_to_log:
            etype_val = EventType.AUTH_ATTEMPT if "auth" in etype else EventType.REQUEST
            asyncio.run_coroutine_threadsafe(
                self._log(session, etype_val, data), loop
            ).result(timeout=5)
        events_to_log.clear()

        chan = t.accept(20)
        if chan is None:
            t.close()
            sock_dup.close()
            return

        # Wait for shell request
        ssh_server._event.wait(10)

        try:
            chan.send(f"Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
            chan.send(f"Last login: Mon Jan 15 08:45:12 2024 from 10.0.1.1\r\n")

            prompt = f"root@prod-web-01:~# "
            chan.send(prompt)

            buf = ""
            while True:
                try:
                    data = chan.recv(1024)
                except Exception:
                    break
                if not data:
                    break

                text = data.decode("utf-8", errors="replace")

                for ch in text:
                    if ch in ("\r", "\n"):
                        command = buf.strip()
                        chan.send("\r\n")
                        if command:
                            # Log the command
                            asyncio.run_coroutine_threadsafe(
                                self._log(session, EventType.COMMAND, {
                                    "command": command,
                                    "username": ssh_server.username,
                                }), loop
                            ).result(timeout=5)

                            if command in ("exit", "quit", "logout"):
                                chan.send("logout\r\n")
                                chan.close()
                                t.close()
                                sock_dup.close()
                                return

                            response = FAKE_RESPONSES.get(command)
                            if response is None:
                                # Check prefix matches
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
                                chan.send(response + "\r\n")
                        chan.send(prompt)
                        buf = ""
                    elif ch == "\x7f" or ch == "\x08":  # Backspace
                        if buf:
                            buf = buf[:-1]
                            chan.send("\b \b")
                    elif ch == "\x03":  # Ctrl+C
                        chan.send("^C\r\n" + prompt)
                        buf = ""
                    elif ch == "\x04":  # Ctrl+D
                        chan.close()
                        t.close()
                        sock_dup.close()
                        return
                    elif ord(ch) >= 32:
                        buf += ch
                        chan.send(ch)

        except Exception as e:
            logger.debug("SSH shell error: %s", e)
        finally:
            try:
                chan.close()
            except Exception:
                pass
            try:
                t.close()
            except Exception:
                pass
            try:
                sock_dup.close()
            except Exception:
                pass

    async def stop(self):
        self._running = False
        if self._sock_server:
            self._sock_server.close()
        if self._accept_thread:
            self._accept_thread.join(timeout=3)
        self.logger.info("SSH service stopped")
