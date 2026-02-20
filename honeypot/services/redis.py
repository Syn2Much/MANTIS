"""Redis honeypot service - RESP protocol with AUTH capture and fake command responses."""

import asyncio
from ..models import EventType
from . import BaseHoneypotService

# Fake Redis INFO output
FAKE_INFO = """\
# Server
redis_version:7.2.4
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:abc123def456
redis_mode:standalone
os:Linux 5.15.0-91-generic x86_64
arch_bits:64
tcp_port:6379
uptime_in_seconds:432000
uptime_in_days:5
hz:10
configured_hz:10
lru_clock:16234567

# Clients
connected_clients:3
blocked_clients:0
tracking_clients:0

# Memory
used_memory:1048576
used_memory_human:1.00M
used_memory_rss:2097152
used_memory_rss_human:2.00M
used_memory_peak:4194304
used_memory_peak_human:4.00M
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction

# Stats
total_connections_received:18234
total_commands_processed:456789
instantaneous_ops_per_sec:12

# Replication
role:master
connected_slaves:0

# Keyspace
db0:keys=1523,expires=42,avg_ttl=86400000
db1:keys=89,expires=5,avg_ttl=3600000"""

# Fake keys for KEYS *
FAKE_KEYS = [
    "session:abc123",
    "session:def456",
    "user:1001",
    "user:1002",
    "user:admin",
    "config:app",
    "config:db",
    "cache:homepage",
    "cache:api_response",
    "token:refresh:abc",
    "api_key:production",
    "queue:emails",
    "queue:notifications",
    "rate_limit:10.0.1.1",
]

# Fake key values
FAKE_VALUES = {
    "user:admin": '{"id":1,"username":"admin","email":"admin@example.com","role":"superadmin","password_hash":"$2b$12$LJ3m4ks..."}',
    "config:app": '{"debug":false,"secret_key":"sk-prod-a1b2c3d4e5f6","db_host":"10.0.1.50"}',
    "config:db": '{"host":"10.0.1.50","port":5432,"user":"app_user","password":"db_pr0d_pw!","database":"production"}',
    "api_key:production": "sk-live-4f7a8b2c9d3e1f6a5b8c7d2e",
    "token:refresh:abc": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMDAxfQ.FAKE_TOKEN",
}


class RedisHoneypot(BaseHoneypotService):
    service_name = "redis"

    async def start(self):
        port = self.config.port
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", port,
        )
        self.logger.info("Redis honeypot listening on port %d", port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        authenticated = False

        try:
            while True:
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=120)
                except asyncio.TimeoutError:
                    break
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                # Parse RESP protocol
                if line.startswith("*"):
                    # Array (inline RESP command)
                    args = await self._parse_resp_array(reader, line)
                    if args is None:
                        break
                elif line.startswith("$"):
                    # Bulk string (shouldn't come alone at top level, skip)
                    continue
                else:
                    # Inline command
                    args = line.split()

                if not args:
                    continue

                cmd = args[0].upper()
                cmd_args = args[1:]

                await self._log(session, EventType.COMMAND, {
                    "command": cmd,
                    "args": [str(a)[:256] for a in cmd_args],
                    "raw": " ".join(str(a) for a in args)[:2048],
                })

                response = await self._handle_command(session, cmd, cmd_args, authenticated)
                if cmd == "AUTH" and response == "+OK\r\n":
                    authenticated = True

                writer.write(response.encode())
                await writer.drain()

                if cmd == "QUIT":
                    break

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("Redis session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _parse_resp_array(self, reader, first_line: str) -> list | None:
        """Parse a RESP array command."""
        try:
            num_args = int(first_line[1:])
        except ValueError:
            return None

        if num_args <= 0 or num_args > 100:
            return None

        args = []
        for _ in range(num_args):
            try:
                size_line = await asyncio.wait_for(reader.readline(), timeout=10)
            except asyncio.TimeoutError:
                return None
            if not size_line:
                return None

            size_str = size_line.decode("utf-8", errors="replace").strip()
            if not size_str.startswith("$"):
                args.append(size_str)
                continue

            try:
                size = int(size_str[1:])
            except ValueError:
                return None

            if size < 0:
                args.append(None)
                continue
            if size > 65536:
                return None

            try:
                value_data = await asyncio.wait_for(reader.readexactly(size + 2), timeout=10)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                return None

            args.append(value_data[:size].decode("utf-8", errors="replace"))

        return args

    async def _handle_command(self, session, cmd: str, args: list, authenticated: bool) -> str:
        """Process a Redis command and return RESP response."""

        if cmd == "AUTH":
            if len(args) >= 2:
                username, password = args[0], args[1]
            elif len(args) == 1:
                username, password = "", args[0]
            else:
                return "-ERR wrong number of arguments for 'auth' command\r\n"

            await self._log(session, EventType.AUTH_ATTEMPT, {
                "username": username,
                "password": password,
            })
            return "+OK\r\n"

        if cmd == "PING":
            if args:
                return f"${len(args[0])}\r\n{args[0]}\r\n"
            return "+PONG\r\n"

        if cmd == "ECHO":
            if args:
                msg = args[0]
                return f"${len(msg)}\r\n{msg}\r\n"
            return "-ERR wrong number of arguments for 'echo' command\r\n"

        if cmd == "INFO":
            section = args[0].lower() if args else "all"
            info = FAKE_INFO
            return f"${len(info)}\r\n{info}\r\n"

        if cmd == "DBSIZE":
            return ":1523\r\n"

        if cmd == "CONFIG":
            if args and args[0].upper() == "GET":
                param = args[1] if len(args) > 1 else ""
                if param == "requirepass":
                    return "*2\r\n$11\r\nrequirepass\r\n$0\r\n\r\n"
                elif param == "dir":
                    return "*2\r\n$3\r\ndir\r\n$8\r\n/var/lib\r\n"
                elif param == "dbfilename":
                    return "*2\r\n$10\r\ndbfilename\r\n$8\r\ndump.rdb\r\n"
                else:
                    return "*0\r\n"
            elif args and args[0].upper() == "SET":
                await self._log(session, EventType.COMMAND, {
                    "command": "CONFIG SET",
                    "param": args[1] if len(args) > 1 else "",
                    "value": args[2] if len(args) > 2 else "",
                    "threat": "config_modification_attempt",
                })
                return "+OK\r\n"
            return "*0\r\n"

        if cmd == "KEYS":
            pattern = args[0] if args else "*"
            # Return fake keys
            resp = f"*{len(FAKE_KEYS)}\r\n"
            for key in FAKE_KEYS:
                resp += f"${len(key)}\r\n{key}\r\n"
            return resp

        if cmd == "GET":
            if not args:
                return "-ERR wrong number of arguments for 'get' command\r\n"
            key = args[0]
            value = FAKE_VALUES.get(key)
            if value:
                return f"${len(value)}\r\n{value}\r\n"
            return "$-1\r\n"  # nil

        if cmd == "SET":
            return "+OK\r\n"

        if cmd == "DEL":
            return ":1\r\n"

        if cmd == "EXISTS":
            key = args[0] if args else ""
            exists = 1 if key in FAKE_VALUES or key in FAKE_KEYS else 0
            return f":{exists}\r\n"

        if cmd == "TYPE":
            return "+string\r\n"

        if cmd == "TTL" or cmd == "PTTL":
            return ":-1\r\n"

        if cmd == "SELECT":
            return "+OK\r\n"

        if cmd == "FLUSHDB" or cmd == "FLUSHALL":
            await self._log(session, EventType.COMMAND, {
                "command": cmd,
                "threat": "destructive_command",
            })
            return "+OK\r\n"

        if cmd == "SAVE" or cmd == "BGSAVE":
            return "+OK\r\n"

        if cmd == "SCAN":
            resp = "*2\r\n$1\r\n0\r\n"
            resp += f"*{min(len(FAKE_KEYS), 10)}\r\n"
            for key in FAKE_KEYS[:10]:
                resp += f"${len(key)}\r\n{key}\r\n"
            return resp

        if cmd == "CLIENT":
            if args and args[0].upper() == "SETNAME":
                return "+OK\r\n"
            if args and args[0].upper() == "GETNAME":
                return "$-1\r\n"
            if args and args[0].upper() == "LIST":
                info = "id=1 addr=127.0.0.1:12345 fd=5 name= db=0 cmd=client\n"
                return f"${len(info)}\r\n{info}\r\n"
            return "+OK\r\n"

        if cmd == "COMMAND":
            return "*0\r\n"

        if cmd == "CLUSTER":
            return "-ERR This instance has cluster support disabled\r\n"

        if cmd == "QUIT":
            return "+OK\r\n"

        if cmd == "SHUTDOWN":
            await self._log(session, EventType.COMMAND, {
                "command": "SHUTDOWN",
                "threat": "shutdown_attempt",
            })
            return "-ERR Errors trying to SHUTDOWN. Check logs.\r\n"

        if cmd == "SLAVEOF" or cmd == "REPLICAOF":
            await self._log(session, EventType.COMMAND, {
                "command": cmd,
                "args": [str(a) for a in args],
                "threat": "replication_hijack_attempt",
            })
            return "+OK\r\n"

        if cmd == "MODULE":
            await self._log(session, EventType.COMMAND, {
                "command": "MODULE",
                "args": [str(a) for a in args],
                "threat": "module_load_attempt",
            })
            return "-ERR Module loading disabled\r\n"

        if cmd == "EVAL" or cmd == "EVALSHA":
            await self._log(session, EventType.COMMAND, {
                "command": cmd,
                "script": args[0][:2048] if args else "",
                "threat": "lua_script_execution",
            })
            return "+OK\r\n"

        return f"-ERR unknown command '{cmd.lower()}'\r\n"
