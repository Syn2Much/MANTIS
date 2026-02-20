#!/usr/bin/env python3
"""
MANTIS endpoint tester.

Connects to each honeypot service to generate real traffic, then hits every
dashboard API endpoint and displays the results.

Usage:
    python test_endpoints.py                  # test against localhost defaults
    python test_endpoints.py --host 10.0.0.5  # test against a remote host
    python test_endpoints.py --skip-services   # only test dashboard API
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import struct
import sys
import time
from dataclasses import dataclass

try:
    import aiohttp
except ImportError:
    sys.exit("aiohttp is required: pip install aiohttp")

# ── Colours ──────────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
AMBER = "\033[33m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

PASS = f"{GREEN}PASS{RESET}"
FAIL = f"{RED}FAIL{RESET}"
WARN = f"{YELLOW}WARN{RESET}"
SKIP = f"{DIM}SKIP{RESET}"


def header(text: str):
    width = 60
    print(f"\n{BOLD}{AMBER}{'=' * width}{RESET}")
    print(f"{BOLD}{AMBER}  {text}{RESET}")
    print(f"{BOLD}{AMBER}{'=' * width}{RESET}")


def result(name: str, status: str, detail: str = ""):
    tag = {"pass": PASS, "fail": FAIL, "warn": WARN, "skip": SKIP}[status]
    suffix = f"  {DIM}{detail}{RESET}" if detail else ""
    print(f"  [{tag}] {name}{suffix}")


def pretty_json(data, indent: int = 6) -> str:
    return json.dumps(data, indent=2, default=str).replace(
        "\n", "\n" + " " * indent
    )


# ── Default ports (must match profiles/default.yaml) ────────────────────────

DEFAULTS = {
    "ssh": 2222,
    "http": 8080,
    "ftp": 21,
    "smb": 4450,
    "mysql": 3306,
    "telnet": 2323,
    "smtp": 25,
    "mongodb": 27017,
    "vnc": 5900,
    "redis": 6379,
    "adb": 5555,
    "dashboard": 8843,
}


# ── Service probes ───────────────────────────────────────────────────────────

async def probe_ssh(host: str, port: int):
    """Connect via Paramiko, authenticate, and run a command in the shell."""
    import paramiko

    def _ssh_blocking():
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host, port=port,
            username="test_admin", password="test_pass123",
            timeout=5, look_for_keys=False, allow_agent=False,
        )
        banner = client.get_transport().remote_version
        chan = client.invoke_shell()
        time.sleep(0.5)
        # Read the welcome banner / prompt
        welcome = b""
        while chan.recv_ready():
            welcome += chan.recv(4096)
        # Send a command
        chan.send("whoami\n")
        time.sleep(0.5)
        output = b""
        while chan.recv_ready():
            output += chan.recv(4096)
        chan.send("exit\n")
        time.sleep(0.2)
        chan.close()
        client.close()
        return banner, output.decode(errors="replace").strip()

    banner, output = await asyncio.to_thread(_ssh_blocking)
    return banner


async def probe_http(host: str, port: int):
    """GET the HTTP honeypot login page, then POST fake credentials."""
    base = f"http://{host}:{port}"
    async with aiohttp.ClientSession() as s:
        # GET login page
        async with s.get(base, timeout=aiohttp.ClientTimeout(total=5)) as r:
            get_status = r.status
            body_len = len(await r.text())

        # POST fake creds
        async with s.post(
            f"{base}/login",
            data={"username": "test_admin", "password": "test_pass123"},
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as r:
            post_status = r.status

    return get_status, body_len, post_status


async def probe_ftp(host: str, port: int):
    """Log in with fake FTP credentials and run a few commands."""
    reader, writer = await asyncio.open_connection(host, port)
    banner = (await asyncio.wait_for(reader.readline(), timeout=5)).decode().strip()

    async def cmd(c: str) -> str:
        writer.write(f"{c}\r\n".encode())
        await writer.drain()
        return (await asyncio.wait_for(reader.readline(), timeout=5)).decode().strip()

    await cmd("USER admin")
    login_resp = await cmd("PASS hunter2")
    pwd_resp = await cmd("PWD")
    list_resp = await cmd("LIST")
    await cmd("QUIT")
    writer.close()
    await writer.wait_closed()
    return banner, login_resp, pwd_resp


async def probe_mysql(host: str, port: int):
    """Connect to the MySQL honeypot, authenticate, and send a query."""
    reader, writer = await asyncio.open_connection(host, port)
    # Read handshake packet
    handshake_raw = await asyncio.wait_for(reader.read(1024), timeout=5)
    if len(handshake_raw) < 5:
        raise RuntimeError("No MySQL handshake received")

    # Build a simple HandshakeResponse41 packet
    capabilities = 0x0003_A685  # CLIENT_PROTOCOL_41 etc.
    max_packet = 0x01000000
    charset = 33  # utf8
    payload = (
        capabilities.to_bytes(4, "little")
        + max_packet.to_bytes(4, "little")
        + charset.to_bytes(1, "little")
        + b"\x00" * 23
        + b"root\x00"          # username, null-terminated
        + b"\x00"               # auth len=0
    )
    pkt = len(payload).to_bytes(3, "little") + b"\x01" + payload
    writer.write(pkt)
    await writer.drain()
    await asyncio.sleep(0.3)

    # Read auth result
    auth_resp = await asyncio.wait_for(reader.read(1024), timeout=5)

    # Send COM_QUERY: SELECT VERSION()
    query = b"SELECT VERSION()"
    query_payload = b"\x03" + query  # 0x03 = COM_QUERY
    query_pkt = len(query_payload).to_bytes(3, "little") + b"\x00" + query_payload
    writer.write(query_pkt)
    await writer.drain()
    await asyncio.sleep(0.3)

    query_resp = await asyncio.wait_for(reader.read(4096), timeout=5)
    writer.close()
    await writer.wait_closed()
    return len(handshake_raw), len(auth_resp), len(query_resp)


async def probe_smb(host: str, port: int):
    """Send an SMB1 Negotiate request to the SMB honeypot."""
    reader, writer = await asyncio.open_connection(host, port)

    # Minimal SMB1 Negotiate Protocol Request
    smb1_negotiate = (
        b"\x00\x00\x00\x45"          # NetBIOS length
        b"\xffSMB"                    # SMB1 magic
        b"\x72"                       # Negotiate command
        b"\x00\x00\x00\x00"          # Status
        b"\x18"                       # Flags
        b"\x01\x28"                  # Flags2
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # Extra (12 bytes)
        b"\x00\x00"                  # TID
        b"\xff\xfe"                  # PID
        b"\x00\x00"                  # UID
        b"\x00\x00"                  # MID
        b"\x00"                      # Word count
        b"\x22\x00"                  # Byte count
        b"\x02NT LM 0.12\x00"
        b"\x02SMB 2.002\x00"
        b"\x02SMB 2.???\x00"
    )
    writer.write(smb1_negotiate)
    await writer.drain()

    resp = await asyncio.wait_for(reader.read(4096), timeout=5)
    writer.close()
    await writer.wait_closed()
    return len(resp)


async def probe_telnet(host: str, port: int):
    """Connect to the telnet honeypot, login, and run a command."""
    reader, writer = await asyncio.open_connection(host, port)

    # Read system banner + login prompt
    banner = b""
    try:
        banner = await asyncio.wait_for(reader.read(4096), timeout=3)
    except asyncio.TimeoutError:
        pass

    # Send username
    writer.write(b"test_admin\r\n")
    await writer.drain()
    await asyncio.sleep(0.3)

    # Read password prompt (may contain IAC sequences)
    try:
        await asyncio.wait_for(reader.read(4096), timeout=3)
    except asyncio.TimeoutError:
        pass

    # Send password
    writer.write(b"test_pass123\r\n")
    await writer.drain()
    await asyncio.sleep(0.5)

    # Read shell prompt
    try:
        await asyncio.wait_for(reader.read(4096), timeout=3)
    except asyncio.TimeoutError:
        pass

    # Send a command
    writer.write(b"whoami\r\n")
    await writer.drain()
    await asyncio.sleep(0.5)
    output = b""
    try:
        output = await asyncio.wait_for(reader.read(4096), timeout=3)
    except asyncio.TimeoutError:
        pass

    writer.write(b"exit\r\n")
    await writer.drain()
    await asyncio.sleep(0.2)
    writer.close()
    await writer.wait_closed()
    return banner.decode(errors="replace").strip(), output.decode(errors="replace").strip()


async def probe_smtp(host: str, port: int):
    """Connect to the SMTP honeypot, issue EHLO, AUTH LOGIN, and send a message."""
    reader, writer = await asyncio.open_connection(host, port)
    banner = (await asyncio.wait_for(reader.readline(), timeout=5)).decode().strip()

    async def cmd(c: str) -> str:
        writer.write(f"{c}\r\n".encode())
        await writer.drain()
        # Read response (may be multi-line)
        lines = []
        while True:
            line = (await asyncio.wait_for(reader.readline(), timeout=5)).decode().strip()
            lines.append(line)
            if len(line) < 4 or line[3] != '-':
                break
        return "\n".join(lines)

    ehlo_resp = await cmd("EHLO test.local")

    # AUTH LOGIN
    await cmd("AUTH LOGIN")
    # Send username (base64)
    writer.write(base64.b64encode(b"attacker@evil.com").decode().encode() + b"\r\n")
    await writer.drain()
    await asyncio.wait_for(reader.readline(), timeout=5)
    # Send password (base64)
    writer.write(base64.b64encode(b"sup3rs3cret").decode().encode() + b"\r\n")
    await writer.drain()
    auth_resp = (await asyncio.wait_for(reader.readline(), timeout=5)).decode().strip()

    # Send a message
    await cmd("MAIL FROM:<attacker@evil.com>")
    await cmd("RCPT TO:<admin@target.com>")
    await cmd("DATA")
    writer.write(b"Subject: Test Probe\r\nFrom: attacker@evil.com\r\n\r\nThis is a test.\r\n.\r\n")
    await writer.drain()
    data_resp = (await asyncio.wait_for(reader.readline(), timeout=5)).decode().strip()

    await cmd("QUIT")
    writer.close()
    await writer.wait_closed()
    return banner, auth_resp, data_resp


async def probe_mongodb(host: str, port: int):
    """Send a MongoDB isMaster query using OP_MSG wire protocol."""
    reader, writer = await asyncio.open_connection(host, port)

    # Build a minimal OP_MSG isMaster command
    def bson_encode_simple(doc: dict) -> bytes:
        elements = b""
        for key, value in doc.items():
            key_bytes = key.encode("utf-8") + b"\x00"
            if isinstance(value, str):
                encoded = value.encode("utf-8") + b"\x00"
                elements += b"\x02" + key_bytes + struct.pack("<i", len(encoded)) + encoded
            elif isinstance(value, int):
                elements += b"\x10" + key_bytes + struct.pack("<i", value)
        doc_bytes = elements + b"\x00"
        return struct.pack("<i", len(doc_bytes) + 4) + doc_bytes

    # OP_MSG with isMaster
    bson_doc = bson_encode_simple({"isMaster": 1, "$db": "admin"})
    body = struct.pack("<I", 0)  # flagBits
    body += b"\x00"  # section kind 0
    body += bson_doc
    msg_header = struct.pack("<iiii", 16 + len(body), 1, 0, 2013)  # OP_MSG = 2013
    writer.write(msg_header + body)
    await writer.drain()

    # Read response header
    resp_header = await asyncio.wait_for(reader.readexactly(16), timeout=5)
    msg_len = struct.unpack("<i", resp_header[:4])[0]
    resp_body = await asyncio.wait_for(reader.readexactly(msg_len - 16), timeout=5)

    # Also send a listDatabases command
    bson_doc2 = bson_encode_simple({"listDatabases": 1, "$db": "admin"})
    body2 = struct.pack("<I", 0) + b"\x00" + bson_doc2
    msg_header2 = struct.pack("<iiii", 16 + len(body2), 2, 0, 2013)
    writer.write(msg_header2 + body2)
    await writer.drain()

    resp_header2 = await asyncio.wait_for(reader.readexactly(16), timeout=5)
    msg_len2 = struct.unpack("<i", resp_header2[:4])[0]
    resp_body2 = await asyncio.wait_for(reader.readexactly(msg_len2 - 16), timeout=5)

    writer.close()
    await writer.wait_closed()
    return msg_len, msg_len2


async def probe_vnc(host: str, port: int):
    """Connect to the VNC honeypot, complete handshake, and send auth response."""
    reader, writer = await asyncio.open_connection(host, port)

    # Read server version
    server_version = await asyncio.wait_for(reader.read(12), timeout=5)
    version_str = server_version.decode("ascii", errors="replace").strip()

    # Send client version
    writer.write(b"RFB 003.008\n")
    await writer.drain()

    # Read security types
    sec_types = await asyncio.wait_for(reader.read(16), timeout=5)

    # Select VNC Auth (type 2)
    writer.write(bytes([2]))
    await writer.drain()

    # Read 16-byte challenge
    challenge = await asyncio.wait_for(reader.readexactly(16), timeout=5)

    # Send fake 16-byte response (as if DES-encrypted)
    writer.write(os.urandom(16))
    await writer.drain()

    # Read SecurityResult
    sec_result = await asyncio.wait_for(reader.read(4), timeout=5)
    result_val = struct.unpack(">I", sec_result)[0]

    # Send ClientInit (shared=1)
    writer.write(bytes([1]))
    await writer.drain()

    # Read ServerInit
    try:
        server_init = await asyncio.wait_for(reader.read(4096), timeout=5)
    except asyncio.TimeoutError:
        server_init = b""

    writer.close()
    await writer.wait_closed()
    return version_str, result_val, len(server_init)


async def probe_redis(host: str, port: int):
    """Connect to the Redis honeypot, authenticate, and run commands."""
    reader, writer = await asyncio.open_connection(host, port)

    async def redis_cmd(*args) -> str:
        # Send RESP array
        cmd_str = f"*{len(args)}\r\n"
        for a in args:
            a = str(a)
            cmd_str += f"${len(a)}\r\n{a}\r\n"
        writer.write(cmd_str.encode())
        await writer.drain()

        # Read response
        resp_lines = []
        line = (await asyncio.wait_for(reader.readline(), timeout=5)).decode().strip()
        resp_lines.append(line)

        if line.startswith("$"):
            # Bulk string
            size = int(line[1:])
            if size > 0:
                data = await asyncio.wait_for(reader.readexactly(size + 2), timeout=5)
                resp_lines.append(data[:size].decode("utf-8", errors="replace"))
        elif line.startswith("*"):
            # Array
            count = int(line[1:])
            for _ in range(count):
                header_line = (await asyncio.wait_for(reader.readline(), timeout=5)).decode().strip()
                if header_line.startswith("$"):
                    size = int(header_line[1:])
                    if size > 0:
                        data = await asyncio.wait_for(reader.readexactly(size + 2), timeout=5)
                        resp_lines.append(data[:size].decode("utf-8", errors="replace"))
                else:
                    resp_lines.append(header_line)

        return "\n".join(resp_lines)

    # PING
    ping_resp = await redis_cmd("PING")

    # AUTH
    auth_resp = await redis_cmd("AUTH", "admin", "r3d1s_p4ss!")

    # INFO
    info_resp = await redis_cmd("INFO", "server")

    # KEYS *
    keys_resp = await redis_cmd("KEYS", "*")

    # GET a sensitive key
    get_resp = await redis_cmd("GET", "config:db")

    # CONFIG GET
    await redis_cmd("CONFIG", "GET", "requirepass")

    # QUIT
    await redis_cmd("QUIT")

    writer.close()
    await writer.wait_closed()
    return ping_resp.split("\n")[0], auth_resp.split("\n")[0], len(keys_resp)


async def probe_adb(host: str, port: int):
    """Connect to the ADB honeypot and run shell commands."""
    reader, writer = await asyncio.open_connection(host, port)

    def build_adb_msg(command: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
        magic = command ^ 0xFFFFFFFF
        data_check = sum(data) & 0xFFFFFFFF
        hdr = struct.pack("<IIIIII", command, arg0, arg1, len(data), data_check, magic)
        return hdr + data

    ADB_CNXN = 0x4e584e43
    ADB_OPEN = 0x4e45504f
    ADB_WRTE = 0x45545257
    ADB_CLSE = 0x45534c43
    ADB_VERSION = 0x01000000
    ADB_MAXDATA = 4096

    # Send CNXN
    client_banner = b"host::features=shell_v2,cmd\x00"
    writer.write(build_adb_msg(ADB_CNXN, ADB_VERSION, ADB_MAXDATA, client_banner))
    await writer.drain()

    # Read CNXN response
    resp_header = await asyncio.wait_for(reader.readexactly(24), timeout=5)
    cmd, arg0, arg1, data_len = struct.unpack("<IIII", resp_header[:16])
    if data_len > 0:
        resp_data = await asyncio.wait_for(reader.readexactly(data_len), timeout=5)
        device_banner = resp_data.decode("utf-8", errors="replace").rstrip("\x00")
    else:
        device_banner = ""

    # Open shell:id
    shell_dest = b"shell:id\x00"
    writer.write(build_adb_msg(ADB_OPEN, 1, 0, shell_dest))
    await writer.drain()

    # Read OKAY
    okay_header = await asyncio.wait_for(reader.readexactly(24), timeout=5)

    # Read WRTE (response)
    wrte_header = await asyncio.wait_for(reader.readexactly(24), timeout=5)
    _, _, _, wrte_len = struct.unpack("<IIII", wrte_header[:16])
    shell_output = ""
    if wrte_len > 0:
        wrte_data = await asyncio.wait_for(reader.readexactly(wrte_len), timeout=5)
        shell_output = wrte_data.decode("utf-8", errors="replace").strip()

    writer.close()
    await writer.wait_closed()
    return device_banner[:60], shell_output[:80]


# ── Dashboard API tests ─────────────────────────────────────────────────────

@dataclass
class APITest:
    name: str
    method: str
    path: str
    params: dict | None = None
    body: dict | None = None
    expect_status: int = 200
    expect_type: str = "json"  # json | html


API_TESTS = [
    APITest("Dashboard HTML", "GET", "/", expect_type="html"),
    APITest("Stats", "GET", "/api/stats"),
    APITest("Events (default)", "GET", "/api/events"),
    APITest("Events (limit=5)", "GET", "/api/events", params={"limit": 5}),
    APITest("Events (filter service=ssh)", "GET", "/api/events", params={"service": "ssh"}),
    APITest("Events (filter type=CONNECTION)", "GET", "/api/events", params={"type": "CONNECTION"}),
    APITest("Sessions", "GET", "/api/sessions"),
    APITest("Sessions (limit=3)", "GET", "/api/sessions", params={"limit": 3}),
    APITest("Alerts", "GET", "/api/alerts"),
    APITest("Alerts (unacked)", "GET", "/api/alerts", params={"unacknowledged": "true"}),
    APITest("Geo lookup (8.8.8.8)", "GET", "/api/geo/8.8.8.8"),
    APITest("Map data", "GET", "/api/map"),
    APITest("Config", "GET", "/api/config"),
    APITest("Unique IPs", "GET", "/api/ips"),
    APITest("Events (paginated)", "GET", "/api/events", params={"paginated": "1", "limit": 5}),
]


async def run_api_tests(base_url: str, session: aiohttp.ClientSession) -> tuple[int, int]:
    passed = failed = 0

    for t in API_TESTS:
        try:
            if t.method == "GET":
                async with session.get(
                    f"{base_url}{t.path}",
                    params=t.params,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    if t.expect_type == "json":
                        data = await resp.json()
                    else:
                        data = f"{len(await resp.text())} bytes HTML"
            elif t.method == "POST":
                async with session.post(
                    f"{base_url}{t.path}",
                    json=t.body,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    data = await resp.json()

            if status == t.expect_status:
                # Summarize the response
                if isinstance(data, dict):
                    summary = ", ".join(f"{k}={v}" for k, v in list(data.items())[:6])
                    if len(data) > 6:
                        summary += f", ... ({len(data)} keys)"
                elif isinstance(data, list):
                    summary = f"{len(data)} items"
                else:
                    summary = str(data)
                result(t.name, "pass", f"[{status}] {summary}")
                passed += 1
            else:
                result(t.name, "fail", f"expected {t.expect_status}, got {status}")
                failed += 1

        except Exception as e:
            result(t.name, "fail", str(e))
            failed += 1

    # --- Acknowledge alert (needs a real alert id) ---
    try:
        async with session.get(
            f"{base_url}/api/alerts", params={"limit": 1},
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            alerts = await resp.json()

        if alerts:
            alert_id = alerts[0]["id"]
            async with session.post(
                f"{base_url}/api/alerts/{alert_id}/ack",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                data = await resp.json()
                if resp.status == 200 and data.get("status") == "ok":
                    result("Acknowledge alert", "pass", f"alert {alert_id} acked")
                    passed += 1
                else:
                    result("Acknowledge alert", "fail", f"status={resp.status}")
                    failed += 1
        else:
            result("Acknowledge alert", "skip", "no alerts to acknowledge")
    except Exception as e:
        result("Acknowledge alert", "fail", str(e))
        failed += 1

    return passed, failed


async def test_websocket(base_url: str, session: aiohttp.ClientSession) -> bool:
    """Connect to the WebSocket and listen briefly for any broadcast."""
    ws_url = base_url.replace("http://", "ws://") + "/ws"
    try:
        async with session.ws_connect(ws_url, timeout=5) as ws:
            # Just verify the connection was accepted
            result("WebSocket connect", "pass", ws_url)
            # Try to receive a message (may timeout if no events are flowing)
            try:
                msg = await asyncio.wait_for(ws.receive(), timeout=3)
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    result("WebSocket message", "pass", f"type={data.get('type')}")
                else:
                    result("WebSocket message", "warn", f"msg_type={msg.type}")
            except asyncio.TimeoutError:
                result("WebSocket message", "skip", "no messages within 3s (normal if idle)")
            return True
    except Exception as e:
        result("WebSocket connect", "fail", str(e))
        return False


# ── Orchestrator ─────────────────────────────────────────────────────────────

async def run(args):
    host = args.host
    summary = {"passed": 0, "failed": 0, "skipped": 0}

    # ── 1. Probe honeypot services ───────────────────────────────────────
    if not args.skip_services:
        header("Honeypot Service Probes")
        print(f"  {DIM}Generating real traffic so the API has data to return{RESET}\n")

        # SSH
        try:
            banner = await probe_ssh(host, args.port_ssh)
            result("SSH", "pass", f"banner: {banner}")
            summary["passed"] += 1
        except Exception as e:
            result("SSH", "fail", str(e))
            summary["failed"] += 1

        # HTTP
        try:
            get_st, body_len, post_st = await probe_http(host, args.port_http)
            result("HTTP GET /", "pass", f"status={get_st}, body={body_len}b")
            result("HTTP POST /login", "pass", f"status={post_st}")
            summary["passed"] += 2
        except Exception as e:
            result("HTTP", "fail", str(e))
            summary["failed"] += 1

        # FTP
        try:
            banner, login_resp, pwd_resp = await probe_ftp(host, args.port_ftp)
            result("FTP", "pass", f"banner: {banner}")
            summary["passed"] += 1
        except Exception as e:
            result("FTP", "fail", str(e))
            summary["failed"] += 1

        # MySQL
        try:
            hs_len, auth_len, q_len = await probe_mysql(host, args.port_mysql)
            result("MySQL", "pass", f"handshake={hs_len}b, auth_resp={auth_len}b, query_resp={q_len}b")
            summary["passed"] += 1
        except Exception as e:
            result("MySQL", "fail", str(e))
            summary["failed"] += 1

        # SMB
        try:
            resp_len = await probe_smb(host, args.port_smb)
            result("SMB", "pass", f"negotiate response={resp_len}b")
            summary["passed"] += 1
        except Exception as e:
            result("SMB", "fail", str(e))
            summary["failed"] += 1

        # Telnet
        try:
            banner, output = await probe_telnet(host, args.port_telnet)
            result("Telnet", "pass", f"banner received, output: {output[:60]}")
            summary["passed"] += 1
        except Exception as e:
            result("Telnet", "fail", str(e))
            summary["failed"] += 1

        # SMTP
        try:
            banner, auth_resp, data_resp = await probe_smtp(host, args.port_smtp)
            result("SMTP", "pass", f"banner: {banner[:50]}")
            result("SMTP AUTH", "pass", f"auth: {auth_resp[:50]}")
            summary["passed"] += 2
        except Exception as e:
            result("SMTP", "fail", str(e))
            summary["failed"] += 1

        # MongoDB
        try:
            ismaster_len, listdb_len = await probe_mongodb(host, args.port_mongodb)
            result("MongoDB", "pass", f"isMaster resp={ismaster_len}b, listDatabases resp={listdb_len}b")
            summary["passed"] += 1
        except Exception as e:
            result("MongoDB", "fail", str(e))
            summary["failed"] += 1

        # VNC
        try:
            version, sec_result_val, init_len = await probe_vnc(host, args.port_vnc)
            result("VNC", "pass", f"version: {version}, auth_ok={sec_result_val == 0}, init={init_len}b")
            summary["passed"] += 1
        except Exception as e:
            result("VNC", "fail", str(e))
            summary["failed"] += 1

        # Redis
        try:
            ping, auth, keys_len = await probe_redis(host, args.port_redis)
            result("Redis", "pass", f"ping: {ping}, auth: {auth}, keys_resp={keys_len}b")
            summary["passed"] += 1
        except Exception as e:
            result("Redis", "fail", str(e))
            summary["failed"] += 1

        # ADB
        try:
            device, shell_out = await probe_adb(host, args.port_adb)
            result("ADB", "pass", f"device: {device}")
            result("ADB shell:id", "pass", f"{shell_out[:60]}")
            summary["passed"] += 2
        except Exception as e:
            result("ADB", "fail", str(e))
            summary["failed"] += 1

        # Brief pause so events are flushed to the DB
        print(f"\n  {DIM}Waiting 1s for events to flush...{RESET}")
        await asyncio.sleep(1)

    # ── 2. Dashboard API endpoints ───────────────────────────────────────
    header("Dashboard API Endpoints")
    base_url = f"http://{host}:{args.port_dashboard}"
    print(f"  {DIM}Base URL: {base_url}{RESET}\n")

    async with aiohttp.ClientSession() as session:
        p, f = await run_api_tests(base_url, session)
        summary["passed"] += p
        summary["failed"] += f

        # ── 3. WebSocket ────────────────────────────────────────────────
        header("WebSocket")
        ws_ok = await test_websocket(base_url, session)
        if ws_ok:
            summary["passed"] += 1
        else:
            summary["failed"] += 1

    # ── Summary ──────────────────────────────────────────────────────────
    header("Summary")
    total = summary["passed"] + summary["failed"]
    colour = GREEN if summary["failed"] == 0 else RED
    print(f"  {GREEN}{summary['passed']}{RESET} passed, "
          f"{RED}{summary['failed']}{RESET} failed "
          f"out of {total} checks")
    print()

    return 0 if summary["failed"] == 0 else 1


def main():
    parser = argparse.ArgumentParser(
        description="MANTIS Endpoint Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  python test_endpoints.py                     # all defaults (localhost)
  python test_endpoints.py --host 10.0.0.5     # remote host
  python test_endpoints.py --skip-services     # API-only
  python test_endpoints.py --port-dashboard 9090
""",
    )
    parser.add_argument("--host", default="127.0.0.1", help="target host (default: 127.0.0.1)")
    parser.add_argument("--port-ssh", type=int, default=DEFAULTS["ssh"])
    parser.add_argument("--port-http", type=int, default=DEFAULTS["http"])
    parser.add_argument("--port-ftp", type=int, default=DEFAULTS["ftp"])
    parser.add_argument("--port-smb", type=int, default=DEFAULTS["smb"])
    parser.add_argument("--port-mysql", type=int, default=DEFAULTS["mysql"])
    parser.add_argument("--port-telnet", type=int, default=DEFAULTS["telnet"])
    parser.add_argument("--port-smtp", type=int, default=DEFAULTS["smtp"])
    parser.add_argument("--port-mongodb", type=int, default=DEFAULTS["mongodb"])
    parser.add_argument("--port-vnc", type=int, default=DEFAULTS["vnc"])
    parser.add_argument("--port-redis", type=int, default=DEFAULTS["redis"])
    parser.add_argument("--port-adb", type=int, default=DEFAULTS["adb"])
    parser.add_argument("--port-dashboard", type=int, default=DEFAULTS["dashboard"])
    parser.add_argument("--skip-services", action="store_true", help="skip honeypot service probes, only test dashboard API")
    args = parser.parse_args()

    print(f"\n{BOLD}{AMBER}MANTIS Endpoint Tester{RESET}")
    print(f"{DIM}Target: {args.host}{RESET}")

    rc = asyncio.run(run(args))
    sys.exit(rc)


if __name__ == "__main__":
    main()
