"""Android Debug Bridge (ADB) honeypot - captures connection attempts and shell commands."""

import asyncio
import struct
from ..models import EventType
from . import BaseHoneypotService

# ADB protocol constants
ADB_AUTH = 0x41555448      # AUTH
ADB_CNXN = 0x4e584e43     # CNXN
ADB_OPEN = 0x4e45504f     # OPEN
ADB_OKAY = 0x59414b4f     # OKAY
ADB_WRTE = 0x45545257     # WRTE
ADB_CLSE = 0x45534c43     # CLSE

ADB_VERSION = 0x01000000
ADB_MAXDATA = 4096

# Fake device banner
DEVICE_BANNER = "device::ro.product.model=Pixel 7;ro.product.device=panther;ro.build.version.release=14;ro.build.display.id=UP1A.231005.007"

# Fake shell responses
FAKE_RESPONSES = {
    "id": "uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),3003(inet),3006(net_bw_stats),3009(readproc),3011(uhid)",
    "whoami": "root",
    "uname -a": "Linux localhost 5.15.104-android14-8-00001-g123abc #1 SMP PREEMPT Fri Oct 6 2023 aarch64",
    "getprop ro.build.version.release": "14",
    "getprop ro.product.model": "Pixel 7",
    "getprop ro.product.device": "panther",
    "getprop ro.build.display.id": "UP1A.231005.007",
    "getprop ro.serialno": "28161FDH2000GT",
    "pm list packages": """package:com.android.providers.telephony
package:com.android.providers.calendar
package:com.android.providers.media
package:com.android.wallpapercropper
package:com.android.documentsui
package:com.android.galaxy.apps
package:com.google.android.apps.maps
package:com.google.android.gms
package:com.google.android.apps.photos
package:com.android.chrome
package:com.whatsapp
package:com.android.vending""",
    "ls /sdcard/": """Alarms
Android
DCIM
Documents
Download
Movies
Music
Notifications
Pictures
Podcasts
Ringtones""",
    "ls /data/data/": """com.android.providers.telephony
com.android.providers.media
com.google.android.gms
com.android.chrome
com.whatsapp""",
    "cat /proc/cpuinfo": """processor\t: 0
BogoMIPS\t: 38.40
Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics
CPU implementer\t: 0x41
CPU architecture: 8
CPU variant\t: 0x1
CPU part\t: 0xd05
CPU revision\t: 0""",
    "df -h": """Filesystem      Size  Used Avail Use% Mounted on
/dev/block/dm-0  5.8G  4.2G  1.4G  76% /
tmpfs           3.7G  1.1M  3.7G   1% /dev
/dev/block/dm-6  246G   89G  157G  37% /data
/dev/fuse       246G   89G  157G  37% /sdcard""",
    "dumpsys battery": """Current Battery Service state:
  AC powered: false
  USB powered: true
  Wireless powered: false
  Max charging current: 500000
  status: 5
  health: 2
  present: true
  level: 87
  scale: 100
  voltage: 4234
  temperature: 275
  technology: Li-ion""",
    "settings list secure": """android_id=a1b2c3d4e5f6g7h8
bluetooth_address=AA:BB:CC:DD:EE:FF
install_non_market_apps=1
lock_screen_lock_after_timeout=5000""",
    "ifconfig wlan0": """wlan0     Link encap:Ethernet  HWaddr AA:BB:CC:DD:EE:FF
          inet addr:192.168.1.142  Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1""",
    "netstat -tlnp": """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program
tcp        0      0 0.0.0.0:5555            0.0.0.0:*               LISTEN      1234/adbd""",
    "ps": """USER      PID   PPID  VSIZE  RSS   WCHAN    PC        NAME
root      1     0     10632  776   SyS_epoll 0000000000 S /init
root      234   1     14520  1336  poll_sch  0000000000 S /sbin/adbd
system    456   1     1803456 65432 SyS_epoll 0000000000 S system_server
u0_a12    1234  456   1024564 43210 SyS_epoll 0000000000 S com.google.android.gms""",
}


def _build_adb_message(command: int, arg0: int, arg1: int, data: bytes = b"") -> bytes:
    """Build an ADB protocol message."""
    magic = command ^ 0xFFFFFFFF
    data_check = sum(data) & 0xFFFFFFFF
    header = struct.pack("<IIIIII", command, arg0, arg1, len(data), data_check, magic)
    return header + data


def _parse_adb_message(data: bytes):
    """Parse an ADB message header. Returns (command, arg0, arg1, data_len) or None."""
    if len(data) < 24:
        return None
    command, arg0, arg1, data_len, data_check, magic = struct.unpack("<IIIIII", data[:24])
    return command, arg0, arg1, data_len


class ADBHoneypot(BaseHoneypotService):
    service_name = "adb"

    async def start(self):
        port = self.config.port
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", port,
        )
        self.logger.info("ADB honeypot listening on port %d", port)

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        local_id = 1
        try:
            # Read CNXN from client
            try:
                header = await asyncio.wait_for(reader.readexactly(24), timeout=30)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                return

            parsed = _parse_adb_message(header)
            if parsed is None:
                return

            command, arg0, arg1, data_len = parsed

            # Read payload if any
            client_banner = b""
            if data_len > 0 and data_len < 8192:
                try:
                    client_banner = await asyncio.wait_for(reader.readexactly(data_len), timeout=5)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    pass

            await self._log(session, EventType.REQUEST, {
                "stage": "connect",
                "client_command": hex(command),
                "client_banner": client_banner.decode("utf-8", errors="replace").rstrip("\x00"),
            })

            if command == ADB_CNXN:
                # Send CNXN response
                banner_data = DEVICE_BANNER.encode("utf-8") + b"\x00"
                resp = _build_adb_message(ADB_CNXN, ADB_VERSION, ADB_MAXDATA, banner_data)
                writer.write(resp)
                await writer.drain()
            elif command == ADB_AUTH:
                # Client is trying auth - send CNXN anyway (accept all)
                banner_data = DEVICE_BANNER.encode("utf-8") + b"\x00"
                resp = _build_adb_message(ADB_CNXN, ADB_VERSION, ADB_MAXDATA, banner_data)
                writer.write(resp)
                await writer.drain()
            else:
                return

            # Main message loop
            while True:
                try:
                    header = await asyncio.wait_for(reader.readexactly(24), timeout=120)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                parsed = _parse_adb_message(header)
                if parsed is None:
                    break

                command, arg0, arg1, data_len = parsed

                payload = b""
                if data_len > 0 and data_len < 65536:
                    try:
                        payload = await asyncio.wait_for(reader.readexactly(data_len), timeout=10)
                    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                        break

                if command == ADB_OPEN:
                    # Client wants to open a stream (e.g., "shell:", "shell:ls")
                    dest = payload.decode("utf-8", errors="replace").rstrip("\x00")
                    remote_id = arg0

                    await self._log(session, EventType.COMMAND, {
                        "command": "OPEN",
                        "destination": dest,
                    })

                    # Send OKAY
                    writer.write(_build_adb_message(ADB_OKAY, local_id, remote_id))
                    await writer.drain()

                    if dest.startswith("shell:"):
                        shell_cmd = dest[6:].strip()
                        if shell_cmd:
                            # Single command execution
                            await self._log(session, EventType.COMMAND, {
                                "command": shell_cmd,
                                "mode": "exec",
                            })
                            response = self._get_response(shell_cmd)
                            resp_data = (response + "\n").encode("utf-8")
                            writer.write(_build_adb_message(ADB_WRTE, local_id, remote_id, resp_data))
                            await writer.drain()
                            # Close the stream
                            writer.write(_build_adb_message(ADB_CLSE, local_id, remote_id))
                            await writer.drain()
                        else:
                            # Interactive shell - send prompt
                            prompt = "panther:/ # "
                            writer.write(_build_adb_message(ADB_WRTE, local_id, remote_id, prompt.encode()))
                            await writer.drain()

                    local_id += 1

                elif command == ADB_WRTE:
                    # Client writing data (shell input)
                    text = payload.decode("utf-8", errors="replace").strip()
                    remote_id = arg0

                    # ACK the write
                    writer.write(_build_adb_message(ADB_OKAY, local_id - 1, remote_id))
                    await writer.drain()

                    if text:
                        await self._log(session, EventType.COMMAND, {
                            "command": text,
                            "mode": "interactive",
                        })

                        if text in ("exit", "quit"):
                            writer.write(_build_adb_message(ADB_CLSE, local_id - 1, remote_id))
                            await writer.drain()
                            break

                        response = self._get_response(text)
                        prompt = "panther:/ # "
                        resp_data = (response + "\n" + prompt).encode("utf-8")
                        writer.write(_build_adb_message(ADB_WRTE, local_id - 1, remote_id, resp_data))
                        await writer.drain()

                elif command == ADB_CLSE:
                    break

                elif command == ADB_OKAY:
                    pass  # ACK, ignore

                else:
                    await self._log(session, EventType.COMMAND, {
                        "unknown_command": hex(command),
                        "payload_len": data_len,
                    })

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("ADB session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _get_response(self, command: str) -> str:
        """Look up fake response for a command."""
        response = FAKE_RESPONSES.get(command)
        if response:
            return response
        # Prefix match
        for k, v in FAKE_RESPONSES.items():
            if command.startswith(k.split()[0]):
                return v
        if command.startswith("cd "):
            return ""
        if command.startswith("echo "):
            return command[5:]
        if command.startswith("getprop"):
            return ""
        return f"/system/bin/sh: {command.split()[0]}: not found"
