"""CLI argument parsing, config loading, and banner display."""

import argparse
import asyncio
import logging
import os
import secrets
import socket
import sys
import time

import questionary

from . import __version__
from .config import HoneypotConfig, load_config
from .core import HoneypotOrchestrator

BANNER = """
    \033[33m███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗
    ████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝
    ██╔████╔██║███████║██╔██╗ ██║   ██║   ██║███████╗
    ██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██║╚════██║
    ██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║███████║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝\033[0m
\033[2m    Network Threat Intelligence       v{version}
    Watch. Wait. Capture.\033[0m
"""

ALL_SERVICES = [
    ("ssh", 2222), ("http", 8080), ("ftp", 21), ("smb", 4450),
    ("mysql", 3306), ("telnet", 2323), ("smtp", 25),
    ("mongodb", 27017), ("vnc", 5900), ("redis", 6379), ("adb", 5555),
]


def _interactive_setup() -> HoneypotConfig:
    """Run interactive questionary prompts to build config."""
    config = HoneypotConfig()

    # 1. Checkbox: pick services
    choices = [
        questionary.Choice(f"{name.upper():8s}  port {port}", value=name, checked=True)
        for name, port in ALL_SERVICES
    ]
    selected = questionary.checkbox(
        "Select honeypot services", choices=choices
    ).ask()

    if selected is None:
        # User cancelled (Ctrl-C during prompt)
        sys.exit(0)

    # Disable unselected services
    for name, _ in ALL_SERVICES:
        getattr(config, name).enabled = name in selected

    # 2. Configure ports?
    custom_ports = questionary.confirm("Configure custom ports?", default=False).ask()
    if custom_ports is None:
        sys.exit(0)

    if custom_ports:
        for name in selected:
            cfg = config.get_service_config(name)
            val = questionary.text(
                f"  {name.upper()} port", default=str(cfg.port)
            ).ask()
            if val is None:
                sys.exit(0)
            cfg.port = int(val)

        val = questionary.text(
            "  Dashboard port", default=str(config.dashboard.port)
        ).ask()
        if val is None:
            sys.exit(0)
        config.dashboard.port = int(val)

    # 3. Auth token
    default_token = secrets.token_urlsafe(24)
    token = questionary.text("Auth token", default=default_token).ask()
    if token is None:
        sys.exit(0)
    config.dashboard.auth_token = token

    return config


def _setup_logging(args):
    level = logging.INFO
    if getattr(args, "verbose", False):
        level = logging.DEBUG
    elif getattr(args, "quiet", False):
        level = logging.ERROR

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress noisy loggers
    logging.getLogger("paramiko").setLevel(logging.WARNING)
    logging.getLogger("aiohttp").setLevel(logging.WARNING)


async def _run_stats(args):
    from .database import Database
    db = Database(getattr(args, "db", "honeypot.db"))
    await db.initialize()
    stats = await db.get_stats()
    await db.close()

    print(f"\n  MANTIS Statistics")
    print(f"  {'='*40}")
    print(f"  Total Events:    {stats['total_events']}")
    print(f"  Total Sessions:  {stats['total_sessions']}")
    print(f"  Unique IPs:      {stats['unique_ips']}")
    print(f"  Total Alerts:    {stats['total_alerts']}")
    print(f"  Unacked Alerts:  {stats['unacknowledged_alerts']}")
    print(f"\n  Events by Service:")
    for svc, count in stats.get("events_by_service", {}).items():
        print(f"    {svc:10s}  {count}")
    print(f"\n  Top IPs:")
    for entry in stats.get("top_ips", []):
        print(f"    {entry['ip']:20s}  {entry['count']} events")
    print()


DIM = "\033[2m"
BOLD = "\033[1m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
RESET = "\033[0m"
CHECK = f"{GREEN}\u2714{RESET}"
CROSS = f"{RED}\u2718{RESET}"


def _spin_print(msg: str, duration: float = 0.0):
    """Print a check mark for a completed step."""
    sys.stdout.write(f"  {CHECK} {msg}\n")
    sys.stdout.flush()


def _spin_fail(msg: str, detail: str = ""):
    suffix = f"  {DIM}{detail}{RESET}" if detail else ""
    sys.stdout.write(f"\r  {CROSS} {msg}{suffix}\n")
    sys.stdout.flush()


def _get_local_ip() -> str:
    """Get the primary local IP address of this machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _kill_stale_ports(config: HoneypotConfig):
    """Check for and kill any processes holding our configured ports."""
    import subprocess
    ports = set()
    for svc_name in ("ssh", "http", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
        cfg = config.get_service_config(svc_name)
        if cfg.enabled:
            ports.add(cfg.port)
            if svc_name == "telnet" and cfg.extra.get("additional_ports"):
                for p in cfg.extra["additional_ports"]:
                    ports.add(p)
    if config.dashboard.enabled:
        ports.add(config.dashboard.port)

    stale_pids = set()
    my_pid = os.getpid()
    for port in ports:
        try:
            out = subprocess.check_output(
                ["lsof", "-ti", f":{port}"], stderr=subprocess.DEVNULL, text=True
            )
            for pid_str in out.strip().split("\n"):
                pid = int(pid_str.strip())
                if pid != my_pid:
                    stale_pids.add(pid)
        except (subprocess.CalledProcessError, FileNotFoundError, ValueError):
            pass

    if stale_pids:
        _spin_print(f"Killing {len(stale_pids)} stale process(es) holding ports", 0.3)
        import signal as sig
        for pid in stale_pids:
            try:
                os.kill(pid, sig.SIGTERM)
            except ProcessLookupError:
                pass
        # Wait for ports to free up
        time.sleep(2)
        # Force kill any remaining
        for pid in stale_pids:
            try:
                os.kill(pid, sig.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.5)


def main():
    parser = argparse.ArgumentParser(
        description="MANTIS - Network Threat Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"honeypot {__version__}")
    parser.add_argument("--headless", action="store_true", help="Non-interactive mode (all defaults)")
    parser.add_argument("-c", "--config", help="YAML config file path")
    parser.add_argument("--db", default=None, help="Database file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (errors only)")

    sub = parser.add_subparsers(dest="command")
    stats_parser = sub.add_parser("stats", help="Show captured statistics")
    stats_parser.add_argument("--db", default="honeypot.db", help="Database path")

    args = parser.parse_args()

    if args.command == "stats":
        asyncio.run(_run_stats(args))
        return

    print(BANNER.format(version=__version__))
    _setup_logging(args)

    if args.headless or args.config:
        # Non-interactive: load from YAML or use defaults
        config = load_config(args.config)
        if args.db:
            config.database_path = args.db
        if not config.dashboard.auth_token:
            config.dashboard.auth_token = secrets.token_urlsafe(24)
    else:
        # Interactive setup
        config = _interactive_setup()
        if args.db:
            config.database_path = args.db

    # Kill any stale processes holding our ports
    print(f"\n  {DIM}Opening ports for honeypot services...{RESET}", flush=True)
    _kill_stale_ports(config)
    print()

    display_host = _get_local_ip() if config.dashboard.host == "0.0.0.0" else config.dashboard.host
    orchestrator = HoneypotOrchestrator(config, on_service_started=_spin_print, on_service_failed=_spin_fail, display_host=display_host)
    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        pass
