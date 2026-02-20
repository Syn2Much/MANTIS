"""CLI argument parsing, config loading, and banner display."""

import argparse
import asyncio
import logging
import os
import sys

from . import __version__
from .config import HoneypotConfig, load_config
from .core import HoneypotOrchestrator

BANNER = r"""
{g}
                  \  /
                   \/
                   /\
                  /  \
            ----./    \.----
           /    / \  / \    \
          /    /   \/   \    \
               |   /\   |
               |  /  \  |
               | /    \ |
               |/      \|
{r}
    ███╗   ███╗ █████╗ ███╗   ██╗████████╗██╗███████╗
    ████╗ ████║██╔══██╗████╗  ██║╚══██╔══╝██║██╔════╝
    ██╔████╔██║███████║██╔██╗ ██║   ██║   ██║███████╗
    ██║╚██╔╝██║██╔══██║██║╚██╗██║   ██║   ██║╚════██║
    ██║ ╚═╝ ██║██║  ██║██║ ╚████║   ██║   ██║███████║
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚══════╝
{d}
    Network Threat Intelligence       v{version}
    Watch. Wait. Capture.
""".format(g="\033[33m", r="\033[0m", d="\033[2m", version="{version}") + "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MANTIS - Network Threat Intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"honeypot {__version__}")

    sub = parser.add_subparsers(dest="command")

    # Run (default)
    run_parser = sub.add_parser("run", help="Start the honeypot (default)")
    _add_run_args(run_parser)

    # Also add run args to main parser for default behavior
    _add_run_args(parser)

    # Stats subcommand
    stats_parser = sub.add_parser("stats", help="Show captured statistics")
    stats_parser.add_argument("--db", default="honeypot.db", help="Database path")

    return parser


def _add_run_args(parser):
    parser.add_argument("-c", "--config", help="YAML config file path")
    parser.add_argument("-p", "--profile", help="Profile YAML (from profiles/ directory)")
    parser.add_argument("--port-ssh", type=int, help="SSH port override")
    parser.add_argument("--port-http", type=int, help="HTTP port override")
    parser.add_argument("--port-ftp", type=int, help="FTP port override")
    parser.add_argument("--port-smb", type=int, help="SMB port override")
    parser.add_argument("--port-mysql", type=int, help="MySQL port override")
    parser.add_argument("--port-telnet", type=int, help="Telnet port override")
    parser.add_argument("--port-smtp", type=int, help="SMTP port override")
    parser.add_argument("--port-mongodb", type=int, help="MongoDB port override")
    parser.add_argument("--port-vnc", type=int, help="VNC port override")
    parser.add_argument("--port-redis", type=int, help="Redis port override")
    parser.add_argument("--port-adb", type=int, help="ADB port override")
    parser.add_argument("--port-dashboard", type=int, help="Dashboard port override")
    parser.add_argument("--services", help="Comma-separated list of services to enable")
    parser.add_argument("--webhook", help="Webhook URL for alerts")
    parser.add_argument("--db", default=None, help="Database file path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode (errors only)")


def _resolve_config(args) -> HoneypotConfig:
    """Resolve config from file/profile + CLI overrides."""
    config_path = None
    if args.config:
        config_path = args.config
    elif args.profile:
        # Look for profile in profiles/ directory
        profile_path = args.profile
        if not os.path.exists(profile_path):
            profile_path = os.path.join("profiles", args.profile)
        if not os.path.exists(profile_path):
            profile_path = os.path.join("profiles", f"{args.profile}.yaml")
        if os.path.exists(profile_path):
            config_path = profile_path

    config = load_config(config_path)

    # CLI overrides
    port_map = {
        "port_ssh": "ssh",
        "port_http": "http",
        "port_ftp": "ftp",
        "port_smb": "smb",
        "port_mysql": "mysql",
        "port_telnet": "telnet",
        "port_smtp": "smtp",
        "port_mongodb": "mongodb",
        "port_vnc": "vnc",
        "port_redis": "redis",
        "port_adb": "adb",
    }
    for arg_name, svc_name in port_map.items():
        val = getattr(args, arg_name, None)
        if val is not None:
            getattr(config, svc_name).port = val

    if getattr(args, "port_dashboard", None):
        config.dashboard.port = args.port_dashboard

    if args.services:
        enabled = set(s.strip().lower() for s in args.services.split(","))
        for svc in ("ssh", "http", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
            getattr(config, svc).enabled = svc in enabled

    if args.webhook:
        config.alerts.webhook_url = args.webhook

    if getattr(args, "db", None):
        config.database_path = args.db

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


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "stats":
        asyncio.run(_run_stats(args))
        return

    _setup_logging(args)
    config = _resolve_config(args)

    print(BANNER.format(version=__version__))

    services = config.enabled_services()
    print(f"  Services: {', '.join(s.upper() for s in services)}")
    for svc in services:
        cfg = config.get_service_config(svc)
        print(f"    {svc.upper():6s} -> port {cfg.port}")
    if config.dashboard.enabled:
        print(f"  Dashboard -> http://{config.dashboard.host}:{config.dashboard.port}")
    print()

    orchestrator = HoneypotOrchestrator(config)
    try:
        asyncio.run(orchestrator.run())
    except KeyboardInterrupt:
        pass
