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
import questionary.constants as qconst
from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
from prompt_toolkit.styles import Style as PTStyle

from . import __version__
from .config import HoneypotConfig, load_config
from .core import HoneypotOrchestrator

# Override questionary's default indicators for clearer checkboxes
qconst.INDICATOR_SELECTED = "[x]"
qconst.INDICATOR_UNSELECTED = "[ ]"

MANTIS_STYLE = PTStyle([
    ("qmark", "fg:ansicyan bold"),
    ("question", "bold"),
    ("answer", "fg:ansicyan bold"),
    ("pointer", "fg:ansicyan bold"),
    ("highlighted", "fg:ansicyan bold"),
    ("selected", "fg:ansicyan bold"),
    ("instruction", "fg:ansibrightblack"),
    ("text", "fg:ansiwhite"),
    ("separator", "fg:ansibrightblack"),
])

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


def _service_selector():
    """Combined service checkbox + inline port editing with right-arrow.

    Returns (selected_names, ports_dict) or None if cancelled.
    """
    from questionary.prompts.common import Choice, InquirerControl, Separator, create_inquirer_layout
    from questionary.styles import merge_styles_default

    ports = {name: port for name, port in ALL_SERVICES}
    ports["dashboard"] = 8843
    editing = {"active": False, "buffer": ""}

    def make_title(name, port):
        return f"{name.upper():8s}  :{port}"

    choices = [
        Choice(make_title(name, port), value=name, checked=True)
        for name, port in ALL_SERVICES
    ]
    choices.append(Separator("\u2500" * 28))
    choices.append(Choice(make_title("dashboard", 8843), value="dashboard", checked=True))

    ic = InquirerControl(choices, pointer="\u276f")

    def get_prompt_tokens():
        tokens = [
            ("class:qmark", "?"),
            ("class:question", " Select services & configure ports "),
        ]
        if ic.is_answered:
            nbr = len(ic.selected_options) - (1 if "dashboard" in ic.selected_options else 0)
            tokens.append(("class:answer", f"done ({nbr} services)"))
        elif editing["active"]:
            name = ic.get_pointed_at().value
            tokens.append(
                ("class:instruction",
                 f" {name.upper()} port: {editing['buffer']}\u2588"
                 "  (enter = save, esc = cancel)")
            )
        else:
            tokens.append(
                ("class:instruction",
                 "(space = toggle, \u2192 = set port, enter = confirm)")
            )
        return tokens

    layout = create_inquirer_layout(ic, get_prompt_tokens)

    bindings = KeyBindings()

    @bindings.add(Keys.ControlC, eager=True)
    @bindings.add(Keys.ControlQ, eager=True)
    def abort(event):
        event.app.exit(exception=KeyboardInterrupt, style="class:aborting")

    @bindings.add(" ", eager=True)
    def toggle(event):
        if editing["active"]:
            return
        pointed = ic.get_pointed_at().value
        if pointed in ic.selected_options:
            ic.selected_options.remove(pointed)
        else:
            ic.selected_options.append(pointed)

    @bindings.add(Keys.Right, eager=True)
    def enter_edit(event):
        if editing["active"]:
            return
        name = ic.get_pointed_at().value
        editing["active"] = True
        editing["buffer"] = str(ports[name])

    @bindings.add(Keys.Escape, eager=True)
    def cancel_edit(event):
        if editing["active"]:
            editing["active"] = False
            editing["buffer"] = ""

    @bindings.add(Keys.Backspace, eager=True)
    def backspace(event):
        if editing["active"]:
            editing["buffer"] = editing["buffer"][:-1]

    for d in "0123456789":
        @bindings.add(d, eager=True)
        def digit(event, _d=d):
            if editing["active"]:
                editing["buffer"] += _d

    @bindings.add(Keys.ControlM, eager=True)
    def enter(event):
        if editing["active"]:
            name = ic.get_pointed_at().value
            buf = editing["buffer"]
            if buf.isdigit() and 1 <= int(buf) <= 65535:
                ports[name] = int(buf)
                ic.get_pointed_at().title = make_title(name, ports[name])
            editing["active"] = False
            editing["buffer"] = ""
        else:
            ic.is_answered = True
            selected = [c.value for c in ic.get_selected_values()]
            event.app.exit(result=(selected, dict(ports)))

    @bindings.add(Keys.Up, eager=True)
    def up(event):
        if not editing["active"]:
            ic.select_previous()
            while not ic.is_selection_valid():
                ic.select_previous()

    @bindings.add(Keys.Down, eager=True)
    def down(event):
        if not editing["active"]:
            ic.select_next()
            while not ic.is_selection_valid():
                ic.select_next()

    @bindings.add("a", eager=True)
    def select_all(event):
        if editing["active"]:
            return
        all_selected = all(
            c.value in ic.selected_options
            for c in ic.choices
            if not isinstance(c, Separator) and not c.disabled
        )
        if all_selected:
            ic.selected_options = []
        else:
            for c in ic.choices:
                if not isinstance(c, Separator) and c.value not in ic.selected_options and not c.disabled:
                    ic.selected_options.append(c.value)

    @bindings.add(Keys.Any)
    def other(event):
        """Disallow inserting other text."""

    merged_style = merge_styles_default([
        PTStyle([("bottom-toolbar", "noreverse")]),
        MANTIS_STYLE,
    ])

    app = Application(layout=layout, key_bindings=bindings, style=merged_style)
    try:
        return app.run()
    except KeyboardInterrupt:
        return None


def _interactive_setup() -> HoneypotConfig:
    """Run interactive service selector then prompt for auth token."""
    config = HoneypotConfig()

    # 1. Combined service selection + port editing
    result = _service_selector()
    if result is None:
        sys.exit(0)

    selected, ports = result

    # Apply selections and ports
    for name, _ in ALL_SERVICES:
        svc = getattr(config, name)
        svc.enabled = name in selected
        if name in ports:
            svc.port = ports[name]

    # Dashboard
    config.dashboard.enabled = "dashboard" in selected
    if "dashboard" in ports:
        config.dashboard.port = ports["dashboard"]

    # 2. Auth token
    default_token = secrets.token_urlsafe(24)
    token = questionary.text("Auth token", default=default_token, style=MANTIS_STYLE).ask()
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
