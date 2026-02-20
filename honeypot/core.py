"""Orchestrator: wires DB, services, alerts, dashboard and handles lifecycle."""

import asyncio
import logging
import signal

from .config import HoneypotConfig
from .database import Database
from .geo import GeoLocator
from .alerts import AlertEngine
from .dashboard.server import DashboardServer
from .services.ssh import SSHHoneypot
from .services.http import HTTPHoneypot
from .services.ftp import FTPHoneypot
from .services.smb import SMBHoneypot
from .services.mysql import MySQLHoneypot
from .services.telnet import TelnetHoneypot
from .services.smtp import SMTPHoneypot
from .services.mongodb import MongoDBHoneypot
from .services.vnc import VNCHoneypot
from .services.redis import RedisHoneypot
from .services.adb import ADBHoneypot

logger = logging.getLogger("honeypot.core")

SERVICE_MAP = {
    "ssh": SSHHoneypot,
    "http": HTTPHoneypot,
    "ftp": FTPHoneypot,
    "smb": SMBHoneypot,
    "mysql": MySQLHoneypot,
    "telnet": TelnetHoneypot,
    "smtp": SMTPHoneypot,
    "mongodb": MongoDBHoneypot,
    "vnc": VNCHoneypot,
    "redis": RedisHoneypot,
    "adb": ADBHoneypot,
}


class HoneypotOrchestrator:
    def __init__(self, config: HoneypotConfig, on_service_started=None, on_service_failed=None, display_host=None):
        self.config = config
        self.db = Database(config.database_path)
        self.geo = GeoLocator(self.db)
        self.alerts = AlertEngine(self.db, config.alerts)
        self.dashboard = None
        self.services: list = []
        self._shutdown_event = asyncio.Event()
        self._on_started = on_service_started
        self._on_failed = on_service_failed
        self._display_host = display_host

    def _notify_started(self, msg: str):
        if self._on_started:
            self._on_started(msg)
        else:
            logger.info(msg)

    def _notify_failed(self, msg: str, detail: str = ""):
        if self._on_failed:
            self._on_failed(msg, detail)
        else:
            logger.error("%s: %s", msg, detail)

    async def start(self):
        """Initialize all components and start services."""
        await self.db.initialize()
        self._notify_started("Database initialized")

        # Start services
        for svc_name in self.config.enabled_services():
            svc_class = SERVICE_MAP.get(svc_name)
            if svc_class is None:
                self._notify_failed(f"{svc_name.upper()}", "unknown service")
                continue
            svc_config = self.config.get_service_config(svc_name)
            service = svc_class(svc_config, self.db, self.alerts, self.geo)
            try:
                await service.start()
                self.services.append(service)
                self._notify_started(f"{svc_name.upper():8s} listening on port {svc_config.port}")
            except OSError as e:
                self._notify_failed(f"{svc_name.upper():8s} port {svc_config.port}", str(e))

        # Start dashboard
        if self.config.dashboard.enabled:
            self.dashboard = DashboardServer(self.db, self.geo, self.config.dashboard, orchestrator=self)
            try:
                await self.dashboard.start()
                host = self._display_host or self.config.dashboard.host
                dash_url = f"http://{host}:{self.config.dashboard.port}"
                self._notify_started(f"Dashboard  {dash_url}")
            except OSError as e:
                self._notify_failed("Dashboard", str(e))

        # Print summary
        if self._on_started:
            import sys
            print(flush=True)
            token = self.config.dashboard.auth_token
            if token:
                print(f"  \033[1mAuth Token \033[33m{token}\033[0m", flush=True)
            print(f"\n  \033[1m\033[32m{len(self.services)} services active\033[0m — press Ctrl+C to stop\n", flush=True)

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._signal_handler)
            except NotImplementedError:
                pass  # Windows

        dash_host = self._display_host or self.config.dashboard.host
        logger.info(
            "Honeypot running — %d services active, dashboard %s",
            len(self.services),
            f"at http://{dash_host}:{self.config.dashboard.port}" if self.config.dashboard.enabled else "disabled",
        )

    def get_config_dict(self) -> dict:
        """Return the full running config as a dictionary."""
        return self.config.to_dict()

    async def update_service_config(self, svc_name: str, updates: dict) -> dict:
        """Apply config changes to a service, restart it if running."""
        if svc_name not in SERVICE_MAP:
            raise ValueError(f"Unknown service: {svc_name}")

        svc_config = self.config.get_service_config(svc_name)

        # Apply updates
        if "enabled" in updates:
            svc_config.enabled = updates["enabled"]
        if "port" in updates:
            svc_config.port = updates["port"]
        if "banner" in updates:
            svc_config.banner = updates["banner"]

        # Find and stop existing service instance
        old_svc = None
        for i, s in enumerate(self.services):
            if s.service_name == svc_name:
                old_svc = i
                break
        if old_svc is not None:
            try:
                await self.services[old_svc].stop()
            except Exception as e:
                logger.error("Error stopping %s: %s", svc_name, e)
            self.services.pop(old_svc)

        # Start new instance if enabled
        if svc_config.enabled:
            svc_class = SERVICE_MAP[svc_name]
            service = svc_class(svc_config, self.db, self.alerts, self.geo)
            try:
                await service.start()
                self.services.append(service)
                logger.info("Service %s restarted on port %d", svc_name, svc_config.port)
            except OSError as e:
                logger.error("Failed to start %s on port %d: %s", svc_name, svc_config.port, e)

        return self.config.to_dict()

    async def reset_database(self):
        """Wipe all captured data and reset alert engine state."""
        await self.db.reset_database()
        self.alerts.reset_stateful_rules()
        logger.info("Full database reset completed")

    def _signal_handler(self):
        logger.info("Shutdown signal received")
        self._shutdown_event.set()

    async def run(self):
        """Start and wait for shutdown."""
        await self.start()
        await self._shutdown_event.wait()
        await self.stop()

    async def stop(self):
        """Gracefully stop all components."""
        if self._on_started:
            import sys
            print(f"\n  \033[1mShutting down...\033[0m\n")

        if self.dashboard:
            await self.dashboard.stop()
            self._notify_started("Dashboard stopped")

        for service in self.services:
            try:
                await service.stop()
                self._notify_started(f"{service.service_name.upper():8s} stopped")
            except Exception as e:
                self._notify_failed(f"{service.service_name.upper():8s} stop", str(e))

        await self.alerts.close()
        await self.geo.close()
        await self.db.close()
        self._notify_started("Database closed")

        if self._on_started:
            print(f"\n  \033[2mClean shutdown complete.\033[0m\n")
        logger.info("Shutdown complete")
