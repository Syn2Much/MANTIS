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
    def __init__(self, config: HoneypotConfig):
        self.config = config
        self.db = Database(config.database_path)
        self.geo = GeoLocator(self.db)
        self.alerts = AlertEngine(self.db, config.alerts)
        self.dashboard = None
        self.services: list = []
        self._shutdown_event = asyncio.Event()

    async def start(self):
        """Initialize all components and start services."""
        await self.db.initialize()
        logger.info("Database ready")

        # Start services
        for svc_name in self.config.enabled_services():
            svc_class = SERVICE_MAP.get(svc_name)
            if svc_class is None:
                logger.warning("Unknown service: %s", svc_name)
                continue
            svc_config = self.config.get_service_config(svc_name)
            service = svc_class(svc_config, self.db, self.alerts, self.geo)
            try:
                await service.start()
                self.services.append(service)
            except OSError as e:
                logger.error("Failed to start %s on port %d: %s", svc_name, svc_config.port, e)

        # Start dashboard
        if self.config.dashboard.enabled:
            self.dashboard = DashboardServer(self.db, self.geo, self.config.dashboard, orchestrator=self)
            try:
                await self.dashboard.start()
            except OSError as e:
                logger.error("Failed to start dashboard: %s", e)

        # Setup signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._signal_handler)
            except NotImplementedError:
                pass  # Windows

        logger.info(
            "Honeypot running — %d services active, dashboard %s",
            len(self.services),
            f"at http://{self.config.dashboard.host}:{self.config.dashboard.port}" if self.config.dashboard.enabled else "disabled",
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
        logger.info("Shutting down...")

        if self.dashboard:
            await self.dashboard.stop()

        for service in self.services:
            try:
                await service.stop()
            except Exception as e:
                logger.error("Error stopping %s: %s", service.service_name, e)

        await self.alerts.close()
        await self.geo.close()
        await self.db.close()
        logger.info("Shutdown complete")
