"""Configuration dataclasses and YAML loading."""

from dataclasses import dataclass, field
from typing import Optional
import yaml


@dataclass
class ServiceConfig:
    enabled: bool = True
    port: int = 0
    banner: str = ""
    extra: dict = field(default_factory=dict)


@dataclass
class DashboardConfig:
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 8080
    auth_token: Optional[str] = None


@dataclass
class AlertConfig:
    enabled: bool = True
    webhook_url: Optional[str] = None
    webhook_headers: dict = field(default_factory=dict)
    rules: dict = field(default_factory=dict)


@dataclass
class HoneypotConfig:
    ssh: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=2222, banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"))
    http: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=8080))
    ftp: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=21, banner="220 FTP Server ready."))
    smb: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=4450))
    mysql: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=3306, banner="5.7.42-0ubuntu0.18.04.1"))
    telnet: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=2323, banner="gateway-01 login: ", extra={"additional_ports": [23]}))
    smtp: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=25, banner="220 mail.example.com ESMTP Postfix (Ubuntu)"))
    mongodb: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=27017, banner="6.0.12"))
    vnc: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=5900, banner="prod-workstation:0"))
    redis: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=6379))
    adb: ServiceConfig = field(default_factory=lambda: ServiceConfig(port=5555, banner="device::Pixel 7"))
    dashboard: DashboardConfig = field(default_factory=lambda: DashboardConfig(port=8843))
    alerts: AlertConfig = field(default_factory=AlertConfig)
    database_path: str = "honeypot.db"
    log_level: str = "INFO"

    def get_service_config(self, name: str) -> ServiceConfig:
        return getattr(self, name, ServiceConfig(enabled=False))

    def enabled_services(self) -> list:
        services = []
        for name in ("ssh", "http", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
            cfg = self.get_service_config(name)
            if cfg.enabled:
                services.append(name)
        return services

    def to_dict(self) -> dict:
        """Serialize entire config to a dictionary."""
        result = {}
        for name in ("ssh", "http", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
            cfg = self.get_service_config(name)
            result[name] = {
                "enabled": cfg.enabled,
                "port": cfg.port,
                "banner": cfg.banner,
            }
        result["dashboard"] = {
            "enabled": self.dashboard.enabled,
            "host": self.dashboard.host,
            "port": self.dashboard.port,
        }
        result["alerts"] = {
            "enabled": self.alerts.enabled,
            "webhook_url": self.alerts.webhook_url,
        }
        result["database_path"] = self.database_path
        result["log_level"] = self.log_level
        return result


def _merge_service(base: ServiceConfig, overrides: dict) -> ServiceConfig:
    if "enabled" in overrides:
        base.enabled = overrides["enabled"]
    if "port" in overrides:
        base.port = overrides["port"]
    if "banner" in overrides:
        base.banner = overrides["banner"]
    for k, v in overrides.items():
        if k not in ("enabled", "port", "banner"):
            base.extra[k] = v
    return base


def load_config(path: Optional[str] = None) -> HoneypotConfig:
    """Load config from YAML file, falling back to defaults."""
    config = HoneypotConfig()
    if path is None:
        return config

    with open(path, "r") as f:
        raw = yaml.safe_load(f) or {}

    for svc_name in ("ssh", "http", "ftp", "smb", "mysql", "telnet", "smtp", "mongodb", "vnc", "redis", "adb"):
        if svc_name in raw:
            _merge_service(getattr(config, svc_name), raw[svc_name])

    if "dashboard" in raw:
        d = raw["dashboard"]
        if "enabled" in d:
            config.dashboard.enabled = d["enabled"]
        if "host" in d:
            config.dashboard.host = d["host"]
        if "port" in d:
            config.dashboard.port = d["port"]

    if "alerts" in raw:
        a = raw["alerts"]
        if "enabled" in a:
            config.alerts.enabled = a["enabled"]
        if "webhook_url" in a:
            config.alerts.webhook_url = a["webhook_url"]
        if "webhook_headers" in a:
            config.alerts.webhook_headers = a["webhook_headers"]
        if "rules" in a:
            config.alerts.rules = a["rules"]

    if "database_path" in raw:
        config.database_path = raw["database_path"]
    if "log_level" in raw:
        config.log_level = raw["log_level"]

    return config
