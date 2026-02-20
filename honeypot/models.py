"""Data models for the honeypot system."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    CONNECTION = "connection"
    AUTH_ATTEMPT = "auth_attempt"
    COMMAND = "command"
    REQUEST = "request"
    QUERY = "query"
    FILE_TRANSFER = "file_transfer"
    NTLM_AUTH = "ntlm_auth"
    DISCONNECT = "disconnect"
    ERROR = "error"


class ServiceType(str, Enum):
    SSH = "ssh"
    HTTP = "http"
    FTP = "ftp"
    SMB = "smb"
    MYSQL = "mysql"
    TELNET = "telnet"
    SMTP = "smtp"
    MONGODB = "mongodb"
    VNC = "vnc"
    REDIS = "redis"
    ADB = "adb"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class GeoInfo:
    ip: str
    country: str = "Unknown"
    country_code: str = ""
    region: str = ""
    city: str = ""
    lat: float = 0.0
    lon: float = 0.0
    isp: str = ""
    org: str = ""
    as_number: str = ""
    cached_at: str = ""

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "lat": self.lat,
            "lon": self.lon,
            "isp": self.isp,
            "org": self.org,
            "as_number": self.as_number,
        }


@dataclass
class Session:
    id: str
    service: str
    src_ip: str
    src_port: int
    dst_port: int
    started_at: str = ""
    ended_at: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "service": self.service,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "metadata": self.metadata,
        }


@dataclass
class Event:
    id: Optional[int] = None
    session_id: str = ""
    event_type: str = ""
    service: str = ""
    src_ip: str = ""
    timestamp: str = ""
    data: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "session_id": self.session_id,
            "event_type": self.event_type,
            "service": self.service,
            "src_ip": self.src_ip,
            "timestamp": self.timestamp,
            "data": self.data,
        }


@dataclass
class Alert:
    id: Optional[int] = None
    rule_name: str = ""
    severity: str = "medium"
    src_ip: str = ""
    service: str = ""
    message: str = ""
    event_ids: list = field(default_factory=list)
    timestamp: str = ""
    acknowledged: bool = False

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "service": self.service,
            "message": self.message,
            "event_ids": self.event_ids,
            "timestamp": self.timestamp,
            "acknowledged": self.acknowledged,
        }
