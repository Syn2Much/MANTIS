"""Alert engine with stateless and stateful rules, plus webhook dispatch."""

import asyncio
import json
import logging
import re
from datetime import datetime

import aiohttp

from .models import Alert, Event

logger = logging.getLogger("honeypot.alerts")


# ── HTTP Threat Detection Patterns ───────────────────────────────────────────
# Each tuple: (name, severity, compiled_regex, description)

HTTP_THREAT_PATTERNS: list[tuple[str, str, re.Pattern, str]] = [
    # Log4Shell (CVE-2021-44228)
    ("log4shell", "critical", re.compile(r"\$\{jndi:", re.IGNORECASE),
     "Log4Shell JNDI injection attempt (CVE-2021-44228)"),
    # Spring4Shell (CVE-2022-22965)
    ("spring4shell", "critical",
     re.compile(r"class\.module\.classLoader|ClassLoader.*getURLs", re.IGNORECASE),
     "Spring4Shell RCE attempt (CVE-2022-22965)"),
    # Shellshock (CVE-2014-6271)
    ("shellshock", "critical", re.compile(r"\(\)\s*\{.*;\s*\}"),
     "Shellshock bash injection (CVE-2014-6271)"),
    # PHP RCE
    ("php_rce", "high",
     re.compile(r"(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(", re.IGNORECASE),
     "PHP remote code execution attempt"),
    # Command injection
    ("command_injection", "high",
     re.compile(r"(?:;|\||&&|\$\(|`)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby)\b"),
     "OS command injection attempt"),
    # SQL injection
    ("sql_injection", "high",
     re.compile(r"(?:'\s*(?:OR|AND|UNION)\s+|--\s*$|;\s*(?:DROP|DELETE|INSERT|UPDATE|SELECT)\s)", re.IGNORECASE),
     "SQL injection attempt"),
    # Path traversal
    ("path_traversal", "high", re.compile(r"(?:\.\./|\.\.\\){2,}|/etc/(?:passwd|shadow|hosts)"),
     "Path traversal / local file inclusion"),
    # XSS
    ("xss", "medium",
     re.compile(r"<script[^>]*>|javascript:|on(?:error|load|mouseover)\s*=", re.IGNORECASE),
     "Cross-site scripting (XSS) attempt"),
    # Known CVE path probes
    ("cve_path_probe", "medium",
     re.compile(r"(?:/\.env|/wp-admin|/wp-login|/actuator|/\.git/|/phpmyadmin|/phpinfo|/server-status|/admin/config|/solr/|/struts|/cgi-bin/)", re.IGNORECASE),
     "Known vulnerable path probe"),
    # Web shell probes
    ("webshell_probe", "high",
     re.compile(r"(?:c99|r57|wso|b374k|alfa|webshell|cmd\.php|shell\.php)", re.IGNORECASE),
     "Web shell access attempt"),
]


class AlertRule:
    """Base alert rule."""
    name: str = ""
    severity: str = "medium"
    description: str = ""

    def check(self, event: Event) -> Alert | None:
        return None


class SSHShellAccess(AlertRule):
    name = "ssh_shell_access"
    severity = "critical"
    description = "Command input detected after SSH authentication"

    def check(self, event: Event) -> Alert | None:
        if event.service == "ssh" and event.event_type == "command":
            return Alert(
                rule_name=self.name,
                severity=self.severity,
                src_ip=event.src_ip,
                service=event.service,
                message=f"SSH shell command from {event.src_ip}: {event.data.get('command', '?')[:100]}",
                event_ids=[event.id] if event.id else [],
            )
        return None


class PayloadCaptured(AlertRule):
    name = "payload_captured"
    severity = "critical"
    description = "Binary upload/download attempt detected"

    def check(self, event: Event) -> Alert | None:
        if event.event_type == "file_transfer":
            direction = event.data.get("direction", "unknown")
            filename = event.data.get("filename", "unknown")
            return Alert(
                rule_name=self.name,
                severity=self.severity,
                src_ip=event.src_ip,
                service=event.service,
                message=f"File {direction} attempt from {event.src_ip}: {filename}",
                event_ids=[event.id] if event.id else [],
            )
        return None


class NTLMHashCaptured(AlertRule):
    name = "ntlm_hash_captured"
    severity = "high"
    description = "SMB NTLM authentication data captured"

    def check(self, event: Event) -> Alert | None:
        if event.service == "smb" and event.event_type == "ntlm_auth":
            user = event.data.get("username", "unknown")
            domain = event.data.get("domain", "")
            return Alert(
                rule_name=self.name,
                severity=self.severity,
                src_ip=event.src_ip,
                service=event.service,
                message=f"NTLM auth captured from {event.src_ip}: {domain}\\{user}",
                event_ids=[event.id] if event.id else [],
            )
        return None


class MySQLQuery(AlertRule):
    name = "mysql_query"
    severity = "high"
    description = "SQL query received on honeypot MySQL"

    def check(self, event: Event) -> Alert | None:
        if event.service == "mysql" and event.event_type == "query":
            query = event.data.get("query", "?")[:200]
            return Alert(
                rule_name=self.name,
                severity=self.severity,
                src_ip=event.src_ip,
                service=event.service,
                message=f"MySQL query from {event.src_ip}: {query}",
                event_ids=[event.id] if event.id else [],
            )
        return None


class HTTPThreatDetector(AlertRule):
    """Stateless rule: detect RCE, CVE, and attack patterns in HTTP requests."""
    name = "http_threat"
    severity = "high"
    description = "HTTP attack payload detected"

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def check(self, event: Event) -> Alert | None:
        if event.service != "http" or event.event_type != "request":
            return None

        data = event.data
        # Build search corpus from all relevant fields
        parts = [
            data.get("path", ""),
            data.get("body", ""),
            data.get("user_agent", ""),
            str(data.get("query", "")),
        ]
        headers = data.get("headers", {})
        if isinstance(headers, dict):
            parts.extend(headers.values())
        corpus = " ".join(str(p) for p in parts)

        matched = []
        for pattern_name, sev, regex, desc in HTTP_THREAT_PATTERNS:
            if regex.search(corpus):
                matched.append((pattern_name, sev, desc))

        if not matched:
            return None

        # Use highest severity among matches
        best_sev = min(matched, key=lambda m: self.SEVERITY_ORDER.get(m[1], 99))[1]
        names = [m[0] for m in matched]
        descs = [m[2] for m in matched]

        return Alert(
            rule_name=self.name,
            severity=best_sev,
            src_ip=event.src_ip,
            service=event.service,
            message=f"HTTP threat from {event.src_ip}: {', '.join(names)} — {data.get('path', '?')}",
            event_ids=[event.id] if event.id else [],
        )


class BruteForceDetector:
    """Stateful rule: sliding window counter for brute force detection."""
    name = "brute_force"
    severity = "high"
    description = "Excessive auth attempts from same IP"

    def __init__(self, threshold: int = 20, window_seconds: int = 300):
        self.threshold = threshold
        self.window = window_seconds
        # ip -> list of timestamps
        self._counters: dict[str, list[float]] = {}
        self._alerted: set[str] = set()

    def check(self, event: Event) -> Alert | None:
        if event.event_type != "auth_attempt":
            return None

        ip = event.src_ip
        now = datetime.utcnow().timestamp()

        if ip not in self._counters:
            self._counters[ip] = []

        timestamps = self._counters[ip]
        timestamps.append(now)
        # Prune old entries
        cutoff = now - self.window
        self._counters[ip] = [t for t in timestamps if t > cutoff]

        count = len(self._counters[ip])
        if count >= self.threshold and ip not in self._alerted:
            self._alerted.add(ip)
            return Alert(
                rule_name=self.name,
                severity=self.severity,
                src_ip=ip,
                service=event.service,
                message=f"Brute force detected: {count} auth attempts from {ip} in {self.window}s",
                event_ids=[event.id] if event.id else [],
            )
        return None


class ReconnaissanceDetector:
    """Stateful rule: same IP hits multiple services."""
    name = "reconnaissance"
    severity = "medium"
    description = "Same IP probing multiple services"

    def __init__(self, threshold: int = 3, window_seconds: int = 600):
        self.threshold = threshold
        self.window = window_seconds
        # ip -> {service: first_seen_timestamp}
        self._tracking: dict[str, dict[str, float]] = {}
        self._alerted: set[str] = set()

    def check(self, event: Event) -> Alert | None:
        if event.event_type != "connection":
            return None

        ip = event.src_ip
        now = datetime.utcnow().timestamp()

        if ip not in self._tracking:
            self._tracking[ip] = {}

        cutoff = now - self.window
        self._tracking[ip] = {
            svc: ts for svc, ts in self._tracking[ip].items() if ts > cutoff
        }
        self._tracking[ip][event.service] = now

        num_services = len(self._tracking[ip])
        if num_services >= self.threshold and ip not in self._alerted:
            self._alerted.add(ip)
            services = list(self._tracking[ip].keys())
            return Alert(
                rule_name=self.name,
                severity=self.severity,
                src_ip=ip,
                service=",".join(services),
                message=f"Reconnaissance: {ip} probed {num_services} services: {', '.join(services)}",
                event_ids=[event.id] if event.id else [],
            )
        return None


class AlertEngine:
    """Processes events through rules and dispatches alerts."""

    def __init__(self, database, config=None):
        self._db = database
        self._config = config
        self._webhook_url = config.webhook_url if config else None
        self._webhook_headers = config.webhook_headers if config else {}
        self._session: aiohttp.ClientSession | None = None

        self._stateless_rules: list[AlertRule] = [
            SSHShellAccess(),
            PayloadCaptured(),
            NTLMHashCaptured(),
            MySQLQuery(),
            HTTPThreatDetector(),
        ]
        self._stateful_rules = [
            BruteForceDetector(),
            ReconnaissanceDetector(),
        ]

    async def process_event(self, event: Event) -> list[Alert]:
        """Check event against all rules. Returns list of triggered alerts."""
        alerts = []

        for rule in self._stateless_rules:
            alert = rule.check(event)
            if alert:
                alert = await self._db.save_alert(alert)
                alerts.append(alert)

        for rule in self._stateful_rules:
            alert = rule.check(event)
            if alert:
                alert = await self._db.save_alert(alert)
                alerts.append(alert)

        if alerts and self._webhook_url:
            for alert in alerts:
                asyncio.create_task(self._dispatch_webhook(alert))

        return alerts

    async def _dispatch_webhook(self, alert: Alert):
        try:
            if self._session is None or self._session.closed:
                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=10)
                )
            payload = {
                "alert": alert.to_dict(),
                "source": "honeypot",
                "timestamp": datetime.utcnow().isoformat(),
            }
            headers = {"Content-Type": "application/json"}
            headers.update(self._webhook_headers)
            async with self._session.post(
                self._webhook_url, json=payload, headers=headers
            ) as resp:
                if resp.status >= 400:
                    logger.warning("Webhook returned %d", resp.status)
                else:
                    logger.debug("Webhook dispatched for alert %s", alert.rule_name)
        except Exception as e:
            logger.warning("Webhook dispatch failed: %s", e)

    def reset_stateful_rules(self):
        """Clear all stateful rule counters (e.g. after database reset)."""
        self._stateful_rules = [
            BruteForceDetector(),
            ReconnaissanceDetector(),
        ]
        logger.info("Alert engine stateful rules reset")

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
