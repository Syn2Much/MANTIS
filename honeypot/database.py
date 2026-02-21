"""SQLite storage with event subscriber system for real-time push."""

import asyncio
import json
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from .models import Alert, Event, GeoInfo, Session

logger = logging.getLogger("honeypot.database")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    service TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    metadata TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    service TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    data TEXT DEFAULT '{}',
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    service TEXT NOT NULL,
    message TEXT NOT NULL,
    event_ids TEXT DEFAULT '[]',
    timestamp TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    data TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS geo_cache (
    ip TEXT PRIMARY KEY,
    country TEXT,
    country_code TEXT,
    region TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    isp TEXT,
    org TEXT,
    as_number TEXT,
    cached_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_name ON alerts(rule_name);
"""


class Database:
    def __init__(self, db_path: str = "honeypot.db"):
        self._db_path = db_path
        self._executor = ThreadPoolExecutor(max_workers=1)
        self._conn: Optional[sqlite3.Connection] = None
        self._subscribers: list[asyncio.Queue] = []
        self._alert_subscribers: list[asyncio.Queue] = []
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._closed = False

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(SCHEMA)
            self._conn.commit()
            # Migrate existing DBs: add data column to alerts if missing
            try:
                self._conn.execute("ALTER TABLE alerts ADD COLUMN data TEXT DEFAULT '{}'")
                self._conn.commit()
            except sqlite3.OperationalError:
                pass  # column already exists
        return self._conn

    async def initialize(self):
        self._loop = asyncio.get_event_loop()
        await self._loop.run_in_executor(self._executor, self._get_conn)
        logger.info("Database initialized: %s", self._db_path)

    def subscribe_events(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.append(q)
        return q

    def unsubscribe_events(self, q: asyncio.Queue):
        if q in self._subscribers:
            self._subscribers.remove(q)

    def subscribe_alerts(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._alert_subscribers.append(q)
        return q

    def unsubscribe_alerts(self, q: asyncio.Queue):
        if q in self._alert_subscribers:
            self._alert_subscribers.remove(q)

    def _notify_event(self, event: Event):
        for q in self._subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    def _notify_alert(self, alert: Alert):
        for q in self._alert_subscribers:
            try:
                q.put_nowait(alert)
            except asyncio.QueueFull:
                try:
                    q.get_nowait()
                    q.put_nowait(alert)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    pass

    def _insert_session(self, session: Session):
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, service, src_ip, src_port, dst_port, started_at, ended_at, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (session.id, session.service, session.src_ip, session.src_port,
             session.dst_port, session.started_at, session.ended_at,
             json.dumps(session.metadata)),
        )
        conn.commit()

    async def save_session(self, session: Session):
        if self._closed:
            return
        await self._loop.run_in_executor(self._executor, self._insert_session, session)

    def _insert_event(self, event: Event) -> Event:
        conn = self._get_conn()
        cursor = conn.execute(
            "INSERT INTO events (session_id, event_type, service, src_ip, timestamp, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (event.session_id, event.event_type, event.service, event.src_ip,
             event.timestamp, json.dumps(event.data)),
        )
        conn.commit()
        event.id = cursor.lastrowid
        return event

    async def save_event(self, event: Event) -> Event:
        if self._closed:
            return event
        event = await self._loop.run_in_executor(self._executor, self._insert_event, event)
        self._notify_event(event)
        return event

    def _insert_alert(self, alert: Alert) -> Alert:
        conn = self._get_conn()
        cursor = conn.execute(
            "INSERT INTO alerts (rule_name, severity, src_ip, service, message, event_ids, timestamp, acknowledged, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (alert.rule_name, alert.severity, alert.src_ip, alert.service,
             alert.message, json.dumps(alert.event_ids), alert.timestamp, 0,
             json.dumps(alert.data)),
        )
        conn.commit()
        alert.id = cursor.lastrowid
        return alert

    async def save_alert(self, alert: Alert) -> Alert:
        if self._closed:
            return alert
        alert = await self._loop.run_in_executor(self._executor, self._insert_alert, alert)
        self._notify_alert(alert)
        return alert

    def _ack_alert(self, alert_id: int):
        conn = self._get_conn()
        conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        conn.commit()

    async def acknowledge_alert(self, alert_id: int):
        await self._loop.run_in_executor(self._executor, self._ack_alert, alert_id)

    # Geo cache
    def _get_geo(self, ip: str) -> Optional[GeoInfo]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM geo_cache WHERE ip = ?", (ip,)).fetchone()
        if row:
            return GeoInfo(
                ip=row["ip"], country=row["country"], country_code=row["country_code"],
                region=row["region"], city=row["city"], lat=row["lat"], lon=row["lon"],
                isp=row["isp"], org=row["org"], as_number=row["as_number"],
                cached_at=row["cached_at"],
            )
        return None

    async def get_geo(self, ip: str) -> Optional[GeoInfo]:
        return await self._loop.run_in_executor(self._executor, self._get_geo, ip)

    def _save_geo(self, geo: GeoInfo):
        conn = self._get_conn()
        conn.execute(
            "INSERT OR REPLACE INTO geo_cache (ip, country, country_code, region, city, lat, lon, isp, org, as_number, cached_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (geo.ip, geo.country, geo.country_code, geo.region, geo.city,
             geo.lat, geo.lon, geo.isp, geo.org, geo.as_number, geo.cached_at),
        )
        conn.commit()

    async def save_geo(self, geo: GeoInfo):
        await self._loop.run_in_executor(self._executor, self._save_geo, geo)

    # Query helpers
    def _get_events(self, limit: int = 100, offset: int = 0, service: str = None,
                    event_type: str = None, src_ip: str = None,
                    services: list = None, event_types: list = None,
                    search: str = None, time_from: str = None, time_to: str = None,
                    paginated: bool = False) -> list[dict] | dict:
        conn = self._get_conn()
        query = "SELECT * FROM events WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM events WHERE 1=1"
        params = []
        count_params = []

        # Single service filter (backward compat)
        if service:
            query += " AND service = ?"
            count_query += " AND service = ?"
            params.append(service)
            count_params.append(service)
        # Multi-service filter
        if services:
            placeholders = ",".join("?" for _ in services)
            query += f" AND service IN ({placeholders})"
            count_query += f" AND service IN ({placeholders})"
            params.extend(services)
            count_params.extend(services)
        # Single type filter (backward compat)
        if event_type:
            query += " AND event_type = ?"
            count_query += " AND event_type = ?"
            params.append(event_type)
            count_params.append(event_type)
        # Multi-type filter
        if event_types:
            placeholders = ",".join("?" for _ in event_types)
            query += f" AND event_type IN ({placeholders})"
            count_query += f" AND event_type IN ({placeholders})"
            params.extend(event_types)
            count_params.extend(event_types)
        if src_ip:
            query += " AND src_ip = ?"
            count_query += " AND src_ip = ?"
            params.append(src_ip)
            count_params.append(src_ip)
        if search:
            query += " AND data LIKE ?"
            count_query += " AND data LIKE ?"
            params.append(f"%{search}%")
            count_params.append(f"%{search}%")
        if time_from:
            query += " AND timestamp >= ?"
            count_query += " AND timestamp >= ?"
            params.append(time_from)
            count_params.append(time_from)
        if time_to:
            query += " AND timestamp <= ?"
            count_query += " AND timestamp <= ?"
            params.append(time_to)
            count_params.append(time_to)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["data"] = json.loads(d["data"]) if d.get("data") else {}
            except (json.JSONDecodeError, TypeError):
                d["data"] = {"_raw": str(d.get("data", ""))}
            result.append(d)

        if paginated:
            total = conn.execute(count_query, count_params).fetchone()[0]
            return {"events": result, "total": total}

        return result

    async def get_events(self, **kwargs) -> list[dict] | dict:
        return await self._loop.run_in_executor(self._executor, lambda: self._get_events(**kwargs))

    def _get_sessions(self, limit: int = 100, offset: int = 0,
                      src_ip: str = None, service: str = None,
                      services: list = None,
                      paginated: bool = False) -> list[dict] | dict:
        conn = self._get_conn()
        query = "SELECT * FROM sessions WHERE 1=1"
        count_query = "SELECT COUNT(*) FROM sessions WHERE 1=1"
        params = []
        count_params = []
        if src_ip:
            query += " AND src_ip = ?"
            count_query += " AND src_ip = ?"
            params.append(src_ip)
            count_params.append(src_ip)
        if service:
            query += " AND service = ?"
            count_query += " AND service = ?"
            params.append(service)
            count_params.append(service)
        if services:
            placeholders = ",".join("?" for _ in services)
            query += f" AND service IN ({placeholders})"
            count_query += f" AND service IN ({placeholders})"
            params.extend(services)
            count_params.extend(services)
        query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["metadata"] = json.loads(d["metadata"]) if d.get("metadata") else {}
            except (json.JSONDecodeError, TypeError):
                d["metadata"] = {}
            result.append(d)

        if paginated:
            total = conn.execute(count_query, count_params).fetchone()[0]
            return {"sessions": result, "total": total}

        return result

    async def get_sessions(self, **kwargs) -> list[dict] | dict:
        return await self._loop.run_in_executor(self._executor, lambda: self._get_sessions(**kwargs))

    def _get_unique_ips(self) -> list[str]:
        conn = self._get_conn()
        rows = conn.execute("SELECT DISTINCT src_ip FROM events ORDER BY src_ip").fetchall()
        return [row["src_ip"] for row in rows]

    async def get_unique_ips(self) -> list[str]:
        return await self._loop.run_in_executor(self._executor, self._get_unique_ips)

    def _get_events_for_session(self, session_id: str) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["data"] = json.loads(d["data"]) if d.get("data") else {}
            except (json.JSONDecodeError, TypeError):
                d["data"] = {"_raw": str(d.get("data", ""))}
            result.append(d)
        return result

    async def get_events_for_session(self, session_id: str) -> list[dict]:
        return await self._loop.run_in_executor(self._executor, self._get_events_for_session, session_id)

    def _get_alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> list[dict]:
        conn = self._get_conn()
        query = "SELECT * FROM alerts"
        params = []
        if unacknowledged_only:
            query += " WHERE acknowledged = 0"
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["event_ids"] = json.loads(d["event_ids"]) if d.get("event_ids") else []
            except (json.JSONDecodeError, TypeError):
                d["event_ids"] = []
            try:
                d["data"] = json.loads(d["data"]) if d.get("data") else {}
            except (json.JSONDecodeError, TypeError):
                d["data"] = {}
            d["acknowledged"] = bool(d["acknowledged"])
            result.append(d)
        return result

    async def get_alerts(self, **kwargs) -> list[dict]:
        return await self._loop.run_in_executor(self._executor, lambda: self._get_alerts(**kwargs))

    def _get_stats(self) -> dict:
        conn = self._get_conn()
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        unacked_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()[0]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]

        by_service = {}
        for row in conn.execute("SELECT service, COUNT(*) as cnt FROM events GROUP BY service").fetchall():
            by_service[row["service"]] = row["cnt"]

        by_type = {}
        for row in conn.execute("SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type").fetchall():
            by_type[row["event_type"]] = row["cnt"]

        top_ips = []
        for row in conn.execute(
            "SELECT src_ip, COUNT(*) as cnt FROM events GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall():
            top_ips.append({"ip": row["src_ip"], "count": row["cnt"]})

        return {
            "total_events": total_events,
            "total_sessions": total_sessions,
            "total_alerts": total_alerts,
            "unacknowledged_alerts": unacked_alerts,
            "unique_ips": unique_ips,
            "events_by_service": by_service,
            "events_by_type": by_type,
            "top_ips": top_ips,
        }

    async def get_stats(self) -> dict:
        return await self._loop.run_in_executor(self._executor, self._get_stats)

    def _get_map_data(self) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT g.ip, g.lat, g.lon, g.country, g.city, g.isp,
                   COUNT(DISTINCT e.session_id) as session_count,
                   COUNT(e.id) as event_count,
                   GROUP_CONCAT(DISTINCT e.service) as services
            FROM geo_cache g
            JOIN events e ON e.src_ip = g.ip
            WHERE g.lat != 0 OR g.lon != 0
            GROUP BY g.ip
        """).fetchall()
        return [dict(row) for row in rows]

    async def get_map_data(self) -> list[dict]:
        return await self._loop.run_in_executor(self._executor, self._get_map_data)

    def _get_events_for_ip_window(self, ip: str, window_seconds: int) -> list[dict]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM events WHERE src_ip = ? AND timestamp >= datetime('now', ?)",
            (ip, f"-{window_seconds} seconds"),
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            try:
                d["data"] = json.loads(d["data"]) if d.get("data") else {}
            except (json.JSONDecodeError, TypeError):
                d["data"] = {"_raw": str(d.get("data", ""))}
            result.append(d)
        return result

    async def get_events_for_ip_window(self, ip: str, window_seconds: int) -> list[dict]:
        return await self._loop.run_in_executor(
            self._executor, self._get_events_for_ip_window, ip, window_seconds
        )

    def _get_attackers(self, limit: int = 100, offset: int = 0) -> dict:
        """Aggregate attacker profiles: IP, geo, services hit, event counts, timespan."""
        conn = self._get_conn()
        query = """
            SELECT e.src_ip,
                   COUNT(e.id) as event_count,
                   COUNT(DISTINCT e.session_id) as session_count,
                   COUNT(DISTINCT e.service) as service_count,
                   GROUP_CONCAT(DISTINCT e.service) as services,
                   MIN(e.timestamp) as first_seen,
                   MAX(e.timestamp) as last_seen,
                   SUM(CASE WHEN e.event_type = 'auth_attempt' THEN 1 ELSE 0 END) as auth_attempts,
                   SUM(CASE WHEN e.event_type = 'command' THEN 1 ELSE 0 END) as commands,
                   g.country, g.country_code, g.city, g.isp, g.org, g.as_number, g.lat, g.lon
            FROM events e
            LEFT JOIN geo_cache g ON e.src_ip = g.ip
            GROUP BY e.src_ip
            ORDER BY event_count DESC
            LIMIT ? OFFSET ?
        """
        rows = conn.execute(query, (limit, offset)).fetchall()
        total = conn.execute("SELECT COUNT(DISTINCT src_ip) FROM events").fetchone()[0]
        attackers = []
        for row in rows:
            attackers.append({
                "ip": row["src_ip"],
                "event_count": row["event_count"],
                "session_count": row["session_count"],
                "service_count": row["service_count"],
                "services": row["services"].split(",") if row["services"] else [],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "auth_attempts": row["auth_attempts"],
                "commands": row["commands"],
                "country": row["country"] or "Unknown",
                "country_code": row["country_code"] or "",
                "city": row["city"] or "",
                "isp": row["isp"] or "",
                "org": row["org"] or "",
                "as_number": row["as_number"] or "",
                "lat": row["lat"] or 0,
                "lon": row["lon"] or 0,
            })
        return {"attackers": attackers, "total": total}

    async def get_attackers(self, **kwargs) -> dict:
        return await self._loop.run_in_executor(self._executor, lambda: self._get_attackers(**kwargs))

    def _get_payload_stats(self) -> dict:
        """Aggregate payload/IOC alert statistics for the Payload Intel tab."""
        conn = self._get_conn()

        # Total and by-severity counts
        total = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE rule_name = 'payload_ioc'"
        ).fetchone()[0]
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM alerts WHERE rule_name = 'payload_ioc' GROUP BY severity"
        ).fetchall()
        by_severity = {row["severity"]: row["cnt"] for row in sev_rows}

        # Unique source IPs + top 10
        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM alerts WHERE rule_name = 'payload_ioc'"
        ).fetchone()[0]
        top_ips_rows = conn.execute(
            "SELECT src_ip, COUNT(*) as cnt FROM alerts WHERE rule_name = 'payload_ioc' "
            "GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        top_ips = [{"ip": row["src_ip"], "count": row["cnt"]} for row in top_ips_rows]

        # Fetch all payload_ioc alerts to parse JSON data for aggregations
        all_rows = conn.execute(
            "SELECT id, severity, src_ip, service, message, timestamp, acknowledged, data "
            "FROM alerts WHERE rule_name = 'payload_ioc' ORDER BY id DESC"
        ).fetchall()

        # Aggregation accumulators
        pattern_freq = {}       # pattern_name -> {count, severity, description}
        ioc_type_totals = {}    # ioc_type -> set of unique values
        recent_iocs = []        # last 50 unique IOC entries
        seen_iocs = set()
        timeline_buckets = {}   # hour_key -> count

        for row in all_rows:
            try:
                data = json.loads(row["data"]) if row["data"] else {}
            except (json.JSONDecodeError, TypeError):
                data = {}

            # Pattern frequency
            for p in data.get("patterns", []):
                name = p.get("name", "unknown")
                if name not in pattern_freq:
                    pattern_freq[name] = {"count": 0, "severity": p.get("severity", "medium"), "description": p.get("description", "")}
                pattern_freq[name]["count"] += 1
                # Keep worst severity
                sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
                if sev_order.get(p.get("severity"), 99) < sev_order.get(pattern_freq[name]["severity"], 99):
                    pattern_freq[name]["severity"] = p.get("severity", "medium")

            # IOC type totals + recent IOCs
            for ioc_type, values in data.get("iocs", {}).items():
                if ioc_type not in ioc_type_totals:
                    ioc_type_totals[ioc_type] = set()
                for v in values:
                    ioc_type_totals[ioc_type].add(v)
                    ioc_key = f"{ioc_type}:{v}"
                    if ioc_key not in seen_iocs and len(recent_iocs) < 50:
                        seen_iocs.add(ioc_key)
                        recent_iocs.append({"type": ioc_type, "value": v, "timestamp": row["timestamp"]})

            # Timeline buckets (per hour)
            ts = row["timestamp"] or ""
            hour_key = ts[:13]  # "YYYY-MM-DDTHH"
            if hour_key:
                timeline_buckets[hour_key] = timeline_buckets.get(hour_key, 0) + 1

        # Build sorted pattern list
        patterns_list = [
            {"name": name, "count": info["count"], "severity": info["severity"], "description": info["description"]}
            for name, info in pattern_freq.items()
        ]
        patterns_list.sort(key=lambda x: x["count"], reverse=True)

        # Convert IOC type totals to counts
        ioc_types_result = {k: len(v) for k, v in ioc_type_totals.items()}

        # Build timeline (last 48 hours, sorted)
        sorted_hours = sorted(timeline_buckets.keys())
        timeline = [{"hour": h, "count": timeline_buckets[h]} for h in sorted_hours[-48:]]

        # Recent alerts for the table (last 50)
        recent_alerts = []
        for row in all_rows[:50]:
            try:
                data = json.loads(row["data"]) if row["data"] else {}
            except (json.JSONDecodeError, TypeError):
                data = {}
            recent_alerts.append({
                "id": row["id"],
                "severity": row["severity"],
                "src_ip": row["src_ip"],
                "service": row["service"],
                "message": row["message"],
                "timestamp": row["timestamp"],
                "acknowledged": bool(row["acknowledged"]),
                "data": data,
            })

        return {
            "total": total,
            "by_severity": by_severity,
            "unique_ips": unique_ips,
            "top_ips": top_ips,
            "patterns": patterns_list,
            "ioc_types": ioc_types_result,
            "recent_iocs": recent_iocs,
            "timeline": timeline,
            "recent_alerts": recent_alerts,
        }

    async def get_payload_stats(self) -> dict:
        return await self._loop.run_in_executor(self._executor, self._get_payload_stats)

    def _export_all(self, table: str = "events") -> list[dict]:
        """Export all rows from a table for full data dump."""
        conn = self._get_conn()
        if table == "events":
            rows = conn.execute("SELECT * FROM events ORDER BY id DESC").fetchall()
            result = []
            for row in rows:
                d = dict(row)
                try:
                    d["data"] = json.loads(d["data"]) if d.get("data") else {}
                except (json.JSONDecodeError, TypeError):
                    d["data"] = {"_raw": str(d.get("data", ""))}
                result.append(d)
            return result
        elif table == "sessions":
            rows = conn.execute("SELECT * FROM sessions ORDER BY started_at DESC").fetchall()
            result = []
            for row in rows:
                d = dict(row)
                try:
                    d["metadata"] = json.loads(d["metadata"]) if d.get("metadata") else {}
                except (json.JSONDecodeError, TypeError):
                    d["metadata"] = {}
                result.append(d)
            return result
        elif table == "alerts":
            rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
            result = []
            for row in rows:
                d = dict(row)
                try:
                    d["event_ids"] = json.loads(d["event_ids"]) if d.get("event_ids") else []
                except (json.JSONDecodeError, TypeError):
                    d["event_ids"] = []
                try:
                    d["data"] = json.loads(d["data"]) if d.get("data") else {}
                except (json.JSONDecodeError, TypeError):
                    d["data"] = {}
                d["acknowledged"] = bool(d["acknowledged"])
                result.append(d)
            return result
        elif table == "attackers":
            return self._get_attackers(limit=100000, offset=0)["attackers"]
        return []

    async def export_all(self, table: str = "events") -> list[dict]:
        return await self._loop.run_in_executor(self._executor, self._export_all, table)

    def _reset(self):
        conn = self._get_conn()
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM sessions")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM geo_cache")
        conn.commit()
        conn.execute("VACUUM")

    async def reset_database(self):
        """Wipe all data from events, sessions, alerts, and geo_cache."""
        await self._loop.run_in_executor(self._executor, self._reset)
        logger.info("Database reset — all data cleared")

    async def close(self):
        self._closed = True
        if self._conn:
            self._conn.close()
            self._conn = None
        self._executor.shutdown(wait=False)
