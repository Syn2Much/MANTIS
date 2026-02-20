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
    acknowledged INTEGER DEFAULT 0
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
            "INSERT INTO alerts (rule_name, severity, src_ip, service, message, event_ids, timestamp, acknowledged) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (alert.rule_name, alert.severity, alert.src_ip, alert.service,
             alert.message, json.dumps(alert.event_ids), alert.timestamp, 0),
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
            d["data"] = json.loads(d["data"])
            result.append(d)

        if paginated:
            total = conn.execute(count_query, count_params).fetchone()[0]
            return {"events": result, "total": total}

        return result

    async def get_events(self, **kwargs) -> list[dict] | dict:
        return await self._loop.run_in_executor(self._executor, lambda: self._get_events(**kwargs))

    def _get_sessions(self, limit: int = 100, offset: int = 0,
                      src_ip: str = None, service: str = None,
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
        query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["metadata"] = json.loads(d["metadata"])
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
            d["data"] = json.loads(d["data"])
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
            d["event_ids"] = json.loads(d["event_ids"])
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
            d["data"] = json.loads(d["data"])
            result.append(d)
        return result

    async def get_events_for_ip_window(self, ip: str, window_seconds: int) -> list[dict]:
        return await self._loop.run_in_executor(
            self._executor, self._get_events_for_ip_window, ip, window_seconds
        )

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
