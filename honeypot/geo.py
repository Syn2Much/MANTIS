"""Geolocation client using ip-api.com with caching and rate limiting."""

import asyncio
import logging
import time
from datetime import datetime

import aiohttp

from .models import GeoInfo

logger = logging.getLogger("honeypot.geo")

# Private/reserved IP ranges that won't have geo data
_PRIVATE_PREFIXES = ("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                     "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                     "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                     "172.29.", "172.30.", "172.31.", "0.", "169.254.", "::1", "fc", "fd", "fe80")


class GeoLocator:
    """IP geolocation with caching, rate limiting (45 req/min), and dedup."""

    def __init__(self, database):
        self._db = database
        self._rate_tokens = 45
        self._rate_last_refill = time.monotonic()
        self._rate_lock = asyncio.Lock()
        self._pending: dict[str, asyncio.Future] = {}
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            )
        return self._session

    def _is_private(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)

    async def _rate_limit(self):
        async with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._rate_last_refill
            self._rate_tokens = min(45, self._rate_tokens + elapsed * (45 / 60))
            self._rate_last_refill = now
            if self._rate_tokens < 1:
                wait = (1 - self._rate_tokens) * (60 / 45)
                await asyncio.sleep(wait)
                self._rate_tokens = 1
            self._rate_tokens -= 1

    async def lookup(self, ip: str) -> GeoInfo:
        """Look up geolocation for an IP, using cache and dedup."""
        if self._is_private(ip):
            return GeoInfo(ip=ip, country="Private", city="Local Network")

        # Check cache
        cached = await self._db.get_geo(ip)
        if cached:
            return cached

        # Dedup: if already fetching this IP, wait for the existing request
        if ip in self._pending:
            return await self._pending[ip]

        future = asyncio.get_event_loop().create_future()
        self._pending[ip] = future

        try:
            geo = await self._fetch(ip)
            future.set_result(geo)
            return geo
        except Exception as e:
            geo = GeoInfo(ip=ip)
            if not future.done():
                future.set_result(geo)
            logger.warning("Geo lookup failed for %s: %s", ip, e)
            return geo
        finally:
            self._pending.pop(ip, None)

    async def _fetch(self, ip: str) -> GeoInfo:
        await self._rate_limit()
        session = await self._get_session()
        try:
            async with session.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,regionName,city,lat,lon,isp,org,as"}
            ) as resp:
                data = await resp.json()
        except Exception as e:
            logger.warning("Geo API error for %s: %s", ip, e)
            return GeoInfo(ip=ip)

        if data.get("status") != "success":
            return GeoInfo(ip=ip)

        geo = GeoInfo(
            ip=ip,
            country=data.get("country", "Unknown"),
            country_code=data.get("countryCode", ""),
            region=data.get("regionName", ""),
            city=data.get("city", ""),
            lat=data.get("lat", 0.0),
            lon=data.get("lon", 0.0),
            isp=data.get("isp", ""),
            org=data.get("org", ""),
            as_number=data.get("as", ""),
            cached_at=datetime.utcnow().isoformat(),
        )
        await self._db.save_geo(geo)
        return geo

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
