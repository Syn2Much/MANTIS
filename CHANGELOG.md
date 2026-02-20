# Changelog

All notable changes to MANTIS are documented in this file.

## [2.0.0] - 2026-02-20

### Added
- **11 honeypot services**: SSH, HTTP, FTP, SMB, MySQL, Telnet, SMTP, MongoDB, VNC, Redis, ADB with full wire-protocol emulation
- **Real-time dashboard** with WebSocket live feed, filterable event log, session tracking, and alert management
- **Attack origin map** with IP geolocation via ip-api.com
- **IP blocking / firewall** — click any IP in the dashboard to block via iptables; dedicated Firewall tab for managing blocked IPs
- **Dashboard authentication** — `--auth-token` flag protects the dashboard with token-based auth (cookie, Bearer header, WebSocket query param) and a styled login page
- **Automated alerts** with severity levels (Critical / High / Medium) for reconnaissance, credential harvesting, SQL injection, and shell commands
- **Profile system** — YAML configs for minimal, database-trap, and full deployments
- **SQLite storage** with full-text search, pagination, JSON export, and database reset
- **Endpoint test suite** (`test_endpoints.py`) — probes all 11 services and validates every dashboard API endpoint with auth token support
- **CLI interface** with per-service port overrides, service selection, webhook alerts, verbose/quiet modes
- **GitHub badges** for Python, MIT License, AI Assisted, Honeypot, asyncio, and Linux
