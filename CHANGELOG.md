# Changelog

All notable changes to MANTIS are documented in this file.

## [2.1.0] - 2026-02-20

### Changed
- **Interactive CLI** — replaced 20+ argparse flags with a single-screen interactive setup combining service selection and port configuration
- **Combined service selector** — custom prompt_toolkit control: `space` toggles services, `→` edits port inline, `a` toggles all, `enter` confirms — all from one screen
- **Cyan/teal theme** — custom `[x]`/`[ ]` checkbox indicators, cyan pointer and highlights, dim instruction text
- **`--headless` flag** for non-interactive/scripted use (systemd, Docker, CI) — runs with all defaults or loads from YAML config
- Removed `--profile`, `--port-*`, `--services`, `--webhook`, and `--auth-token` flags (use interactive prompts or YAML config instead)

### Fixed
- Shutdown crash (`RuntimeError: cannot schedule new futures after shutdown`) when active client sessions existed during Ctrl-C

### Added
- `questionary>=2.0` dependency

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
