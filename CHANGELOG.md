# Changelog

All notable changes to MANTIS are documented in this file.

## [2.2.0] - 2026-02-21

### Added
- **Payload Intel tab** — dedicated analytics dashboard for payload detections and IOC aggregation, visually distinct from other tabs with cyan accent theme
- **Gradient header banner** with shield icon, refresh and export controls
- **6-stat summary row** — Total Payloads, Critical, High, URLs Found, Hashes Found, Unique Attackers with color-coded accent borders
- **3-column chart row** — Pattern Categories donut chart, IOC Types donut chart, Activity Timeline bar chart (last 48h with hover tooltips)
- **Top Patterns ranked list** — numbered circles, severity badges, proportional gradient progress bars
- **Recent IOCs feed** — scrollable list with compact type badges and monospace values
- **Payload Alerts table** — Time, Severity, Service, Source IP, Patterns, IOC count; click opens existing alert detail modal
- **Cross-service payload detection engine** — 33 regex patterns across 7 categories (Downloaders, Reverse Shells, Miners, Persistence, Encoded Payloads, Privilege Escalation, Other)
- **IOC extraction** — automatic extraction of URLs, IPs, domains, MD5/SHA1/SHA256 hashes, and email addresses from event data
- **`PayloadIOCDetector` alert rule** — stateless rule scanning SSH, Telnet, HTTP, MySQL, FTP, Redis, and all other service events
- **`GET /api/payload-stats` endpoint** — aggregated payload statistics (severity counts, pattern frequency, IOC type totals, timeline buckets, top IPs, recent alerts)
- **`idx_alerts_rule_name` index** for efficient payload_ioc alert queries
- **Live WebSocket updates** — Payload Intel tab auto-refreshes on new payload_ioc alerts with toast notification
- **Alert data field** — `data` dict on Alert model for storing structured pattern/IOC metadata

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
- **Expanded Config page** — service-specific advanced settings (hostnames, prompts, credentials, databases, device models), banner preset dropdowns, collapsible sections per service
- **Global Settings panel** — toggle alerts, configure webhook URL/headers, change log level from the dashboard
- **Config persistence** — Save running config to YAML and export/download from the dashboard toolbar
- **New API endpoints** — `GET /api/config/full`, `PUT /api/config/global`, `POST /api/config/save`, `GET /api/config/export`
- **Mantis logo** — replaced stick-figure with detailed SVG mantis (compound eyes, raptorial forelegs, segmented abdomen, translucent wings)
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
