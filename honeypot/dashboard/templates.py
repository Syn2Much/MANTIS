"""Embedded HTML/CSS/JS dashboard with multi-tab layout, modals, and live config editing."""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MANTIS // Login</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='80' font-size='80'>🪲</text></svg>">
<style>
:root { --bg: #0c0c0c; --card: #161616; --border: #2a2a2a; --text: #e8e0d0; --dim: #8a7e6a; --accent: #f59e0b; --red: #ef4444; }
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'SF Mono','Fira Code','Consolas',monospace; background:var(--bg); color:var(--text); display:flex; align-items:center; justify-content:center; min-height:100vh; }
.login-box { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:40px; width:380px; text-align:center; }
.login-box h1 { color:var(--accent); font-size:24px; font-weight:800; letter-spacing:3px; margin-bottom:6px; }
.login-box .sub { color:var(--dim); font-size:11px; margin-bottom:28px; }
.login-box input { width:100%; background:var(--bg); border:1px solid var(--border); color:var(--text); padding:12px 16px; border-radius:6px; font-family:inherit; font-size:14px; margin-bottom:16px; text-align:center; }
.login-box input:focus { outline:none; border-color:var(--accent); }
.login-box button { width:100%; background:var(--accent); color:#0c0c0c; border:none; padding:12px; border-radius:6px; font-family:inherit; font-size:14px; font-weight:700; cursor:pointer; }
.login-box button:hover { background:#fbbf24; }
.error { color:var(--red); font-size:12px; margin-bottom:12px; display:none; }
</style>
</head>
<body>
<div class="login-box">
    <h1>MANTIS</h1>
    <div class="sub">// threat intelligence</div>
    <div class="error" id="err">Invalid token</div>
    <input type="password" id="token" placeholder="Enter auth token" autofocus>
    <button onclick="doLogin()">Authenticate</button>
</div>
<script>
document.getElementById('token').addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
async function doLogin() {
    const token = document.getElementById('token').value;
    const err = document.getElementById('err');
    err.style.display = 'none';
    try {
        const r = await fetch('/api/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token }),
        });
        if (r.ok) {
            window.location.href = '/';
        } else {
            err.style.display = 'block';
        }
    } catch(e) { err.textContent = 'Connection failed'; err.style.display = 'block'; }
}
</script>
</body>
</html>"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MANTIS // Threat Intelligence</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='80' font-size='80'>🪲</text></svg>">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<style>
:root {
    --bg-primary: #0c0c0c;
    --bg-secondary: #121212;
    --bg-card: #161616;
    --border: #2a2a2a;
    --text-primary: #e8e0d0;
    --text-secondary: #8a7e6a;
    --accent: #f59e0b;
    --red: #ef4444;
    --orange: #f59e0b;
    --green: #10b981;
    --purple: #8b5cf6;
    --cyan: #06b6d4;
    --pink: #ec4899;
    --mantis-glow: rgba(245, 158, 11, 0.12);
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; background: var(--bg-primary); color: var(--text-primary); overflow-x: hidden; }

/* Header */
.header { background: var(--bg-secondary); border-bottom: 1px solid #f59e0b; box-shadow: 0 1px 20px rgba(245,158,11,0.08); padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; }
.header h1 { font-size: 18px; font-weight: 600; display: flex; align-items: center; }
.header h1 span { color: var(--green); }
.status { display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--text-secondary); }
.status .dot { width: 8px; height: 8px; border-radius: 50%; background: #f59e0b; box-shadow: 0 0 6px rgba(245,158,11,0.6); animation: pulse 2s infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }

/* Tab Bar */
.tab-bar { display: flex; background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 0 16px; gap: 0; overflow-x: auto; }
.tab-btn { padding: 10px 20px; font-size: 13px; font-weight: 600; color: var(--text-secondary); background: none; border: none; border-bottom: 2px solid transparent; cursor: pointer; white-space: nowrap; font-family: inherit; transition: all 0.2s; }
.tab-btn:hover { color: var(--text-primary); background: rgba(245,158,11,0.05); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

/* Tab Content */
.tab-content { display: none; padding: 16px; }
.tab-content.active { display: block; }

/* Cards */
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.full-width { grid-column: 1 / -1; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; transition: border-color 0.3s; }
.card:hover { border-color: rgba(245,158,11,0.2); }
.card-header { padding: 12px 16px; border-bottom: 1px solid var(--border); font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); display: flex; justify-content: space-between; align-items: center; }
.card-body { padding: 16px; }

/* Stats */
.stats-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
.stat-box { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 16px; text-align: center; }
.stat-value { font-size: 28px; font-weight: 700; color: var(--accent); }
.stat-label { font-size: 11px; color: var(--text-secondary); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
.stat-box.critical .stat-value { color: var(--red); }
.stat-box.warning .stat-value { color: var(--orange); }
.stat-box.success .stat-value { color: var(--green); }

/* Overview mini map */
#map { height: 300px; background: var(--bg-secondary); border-radius: 4px; }
.leaflet-container { background: #0c0c0c !important; }

/* Full map tab */
.map-tab-layout { display: grid; grid-template-columns: 1fr 320px; gap: 16px; height: calc(100vh - 110px); }
#mapFull { height: 100%; min-height: 500px; background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border); }
.map-sidebar { display: flex; flex-direction: column; gap: 12px; overflow-y: auto; }
.map-legend { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.map-legend h3 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); margin-bottom: 10px; }
.legend-item { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-size: 12px; }
.legend-dot { width: 14px; height: 14px; border-radius: 50%; border: 2px solid rgba(255,255,255,0.3); flex-shrink: 0; }
.map-top-ips { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; flex: 1; overflow-y: auto; }
.map-top-ips h3 { font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); margin-bottom: 10px; }
.top-ip-item { display: flex; align-items: center; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 12px; }
.top-ip-item:last-child { border-bottom: none; }
.top-ip-bar { height: 4px; background: var(--accent); border-radius: 2px; margin-top: 4px; transition: width 0.4s ease; }
.map-stats-mini { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.map-stat { text-align: center; }
.map-stat .val { font-size: 20px; font-weight: 700; color: var(--accent); }
.map-stat .lbl { font-size: 10px; color: var(--text-secondary); text-transform: uppercase; }

/* Leaflet custom popup */
.leaflet-popup-content-wrapper { background: var(--bg-card) !important; color: var(--text-primary) !important; border: 1px solid var(--border) !important; border-radius: 8px !important; box-shadow: 0 8px 32px rgba(0,0,0,0.5) !important; }
.leaflet-popup-tip { background: var(--bg-card) !important; border: 1px solid var(--border) !important; }
.leaflet-popup-content { margin: 12px 16px !important; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace !important; font-size: 12px !important; line-height: 1.6 !important; }
.popup-ip { font-size: 14px; font-weight: 700; color: var(--accent); margin-bottom: 4px; }
.popup-loc { color: var(--text-secondary); margin-bottom: 6px; }
.popup-row { display: flex; justify-content: space-between; gap: 12px; padding: 2px 0; }
.popup-label { color: var(--text-secondary); }
.popup-svcs .badge { margin-right: 3px; }

/* Pulsing map marker animation */
@keyframes markerPulse {
    0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.6); }
    70% { box-shadow: 0 0 0 12px rgba(239, 68, 68, 0); }
    100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
}

/* Tables */
.event-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.event-table th { text-align: left; padding: 8px 12px; background: var(--bg-secondary); color: var(--text-secondary); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; font-size: 10px; position: sticky; top: 0; z-index: 1; }
.event-table td { padding: 6px 12px; border-bottom: 1px solid var(--border); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px; }
.event-table tr:hover td { background: rgba(245, 158, 11, 0.05); cursor: pointer; }
.events-scroll { max-height: 400px; overflow-y: auto; }

/* Badges */
.badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; text-transform: uppercase; display: inline-block; }
.badge-ssh { background: rgba(139, 92, 246, 0.2); color: var(--purple); }
.badge-http { background: rgba(59, 130, 246, 0.2); color: var(--accent); }
.badge-ftp { background: rgba(16, 185, 129, 0.2); color: var(--green); }
.badge-smb { background: rgba(245, 158, 11, 0.2); color: var(--orange); }
.badge-mysql { background: rgba(6, 182, 212, 0.2); color: var(--cyan); }
.badge-telnet { background: rgba(236, 72, 153, 0.2); color: var(--pink); }
.badge-smtp { background: rgba(234, 179, 8, 0.2); color: #eab308; }
.badge-mongodb { background: rgba(34, 197, 94, 0.2); color: #22c55e; }
.badge-vnc { background: rgba(168, 85, 247, 0.2); color: #a855f7; }
.badge-redis { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
.badge-adb { background: rgba(163, 230, 53, 0.2); color: #a3e635; }
.badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--red); }
.badge-high { background: rgba(245, 158, 11, 0.2); color: var(--orange); }
.badge-medium { background: rgba(59, 130, 246, 0.2); color: var(--accent); }
.badge-low { background: rgba(16, 185, 129, 0.2); color: var(--green); }
.badge-info { background: rgba(107, 114, 128, 0.2); color: #9ca3af; }
.badge-threat { background: rgba(239, 68, 68, 0.3); color: var(--red); font-size: 9px; margin-left: 4px; }

/* Alerts */
.alert-item { padding: 10px 14px; border-bottom: 1px solid var(--border); display: flex; gap: 10px; align-items: flex-start; }
.alert-item:hover { background: rgba(239, 68, 68, 0.03); cursor: pointer; }
.alert-msg { font-size: 12px; flex: 1; }
.alert-time { font-size: 10px; color: var(--text-secondary); white-space: nowrap; }
.alert-ack { background: none; border: 1px solid var(--border); color: var(--text-secondary); padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 10px; font-family: inherit; }
.alert-ack:hover { border-color: var(--green); color: var(--green); }
.alerts-scroll { max-height: 350px; overflow-y: auto; }

/* Charts */
.chart-container { display: flex; gap: 16px; align-items: center; }
.chart-canvas { flex-shrink: 0; }
.chart-legend { font-size: 12px; }
.chart-legend-item { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
.chart-legend-color { width: 12px; height: 12px; border-radius: 2px; }

/* Animation */
.new-event { animation: flashNew 1s ease-out; }
@keyframes flashNew { 0% { background: rgba(245, 158, 11, 0.12); } 100% { background: transparent; } }

/* Filter Row */
.filter-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px; padding: 12px; background: var(--bg-secondary); border-radius: 6px; border: 1px solid var(--border); }
.filter-group { display: flex; align-items: center; gap: 6px; }
.filter-group label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }
.filter-group select, .filter-group input { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-primary); padding: 5px 10px; border-radius: 4px; font-size: 12px; font-family: inherit; }
.filter-group select:focus, .filter-group input:focus { outline: none; border-color: var(--accent); }
.filter-btn { background: var(--accent); color: #0c0c0c; border: none; padding: 5px 14px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600; font-family: inherit; }
.filter-btn:hover { background: #fbbf24; }
.filter-btn.secondary { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-secondary); }
.filter-btn.secondary:hover { border-color: var(--accent); color: var(--text-primary); }
.filter-btn.danger { background: var(--red); }
.filter-btn.danger:hover { background: #dc2626; }

/* Pagination */
.pagination { display: flex; align-items: center; justify-content: center; gap: 12px; padding: 12px 0; font-size: 12px; color: var(--text-secondary); }
.pagination button { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-primary); padding: 5px 12px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 12px; }
.pagination button:disabled { opacity: 0.4; cursor: default; }
.pagination button:not(:disabled):hover { border-color: var(--accent); }

/* Config Cards */
.config-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 16px; }
.config-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
.config-card h3 { font-size: 14px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
.config-field { margin-bottom: 10px; }
.config-field label { display: block; font-size: 11px; color: var(--text-secondary); margin-bottom: 4px; text-transform: uppercase; }
.config-field input[type="text"], .config-field input[type="number"] { width: 100%; background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text-primary); padding: 8px 12px; border-radius: 4px; font-family: inherit; font-size: 13px; }
.config-field input:focus { outline: none; border-color: var(--accent); }
.config-toggle { display: flex; align-items: center; gap: 8px; cursor: pointer; }
.toggle-switch { position: relative; width: 40px; height: 22px; background: var(--border); border-radius: 11px; transition: background 0.2s; cursor: pointer; }
.toggle-switch.on { background: var(--accent); }
.toggle-switch::after { content: ''; position: absolute; width: 18px; height: 18px; background: white; border-radius: 50%; top: 2px; left: 2px; transition: left 0.2s; }
.toggle-switch.on::after { left: 20px; }
.config-apply { background: var(--accent); color: #0c0c0c; border: none; padding: 8px 20px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600; font-family: inherit; margin-top: 8px; }
.config-apply:hover { background: #fbbf24; }

/* Modal */
.modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center; }
.modal-overlay.active { display: flex; }
.modal { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; width: 90%; max-width: 700px; max-height: 80vh; overflow-y: auto; }
.modal-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; background: var(--bg-card); z-index: 1; }
.modal-header h2 { font-size: 16px; }
.modal-close { background: none; border: none; color: var(--text-secondary); font-size: 20px; cursor: pointer; padding: 4px 8px; }
.modal-close:hover { color: var(--text-primary); }
.modal-body { padding: 20px; }

/* JSON viewer */
.json-viewer { background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; padding: 16px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 400px; overflow-y: auto; }

/* Toast */
.toast-container { position: fixed; top: 16px; right: 16px; z-index: 2000; display: flex; flex-direction: column; gap: 8px; }
.toast { padding: 12px 20px; border-radius: 6px; font-size: 13px; animation: toastIn 0.3s ease-out, toastOut 0.3s ease-in 4.7s forwards; pointer-events: none; max-width: 400px; }
.toast.success { background: rgba(245, 158, 11, 0.95); color: #0c0c0c; font-weight: 600; }
.toast.error { background: rgba(239, 68, 68, 0.9); color: white; }
@keyframes toastIn { from { opacity: 0; transform: translateX(50px); } to { opacity: 1; transform: translateX(0); } }
@keyframes toastOut { from { opacity: 1; } to { opacity: 0; } }

/* Checkbox group for filters */
.checkbox-group { display: flex; flex-wrap: wrap; gap: 6px; }
.checkbox-group label { display: flex; align-items: center; gap: 4px; font-size: 11px; cursor: pointer; padding: 2px 6px; border-radius: 3px; background: var(--bg-card); border: 1px solid var(--border); }
.checkbox-group label:hover { border-color: var(--accent); }
.checkbox-group input[type="checkbox"] { width: 12px; height: 12px; }

/* Session timeline */
.timeline { border-left: 2px solid var(--border); margin-left: 8px; padding-left: 16px; }
.timeline-item { position: relative; padding-bottom: 14px; }
.timeline-item::before { content: ''; position: absolute; left: -21px; top: 4px; width: 10px; height: 10px; border-radius: 50%; background: var(--accent); border: 2px solid var(--bg-card); }
.timeline-item .tl-time { font-size: 10px; color: var(--text-secondary); }
.timeline-item .tl-type { font-size: 11px; font-weight: 600; margin: 2px 0; }
.timeline-item .tl-detail { font-size: 12px; color: var(--text-secondary); }

/* Bulk actions */
.bulk-bar { display: flex; gap: 8px; align-items: center; padding: 8px 0; }

/* Confirm modal specific */
.confirm-body { text-align: center; padding: 20px 0; }
.confirm-body p { font-size: 14px; margin-bottom: 8px; }
.confirm-body .warn { color: var(--red); font-size: 12px; }
.confirm-btns { display: flex; gap: 12px; justify-content: center; margin-top: 20px; }
.confirm-btns button { padding: 10px 24px; border-radius: 6px; border: none; font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; }
.btn-cancel { background: var(--bg-secondary); color: var(--text-primary); border: 1px solid var(--border) !important; }
.btn-cancel:hover { border-color: var(--accent) !important; }
.btn-danger { background: var(--red); color: white; }
.btn-danger:hover { background: #dc2626; }

/* Active honeypot blobs */
.hp-blob { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 20px; font-size: 10px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; border: 1px solid var(--border); background: var(--bg-secondary); }
.hp-blob .hp-dot { width: 6px; height: 6px; border-radius: 50%; animation: pulse 2s infinite; }
.hp-blob.active { border-color: rgba(245,158,11,0.3); }
.hp-blob.active .hp-dot { background: #f59e0b; box-shadow: 0 0 4px rgba(245,158,11,0.5); }
.hp-blob.inactive { opacity: 0.35; }
.hp-blob.inactive .hp-dot { background: #555; }
.hp-blob .hp-port { color: var(--text-secondary); font-weight: 400; }

/* Clickable IPs */
.ip-addr { color: var(--accent); cursor: pointer; position: relative; border-bottom: 1px dashed rgba(245,158,11,0.3); }
.ip-addr:hover { color: #fbbf24; border-bottom-color: #fbbf24; }
.ip-addr.blocked { color: var(--red); text-decoration: line-through; border-bottom-color: rgba(239,68,68,0.3); }

/* IP Popover */
.ip-popover { position: fixed; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; box-shadow: 0 8px 32px rgba(0,0,0,0.6); z-index: 1500; min-width: 180px; overflow: hidden; animation: popIn 0.15s ease-out; }
@keyframes popIn { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
.ip-popover-header { padding: 10px 14px; border-bottom: 1px solid var(--border); font-size: 13px; font-weight: 700; color: var(--accent); }
.ip-popover-item { padding: 8px 14px; font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 8px; color: var(--text-primary); }
.ip-popover-item:hover { background: rgba(245,158,11,0.08); }
.ip-popover-item.danger { color: var(--red); }
.ip-popover-item.danger:hover { background: rgba(239,68,68,0.08); }
.ip-popover-item.success { color: var(--green); }
.ip-popover-item.success:hover { background: rgba(16,185,129,0.08); }

/* Firewall tab */
.fw-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.fw-blocked-list { display: flex; flex-direction: column; gap: 4px; }
.fw-ip-row { display: flex; align-items: center; justify-content: space-between; padding: 8px 14px; background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; font-size: 13px; }
.fw-ip-row .ip { color: var(--red); font-weight: 600; }
.fw-unblock-btn { background: none; border: 1px solid var(--border); color: var(--green); padding: 3px 10px; border-radius: 4px; cursor: pointer; font-size: 11px; font-family: inherit; }
.fw-unblock-btn:hover { border-color: var(--green); background: rgba(16,185,129,0.1); }
.fw-manual-block { display: flex; gap: 8px; margin-bottom: 16px; }
.fw-manual-block input { flex: 1; background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text-primary); padding: 8px 12px; border-radius: 4px; font-family: inherit; font-size: 13px; }
.fw-manual-block input:focus { outline: none; border-color: var(--accent); }
</style>
</head>
<body>

<!-- Header -->
<div class="header">
    <h1>
        <svg width="24" height="24" viewBox="0 0 100 100" style="vertical-align:middle;margin-right:8px">
            <line x1="50" y1="10" x2="50" y2="30" stroke="#f59e0b" stroke-width="3"/>
            <line x1="50" y1="30" x2="30" y2="15" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round"/>
            <line x1="50" y1="30" x2="70" y2="15" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round"/>
            <ellipse cx="50" cy="40" rx="12" ry="10" fill="none" stroke="#f59e0b" stroke-width="2.5"/>
            <circle cx="45" cy="38" r="2" fill="#f59e0b"/>
            <circle cx="55" cy="38" r="2" fill="#f59e0b"/>
            <line x1="50" y1="50" x2="50" y2="80" stroke="#f59e0b" stroke-width="3"/>
            <line x1="50" y1="55" x2="25" y2="40" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
            <line x1="50" y1="55" x2="75" y2="40" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
            <line x1="50" y1="65" x2="20" y2="55" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
            <line x1="50" y1="65" x2="80" y2="55" stroke="#f59e0b" stroke-width="2" stroke-linecap="round"/>
            <line x1="50" y1="80" x2="35" y2="95" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round"/>
            <line x1="50" y1="80" x2="65" y2="95" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round"/>
        </svg>
        <span style="color:#f59e0b;font-weight:800;letter-spacing:3px">MANTIS</span>
        <span style="color:#8a7e6a;font-weight:400;font-size:12px;margin-left:8px">// threat intelligence</span>
    </h1>
    <div class="status">
        <span style="color:#8a7e6a;font-size:11px;margin-right:12px">WATCH. WAIT. CAPTURE.</span>
        <div class="dot" id="wsDot"></div>
        <span id="wsStatus">Connecting...</span>
    </div>
</div>

<!-- Tab Bar -->
<div class="tab-bar">
    <button class="tab-btn active" onclick="switchTab('overview')">Overview</button>
    <button class="tab-btn" onclick="switchTab('map')">Map</button>
    <button class="tab-btn" onclick="switchTab('events')">Events</button>
    <button class="tab-btn" onclick="switchTab('sessions')">Sessions</button>
    <button class="tab-btn" onclick="switchTab('alerts')">Alerts</button>
    <button class="tab-btn" onclick="switchTab('database')">Database</button>
    <button class="tab-btn" onclick="switchTab('firewall')">Firewall</button>
    <button class="tab-btn" onclick="switchTab('config')">Config</button>
</div>

<!-- ═══════════════════ OVERVIEW TAB ═══════════════════ -->
<div id="tab-overview" class="tab-content active">
<div class="grid">
    <div class="card full-width">
        <div class="card-body">
            <div class="stats-row">
                <div class="stat-box"><div class="stat-value" id="statEvents">0</div><div class="stat-label">Events</div></div>
                <div class="stat-box"><div class="stat-value" id="statSessions">0</div><div class="stat-label">Sessions</div></div>
                <div class="stat-box success"><div class="stat-value" id="statIPs">0</div><div class="stat-label">Unique IPs</div></div>
                <div class="stat-box critical"><div class="stat-value" id="statAlerts">0</div><div class="stat-label">Alerts</div></div>
                <div class="stat-box warning"><div class="stat-value" id="statServices">0</div><div class="stat-label">Services</div></div>
            </div>
        </div>
    </div>
    <div class="card full-width">
        <div class="card-body" style="padding:10px 16px">
            <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
                <span style="font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:1px;color:var(--text-secondary);margin-right:4px">Active Honeypots</span>
                <div id="activeHoneypots" style="display:flex;gap:6px;flex-wrap:wrap"></div>
            </div>
        </div>
    </div>
    <div class="card full-width">
        <div class="card-header">Attack Origin Map <span style="font-size:11px;font-weight:400;color:var(--text-secondary);text-transform:none">Open the Map tab for full view</span></div>
        <div class="card-body"><div id="map"></div></div>
    </div>
    <div class="card">
        <div class="card-header">Live Events <span id="eventCount" style="color:var(--accent)"></span></div>
        <div class="events-scroll">
            <table class="event-table">
                <thead><tr><th>Time</th><th>Service</th><th>Source IP</th><th>Type</th><th>Details</th></tr></thead>
                <tbody id="eventBody"></tbody>
            </table>
        </div>
    </div>
    <div class="card">
        <div class="card-header">Alerts <span id="alertCount" style="color:var(--red)"></span></div>
        <div class="alerts-scroll" id="alertsPanel"></div>
    </div>
    <div class="card">
        <div class="card-header">Events by Service</div>
        <div class="card-body">
            <div class="chart-container">
                <canvas id="serviceChart" width="160" height="160" class="chart-canvas"></canvas>
                <div class="chart-legend" id="serviceLegend"></div>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-header">Events by Type</div>
        <div class="card-body">
            <div class="chart-container">
                <canvas id="typeChart" width="160" height="160" class="chart-canvas"></canvas>
                <div class="chart-legend" id="typeLegend"></div>
            </div>
        </div>
    </div>
</div>
</div>

<!-- ═══════════════════ MAP TAB ═══════════════════ -->
<div id="tab-map" class="tab-content">
<div class="map-tab-layout">
    <div id="mapFull"></div>
    <div class="map-sidebar">
        <div class="map-stats-mini">
            <div class="map-stat"><div class="val" id="mapStatIPs">0</div><div class="lbl">IPs Located</div></div>
            <div class="map-stat"><div class="val" id="mapStatCountries">0</div><div class="lbl">Countries</div></div>
            <div class="map-stat"><div class="val" id="mapStatSessions">0</div><div class="lbl">Sessions</div></div>
            <div class="map-stat"><div class="val" id="mapStatEvents">0</div><div class="lbl">Events</div></div>
        </div>
        <div class="map-legend">
            <h3>Service Colors</h3>
            <div class="legend-item"><div class="legend-dot" style="background:#8b5cf6"></div> SSH</div>
            <div class="legend-item"><div class="legend-dot" style="background:#3b82f6"></div> HTTP</div>
            <div class="legend-item"><div class="legend-dot" style="background:#10b981"></div> FTP</div>
            <div class="legend-item"><div class="legend-dot" style="background:#f59e0b"></div> SMB</div>
            <div class="legend-item"><div class="legend-dot" style="background:#06b6d4"></div> MySQL</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ec4899"></div> Telnet</div>
            <div class="legend-item"><div class="legend-dot" style="background:#eab308"></div> SMTP</div>
            <div class="legend-item"><div class="legend-dot" style="background:#22c55e"></div> MongoDB</div>
            <div class="legend-item"><div class="legend-dot" style="background:#a855f7"></div> VNC</div>
            <div class="legend-item"><div class="legend-dot" style="background:#ef4444"></div> Redis</div>
            <div class="legend-item"><div class="legend-dot" style="background:#a3e635"></div> ADB</div>
            <div class="legend-item" style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border)"><div class="legend-dot" style="background:#ef4444;box-shadow:0 0 0 3px rgba(239,68,68,0.3)"></div> Multiple services</div>
        </div>
        <div class="map-top-ips">
            <h3>Top Attacker IPs</h3>
            <div id="mapTopIPs"><div style="color:var(--text-secondary);font-size:12px">No data yet</div></div>
        </div>
    </div>
</div>
</div>

<!-- ═══════════════════ EVENTS TAB ═══════════════════ -->
<div id="tab-events" class="tab-content">
<div class="filter-row">
    <div class="filter-group">
        <label>Service</label>
        <select id="evtFilterService"><option value="">All</option><option>ssh</option><option>http</option><option>ftp</option><option>smb</option><option>mysql</option><option>telnet</option><option>smtp</option><option>mongodb</option><option>vnc</option><option>redis</option><option>adb</option></select>
    </div>
    <div class="filter-group">
        <label>Type</label>
        <select id="evtFilterType"><option value="">All</option><option>connection</option><option>auth_attempt</option><option>command</option><option>request</option><option>query</option><option>file_transfer</option><option>ntlm_auth</option><option>disconnect</option></select>
    </div>
    <div class="filter-group">
        <label>IP</label>
        <input type="text" id="evtFilterIP" placeholder="e.g. 192.168.1.1" list="ipList" style="width:140px">
    </div>
    <button class="filter-btn" onclick="loadEventsTab()">Apply</button>
</div>
<div class="card">
    <div class="events-scroll" style="max-height:600px">
        <table class="event-table">
            <thead><tr><th>ID</th><th>Time</th><th>Service</th><th>Source IP</th><th>Type</th><th>Details</th></tr></thead>
            <tbody id="evtTabBody"></tbody>
        </table>
    </div>
</div>
<div class="pagination">
    <button onclick="evtPage(-1)" id="evtPrev" disabled>Prev</button>
    <span id="evtPageInfo">Page 1</span>
    <button onclick="evtPage(1)" id="evtNext">Next</button>
</div>
</div>

<!-- ═══════════════════ SESSIONS TAB ═══════════════════ -->
<div id="tab-sessions" class="tab-content">
<div class="filter-row">
    <div class="filter-group">
        <label>IP</label>
        <input type="text" id="sessFilterIP" placeholder="Filter by IP" list="ipList" style="width:140px">
    </div>
    <div class="filter-group">
        <label>Service</label>
        <select id="sessFilterService"><option value="">All</option><option>ssh</option><option>http</option><option>ftp</option><option>smb</option><option>mysql</option><option>telnet</option><option>smtp</option><option>mongodb</option><option>vnc</option><option>redis</option><option>adb</option></select>
    </div>
    <button class="filter-btn" onclick="loadSessionsTab()">Apply</button>
</div>
<div class="card">
    <div class="events-scroll" style="max-height:600px">
        <table class="event-table">
            <thead><tr><th>Session ID</th><th>Service</th><th>Source IP</th><th>Port</th><th>Started</th><th>Ended</th></tr></thead>
            <tbody id="sessTabBody"></tbody>
        </table>
    </div>
</div>
<div class="pagination">
    <button onclick="sessPage(-1)" id="sessPrev" disabled>Prev</button>
    <span id="sessPageInfo">Page 1</span>
    <button onclick="sessPage(1)" id="sessNext">Next</button>
</div>
</div>

<!-- ═══════════════════ ALERTS TAB ═══════════════════ -->
<div id="tab-alerts" class="tab-content">
<div class="filter-row">
    <div class="filter-group">
        <label>Severity</label>
        <select id="alertFilterSev"><option value="">All</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select>
    </div>
    <div class="filter-group">
        <label>Status</label>
        <select id="alertFilterAck"><option value="">All</option><option value="unacked">Unacknowledged</option><option value="acked">Acknowledged</option></select>
    </div>
    <button class="filter-btn" onclick="loadAlertsTab()">Apply</button>
    <button class="filter-btn secondary" onclick="bulkAckAlerts()">Ack All Visible</button>
</div>
<div class="card">
    <div class="alerts-scroll" style="max-height:600px" id="alertsTabPanel"></div>
</div>
<div class="pagination">
    <button onclick="alertPage(-1)" id="alertPrev" disabled>Prev</button>
    <span id="alertPageInfo">Page 1</span>
    <button onclick="alertPage(1)" id="alertNext">Next</button>
</div>
</div>

<!-- ═══════════════════ DATABASE TAB ═══════════════════ -->
<div id="tab-database" class="tab-content">
<div class="filter-row" style="flex-wrap:wrap">
    <div class="filter-group">
        <label>IP</label>
        <input type="text" id="dbFilterIP" placeholder="Filter by IP" list="ipList" style="width:140px">
    </div>
    <div class="filter-group">
        <label>Services</label>
        <div class="checkbox-group" id="dbSvcCheckboxes">
            <label><input type="checkbox" value="ssh" checked> SSH</label>
            <label><input type="checkbox" value="http" checked> HTTP</label>
            <label><input type="checkbox" value="ftp" checked> FTP</label>
            <label><input type="checkbox" value="smb" checked> SMB</label>
            <label><input type="checkbox" value="mysql" checked> MySQL</label>
            <label><input type="checkbox" value="telnet" checked> Telnet</label>
            <label><input type="checkbox" value="smtp" checked> SMTP</label>
            <label><input type="checkbox" value="mongodb" checked> MongoDB</label>
            <label><input type="checkbox" value="vnc" checked> VNC</label>
            <label><input type="checkbox" value="redis" checked> Redis</label>
            <label><input type="checkbox" value="adb" checked> ADB</label>
        </div>
    </div>
    <div class="filter-group">
        <label>Types</label>
        <div class="checkbox-group" id="dbTypeCheckboxes">
            <label><input type="checkbox" value="connection" checked> connection</label>
            <label><input type="checkbox" value="auth_attempt" checked> auth</label>
            <label><input type="checkbox" value="command" checked> command</label>
            <label><input type="checkbox" value="request" checked> request</label>
            <label><input type="checkbox" value="query" checked> query</label>
            <label><input type="checkbox" value="file_transfer" checked> file_transfer</label>
            <label><input type="checkbox" value="disconnect" checked> disconnect</label>
        </div>
    </div>
    <div class="filter-group">
        <label>From</label>
        <input type="datetime-local" id="dbFilterFrom" style="width:180px">
    </div>
    <div class="filter-group">
        <label>To</label>
        <input type="datetime-local" id="dbFilterTo" style="width:180px">
    </div>
    <div class="filter-group">
        <label>Search</label>
        <input type="text" id="dbFilterSearch" placeholder="Text search in data" style="width:200px">
    </div>
    <button class="filter-btn" onclick="loadDatabaseTab()">Search</button>
    <button class="filter-btn secondary" onclick="exportDBResults()">Export JSON</button>
    <button class="filter-btn danger" onclick="confirmResetDB()">Reset Database</button>
</div>
<div class="card">
    <div class="card-header"><span id="dbResultCount">0 results</span></div>
    <div class="events-scroll" style="max-height:600px">
        <table class="event-table" id="dbTable">
            <thead><tr>
                <th style="cursor:pointer" onclick="dbSort('id')">ID</th>
                <th style="cursor:pointer" onclick="dbSort('timestamp')">Time</th>
                <th style="cursor:pointer" onclick="dbSort('service')">Service</th>
                <th style="cursor:pointer" onclick="dbSort('src_ip')">Source IP</th>
                <th style="cursor:pointer" onclick="dbSort('event_type')">Type</th>
                <th>Details</th>
            </tr></thead>
            <tbody id="dbTabBody"></tbody>
        </table>
    </div>
</div>
<div class="pagination">
    <button onclick="dbPage(-1)" id="dbPrev" disabled>Prev</button>
    <span id="dbPageInfo">Page 1</span>
    <button onclick="dbPage(1)" id="dbNext">Next</button>
</div>
</div>

<!-- ═══════════════════ FIREWALL TAB ═══════════════════ -->
<div id="tab-firewall" class="tab-content">
<div class="fw-grid">
    <div class="card">
        <div class="card-header">Block IP Address</div>
        <div class="card-body">
            <div class="fw-manual-block">
                <input type="text" id="fwBlockInput" placeholder="Enter IP address to block" list="ipList">
                <button class="filter-btn danger" onclick="manualBlockIP()">Block</button>
            </div>
            <div style="font-size:11px;color:var(--text-secondary)">
                <p style="margin-bottom:6px">Adds an <code style="background:var(--bg-secondary);padding:2px 6px;border-radius:3px">iptables -A INPUT -s &lt;IP&gt; -j DROP</code> rule to block all incoming traffic from the specified IP.</p>
                <p>You can also click on any IP address in the Events, Sessions, or Map tabs to block it directly.</p>
                <p style="margin-top:6px" id="fwIptablesStatus"></p>
            </div>
        </div>
    </div>
    <div class="card">
        <div class="card-header">Blocked IPs <span id="fwBlockedCount" style="color:var(--red)"></span></div>
        <div class="card-body">
            <div class="fw-blocked-list" id="fwBlockedList">
                <div style="color:var(--text-secondary);font-size:12px">No IPs blocked</div>
            </div>
        </div>
    </div>
</div>
</div>

<!-- ═══════════════════ CONFIG TAB ═══════════════════ -->
<div id="tab-config" class="tab-content">
<div class="config-grid" id="configGrid"></div>
</div>

<!-- ═══════════════════ MODAL ═══════════════════ -->
<div class="modal-overlay" id="modalOverlay" onclick="if(event.target===this)closeModal()">
    <div class="modal">
        <div class="modal-header">
            <h2 id="modalTitle">Detail</h2>
            <button class="modal-close" onclick="closeModal()">&times;</button>
        </div>
        <div class="modal-body" id="modalBody"></div>
    </div>
</div>

<!-- Toast Container -->
<div class="toast-container" id="toastContainer"></div>

<!-- IP Popover (click on IP) -->
<div class="ip-popover" id="ipPopover" style="display:none"></div>

<!-- IP datalist for autocomplete -->
<datalist id="ipList"></datalist>

<script>
// ── Constants ────────────────────────────────────────────────────────────────
const serviceColors = { ssh: '#8b5cf6', http: '#3b82f6', ftp: '#10b981', smb: '#f59e0b', mysql: '#06b6d4', telnet: '#ec4899', smtp: '#eab308', mongodb: '#22c55e', vnc: '#a855f7', redis: '#ef4444', adb: '#a3e635' };
const typeColors = { connection: '#3b82f6', auth_attempt: '#f59e0b', command: '#ef4444', request: '#8b5cf6', query: '#06b6d4', file_transfer: '#10b981', ntlm_auth: '#f97316', disconnect: '#6b7280', error: '#dc2626' };

// ── Helpers ──────────────────────────────────────────────────────────────────
function formatTime(ts) { if (!ts) return ''; const d = new Date(ts + (ts.includes('Z')?'':'Z')); return d.toLocaleTimeString(); }
function formatDateTime(ts) { if (!ts) return ''; const d = new Date(ts + (ts.includes('Z')?'':'Z')); return d.toLocaleString(); }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// ── Blocked IPs tracking ─────────────────────────────────────────────────────
let blockedIPs = new Set();

function ipHTML(ip) {
    if (!ip) return '';
    const blocked = blockedIPs.has(ip);
    return `<span class="ip-addr${blocked ? ' blocked' : ''}" onclick="event.stopPropagation();showIPPopover(event,'${esc(ip)}')">${esc(ip)}</span>`;
}

function summarize(data) {
    if (!data) return '';
    if (data.username) { let s = data.username; if (data.password) s += ':' + data.password; return s; }
    if (data.command) return data.command;
    if (data.query) return data.query.substring(0, 80);
    if (data.method) return data.method + ' ' + (data.path || '');
    if (data.message) return data.message;
    return JSON.stringify(data).substring(0, 80);
}

function threatBadges(data) {
    if (!data || !data.threats || !data.threats.length) return '';
    return data.threats.map(t => `<span class="badge badge-threat">${esc(t.name)}</span>`).join('');
}

// ── Toast ────────────────────────────────────────────────────────────────────
function showToast(msg, type='success') {
    const c = document.getElementById('toastContainer');
    const t = document.createElement('div');
    t.className = 'toast ' + type;
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => t.remove(), 5000);
}

// ── Modal ────────────────────────────────────────────────────────────────────
function openModal(title, html) {
    document.getElementById('modalTitle').textContent = title;
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalOverlay').classList.add('active');
}
function closeModal() { document.getElementById('modalOverlay').classList.remove('active'); }
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

// ── Tab switching ────────────────────────────────────────────────────────────
function switchTab(name) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + name).classList.add('active');
    document.querySelectorAll('.tab-btn').forEach(el => { if (el.textContent.toLowerCase().replace(/\s/g,'') === name) el.classList.add('active'); });
    if (name === 'events') loadEventsTab();
    else if (name === 'sessions') loadSessionsTab();
    else if (name === 'alerts') loadAlertsTab();
    else if (name === 'database') loadDatabaseTab();
    else if (name === 'firewall') loadFirewallTab();
    else if (name === 'config') loadConfigTab();
    else if (name === 'overview') { refreshStats(); refreshOverviewMap(); }
    else if (name === 'map') { initFullMap(); refreshFullMap(); }
}

// ═══════════════════════════════════════════════════════════════════════════
// MAP — Overview (small) + Full tab (large)
// ═══════════════════════════════════════════════════════════════════════════

// Overview mini map
let overviewMap, overviewMarkers = {};
function initOverviewMap() {
    overviewMap = L.map('map', { center: [20, 0], zoom: 2, zoomControl: true, attributionControl: false });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(overviewMap);
}
initOverviewMap();

function addOverviewMarker(d) {
    if (!d.lat && !d.lon) return;
    const key = d.ip;
    if (overviewMarkers[key]) overviewMap.removeLayer(overviewMarkers[key]);
    const color = pickMarkerColor(d);
    const radius = Math.min(5 + (d.event_count || 1) * 0.5, 20);
    const m = L.circleMarker([d.lat, d.lon], { radius, color, fillColor: color, fillOpacity: 0.6, weight: 1 }).addTo(overviewMap);
    m.bindPopup(buildPopupHTML(d));
    overviewMarkers[key] = m;
}

async function refreshOverviewMap() {
    try {
        const r = await fetch('/api/map');
        const data = await r.json();
        data.forEach(addOverviewMarker);
    } catch(e) {}
}

// Full map tab
let fullMap = null, fullMarkers = {}, fullMapData = [];
function initFullMap() {
    if (fullMap) return; // already initialized
    fullMap = L.map('mapFull', { center: [20, 0], zoom: 2, zoomControl: true, attributionControl: false });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(fullMap);
    // Fix Leaflet sizing issue when map is in a hidden tab
    setTimeout(() => fullMap.invalidateSize(), 200);
}

function pickMarkerColor(d) {
    if (!d.services) return '#ef4444';
    const svcs = d.services.split(',');
    if (svcs.length > 1) return '#ef4444'; // multi-service = red
    return serviceColors[svcs[0]] || '#ef4444';
}

function buildPopupHTML(d) {
    const svcs = (d.services || '').split(',').filter(Boolean);
    const svcBadges = svcs.map(s => `<span class="badge badge-${s}">${s}</span>`).join(' ');
    const ip = d.ip || '?';
    const isBlocked = blockedIPs.has(ip);
    const blockBtn = isBlocked
        ? `<button onclick="unblockIP('${ip}')" style="background:var(--green);color:#0c0c0c;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;font-family:inherit;width:100%">Unblock IP</button>`
        : `<button onclick="blockIP('${ip}')" style="background:var(--red);color:white;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:11px;font-weight:600;font-family:inherit;width:100%">Block IP</button>`;
    return `<div class="popup-ip">${ip}${isBlocked ? ' <span style="color:var(--red);font-size:10px">BLOCKED</span>' : ''}</div>
        <div class="popup-loc">${[d.city, d.country].filter(Boolean).join(', ') || 'Unknown location'}</div>
        <div class="popup-row"><span class="popup-label">ISP</span><span>${d.isp || '?'}</span></div>
        <div class="popup-row"><span class="popup-label">Events</span><span style="color:var(--accent);font-weight:700">${d.event_count || 0}</span></div>
        <div class="popup-row"><span class="popup-label">Sessions</span><span>${d.session_count || 0}</span></div>
        <div class="popup-svcs" style="margin-top:6px">${svcBadges}</div>
        <div style="margin-top:8px">${blockBtn}</div>`;
}

async function refreshFullMap() {
    if (!fullMap) return;
    try {
        const r = await fetch('/api/map');
        fullMapData = await r.json();
    } catch(e) { return; }

    // Clear old markers
    Object.values(fullMarkers).forEach(m => fullMap.removeLayer(m));
    fullMarkers = {};

    let totalSessions = 0, totalEvents = 0;
    const countries = new Set();

    fullMapData.forEach(d => {
        if (!d.lat && !d.lon) return;
        const color = pickMarkerColor(d);
        const evtCount = d.event_count || 1;
        const radius = Math.min(6 + evtCount * 0.7, 28);

        const m = L.circleMarker([d.lat, d.lon], {
            radius, color, fillColor: color, fillOpacity: 0.55, weight: 2, opacity: 0.8
        }).addTo(fullMap);
        m.bindPopup(buildPopupHTML(d), { maxWidth: 280 });
        fullMarkers[d.ip] = m;

        totalSessions += d.session_count || 0;
        totalEvents += evtCount;
        if (d.country) countries.add(d.country);
    });

    // Auto-fit bounds if we have markers
    const coords = fullMapData.filter(d => d.lat || d.lon).map(d => [d.lat, d.lon]);
    if (coords.length > 0) {
        fullMap.fitBounds(coords, { padding: [40, 40], maxZoom: 6 });
    }

    // Update sidebar stats
    document.getElementById('mapStatIPs').textContent = fullMapData.length;
    document.getElementById('mapStatCountries').textContent = countries.size;
    document.getElementById('mapStatSessions').textContent = totalSessions;
    document.getElementById('mapStatEvents').textContent = totalEvents;

    // Top attacker IPs panel
    const sorted = [...fullMapData].sort((a, b) => (b.event_count || 0) - (a.event_count || 0)).slice(0, 15);
    const maxEvt = sorted.length ? (sorted[0].event_count || 1) : 1;
    const panel = document.getElementById('mapTopIPs');
    if (sorted.length === 0) {
        panel.innerHTML = '<div style="color:var(--text-secondary);font-size:12px">No data yet</div>';
    } else {
        panel.innerHTML = sorted.map(d => {
            const pct = Math.round(((d.event_count || 1) / maxEvt) * 100);
            const svcs = (d.services || '').split(',').filter(Boolean);
            const svcBadges = svcs.map(s => `<span class="badge badge-${s}" style="font-size:9px;padding:1px 4px">${s}</span>`).join(' ');
            return `<div class="top-ip-item">
                <div style="flex:1;min-width:0">
                    <div style="display:flex;justify-content:space-between;align-items:center">
                        <span style="font-weight:600;color:var(--accent)">${d.ip}</span>
                        <span style="color:var(--text-secondary);font-size:11px">${d.event_count || 0} events</span>
                    </div>
                    <div style="font-size:10px;color:var(--text-secondary);margin:2px 0">${[d.city, d.country].filter(Boolean).join(', ') || '?'}</div>
                    <div>${svcBadges}</div>
                    <div class="top-ip-bar" style="width:${pct}%;background:${pickMarkerColor(d)}"></div>
                </div>
            </div>`;
        }).join('');
    }
}

// ── OVERVIEW: events + alerts in mini feed ───────────────────────────────────
function addEvent(ev) {
    const tbody = document.getElementById('eventBody');
    const tr = document.createElement('tr');
    tr.className = 'new-event';
    const svc = ev.service || '';
    tr.innerHTML = `<td>${formatTime(ev.timestamp)}</td><td><span class="badge badge-${svc}">${svc}</span></td><td>${ipHTML(ev.src_ip)}</td><td>${ev.event_type||''}</td><td title="${esc(summarize(ev.data))}">${esc(summarize(ev.data))}${threatBadges(ev.data)}</td>`;
    tr.onclick = () => showEventDetail(ev);
    tbody.insertBefore(tr, tbody.firstChild);
    while (tbody.children.length > 200) tbody.removeChild(tbody.lastChild);
}

function addAlert(al) {
    const panel = document.getElementById('alertsPanel');
    const div = document.createElement('div');
    div.className = 'alert-item';
    div.id = 'alert-' + al.id;
    div.innerHTML = `<span class="badge badge-${al.severity}">${al.severity}</span><div class="alert-msg">${esc(al.message||al.rule_name)}</div><span class="alert-time">${formatTime(al.timestamp)}</span><button class="alert-ack" onclick="event.stopPropagation();ackAlert(${al.id})">ACK</button>`;
    div.onclick = () => showAlertDetail(al);
    panel.insertBefore(div, panel.firstChild);
    while (panel.children.length > 100) panel.removeChild(panel.lastChild);
}

async function ackAlert(id) {
    await fetch('/api/alerts/' + id + '/ack', { method: 'POST' });
    const el = document.getElementById('alert-' + id);
    if (el) el.style.opacity = '0.4';
    showToast('Alert ' + id + ' acknowledged');
}

// ── Donut Charts ─────────────────────────────────────────────────────────────
function drawDonut(canvasId, legendId, dataMap, colorMap) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = 80, cy = 80, r = 60, ir = 35;
    ctx.clearRect(0, 0, 160, 160);
    const entries = Object.entries(dataMap).filter(([,v]) => v > 0).sort((a,b) => b[1] - a[1]);
    const total = entries.reduce((s,[,v]) => s + v, 0);
    if (total === 0) return;
    let angle = -Math.PI / 2;
    entries.forEach(([key, val]) => {
        const slice = (val / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(cx + ir * Math.cos(angle), cy + ir * Math.sin(angle));
        ctx.arc(cx, cy, r, angle, angle + slice);
        ctx.arc(cx, cy, ir, angle + slice, angle, true);
        ctx.closePath();
        ctx.fillStyle = colorMap[key] || '#666';
        ctx.fill();
        angle += slice;
    });
    ctx.beginPath(); ctx.arc(cx, cy, ir - 1, 0, Math.PI * 2); ctx.fillStyle = '#161616'; ctx.fill();
    ctx.fillStyle = '#e8e0d0'; ctx.font = 'bold 16px monospace'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy);
    const legend = document.getElementById(legendId);
    if (legend) legend.innerHTML = entries.map(([k,v]) => `<div class="chart-legend-item"><div class="chart-legend-color" style="background:${colorMap[k]||'#666'}"></div>${k}: ${v} (${Math.round(v/total*100)}%)</div>`).join('');
}

// ── Stats refresh ────────────────────────────────────────────────────────────
let stats = {};
async function refreshStats() {
    try {
        const r = await fetch('/api/stats');
        stats = await r.json();
        document.getElementById('statEvents').textContent = stats.total_events || 0;
        document.getElementById('statSessions').textContent = stats.total_sessions || 0;
        document.getElementById('statIPs').textContent = stats.unique_ips || 0;
        document.getElementById('statAlerts').textContent = stats.unacknowledged_alerts || 0;
        document.getElementById('statServices').textContent = Object.keys(stats.events_by_service || {}).length;
        drawDonut('serviceChart', 'serviceLegend', stats.events_by_service || {}, serviceColors);
        drawDonut('typeChart', 'typeLegend', stats.events_by_type || {}, typeColors);
    } catch(e) {}
}

async function loadInitial() {
    try {
        const [evR, alR] = await Promise.all([fetch('/api/events?limit=50'), fetch('/api/alerts?limit=50')]);
        const events = await evR.json();
        const alerts = await alR.json();
        events.reverse().forEach(addEvent);
        alerts.reverse().forEach(addAlert);
    } catch(e) {}
}

// ── IP autocomplete ──────────────────────────────────────────────────────────
async function loadIPList() {
    try {
        const r = await fetch('/api/ips');
        const ips = await r.json();
        const dl = document.getElementById('ipList');
        dl.innerHTML = ips.map(ip => `<option value="${ip}">`).join('');
    } catch(e) {}
}

// ── EVENTS TAB ───────────────────────────────────────────────────────────────
let evtOffset = 0; const evtLimit = 50;
async function loadEventsTab() {
    const svc = document.getElementById('evtFilterService').value;
    const typ = document.getElementById('evtFilterType').value;
    const ip = document.getElementById('evtFilterIP').value;
    let url = `/api/events?limit=${evtLimit}&offset=${evtOffset}`;
    if (svc) url += '&service=' + encodeURIComponent(svc);
    if (typ) url += '&type=' + encodeURIComponent(typ);
    if (ip) url += '&ip=' + encodeURIComponent(ip);
    try {
        const r = await fetch(url);
        const events = await r.json();
        const tbody = document.getElementById('evtTabBody');
        tbody.innerHTML = '';
        events.forEach(ev => {
            const tr = document.createElement('tr');
            const s = ev.service || '';
            tr.innerHTML = `<td>${ev.id}</td><td>${formatTime(ev.timestamp)}</td><td><span class="badge badge-${s}">${s}</span></td><td>${ipHTML(ev.src_ip)}</td><td>${ev.event_type||''}</td><td title="${esc(summarize(ev.data))}">${esc(summarize(ev.data))}${threatBadges(ev.data)}</td>`;
            tr.onclick = () => showEventDetail(ev);
            tbody.appendChild(tr);
        });
        document.getElementById('evtPrev').disabled = evtOffset === 0;
        document.getElementById('evtNext').disabled = events.length < evtLimit;
        document.getElementById('evtPageInfo').textContent = `Page ${Math.floor(evtOffset/evtLimit)+1}`;
    } catch(e) { showToast('Failed to load events', 'error'); }
}
function evtPage(dir) { evtOffset = Math.max(0, evtOffset + dir * evtLimit); loadEventsTab(); }

// ── SESSIONS TAB ─────────────────────────────────────────────────────────────
let sessOffset = 0; const sessLimit = 50;
async function loadSessionsTab() {
    const ip = document.getElementById('sessFilterIP').value;
    const svc = document.getElementById('sessFilterService').value;
    let url = `/api/sessions?limit=${sessLimit}&offset=${sessOffset}`;
    if (ip) url += '&ip=' + encodeURIComponent(ip);
    if (svc) url += '&service=' + encodeURIComponent(svc);
    try {
        const r = await fetch(url);
        const sessions = await r.json();
        const tbody = document.getElementById('sessTabBody');
        tbody.innerHTML = '';
        sessions.forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td title="${s.id}">${s.id.substring(0,8)}...</td><td><span class="badge badge-${s.service}">${s.service}</span></td><td>${ipHTML(s.src_ip)}</td><td>${s.dst_port}</td><td>${formatDateTime(s.started_at)}</td><td>${s.ended_at ? formatDateTime(s.ended_at) : '<span style="color:var(--green)">active</span>'}</td>`;
            tr.onclick = () => showSessionDetail(s);
            tbody.appendChild(tr);
        });
        document.getElementById('sessPrev').disabled = sessOffset === 0;
        document.getElementById('sessNext').disabled = sessions.length < sessLimit;
        document.getElementById('sessPageInfo').textContent = `Page ${Math.floor(sessOffset/sessLimit)+1}`;
    } catch(e) { showToast('Failed to load sessions', 'error'); }
}
function sessPage(dir) { sessOffset = Math.max(0, sessOffset + dir * sessLimit); loadSessionsTab(); }

// ── ALERTS TAB ───────────────────────────────────────────────────────────────
let alertOffset = 0; const alertLimit = 50;
let alertTabData = [];
async function loadAlertsTab() {
    const sev = document.getElementById('alertFilterSev').value;
    const ack = document.getElementById('alertFilterAck').value;
    let url = `/api/alerts?limit=${alertLimit}`;
    if (ack === 'unacked') url += '&unacknowledged=true';
    try {
        const r = await fetch(url);
        let alerts = await r.json();
        if (sev) alerts = alerts.filter(a => a.severity === sev);
        if (ack === 'acked') alerts = alerts.filter(a => a.acknowledged);
        alertTabData = alerts;
        const panel = document.getElementById('alertsTabPanel');
        panel.innerHTML = '';
        alerts.forEach(al => {
            const div = document.createElement('div');
            div.className = 'alert-item';
            div.innerHTML = `<span class="badge badge-${al.severity}">${al.severity}</span><div class="alert-msg">${esc(al.message||al.rule_name)}</div><span class="alert-time">${formatTime(al.timestamp)}</span>${al.acknowledged?'<span style="color:var(--green);font-size:10px">ACK</span>':'<button class="alert-ack" onclick="event.stopPropagation();ackAlertTab('+al.id+')">ACK</button>'}`;
            div.onclick = () => showAlertDetail(al);
            panel.appendChild(div);
        });
        document.getElementById('alertPrev').disabled = alertOffset === 0;
        document.getElementById('alertNext').disabled = alerts.length < alertLimit;
        document.getElementById('alertPageInfo').textContent = `Page ${Math.floor(alertOffset/alertLimit)+1}`;
    } catch(e) { showToast('Failed to load alerts', 'error'); }
}
function alertPage(dir) { alertOffset = Math.max(0, alertOffset + dir * alertLimit); loadAlertsTab(); }

async function ackAlertTab(id) {
    await fetch('/api/alerts/' + id + '/ack', { method: 'POST' });
    showToast('Alert ' + id + ' acknowledged');
    loadAlertsTab();
}
async function bulkAckAlerts() {
    const unacked = alertTabData.filter(a => !a.acknowledged);
    for (const al of unacked) { await fetch('/api/alerts/' + al.id + '/ack', { method: 'POST' }); }
    showToast(`Acknowledged ${unacked.length} alerts`);
    loadAlertsTab();
}

// ── DATABASE TAB ─────────────────────────────────────────────────────────────
let dbOffset = 0; const dbLimit = 50; let dbResults = []; let dbTotal = 0;
let dbSortCol = 'id'; let dbSortDir = 'desc';

async function loadDatabaseTab() {
    const ip = document.getElementById('dbFilterIP').value;
    const search = document.getElementById('dbFilterSearch').value;
    const from = document.getElementById('dbFilterFrom').value;
    const to = document.getElementById('dbFilterTo').value;
    const svcBoxes = document.querySelectorAll('#dbSvcCheckboxes input:checked');
    const typeBoxes = document.querySelectorAll('#dbTypeCheckboxes input:checked');
    const services = Array.from(svcBoxes).map(c => c.value).join(',');
    const types = Array.from(typeBoxes).map(c => c.value).join(',');

    let url = `/api/events?paginated=1&limit=${dbLimit}&offset=${dbOffset}`;
    if (ip) url += '&ip=' + encodeURIComponent(ip);
    if (services) url += '&services=' + encodeURIComponent(services);
    if (types) url += '&types=' + encodeURIComponent(types);
    if (search) url += '&search=' + encodeURIComponent(search);
    if (from) url += '&from=' + encodeURIComponent(new Date(from).toISOString());
    if (to) url += '&to=' + encodeURIComponent(new Date(to).toISOString());

    try {
        const r = await fetch(url);
        const data = await r.json();
        dbResults = data.events || [];
        dbTotal = data.total || 0;
        renderDBTable();
        document.getElementById('dbResultCount').textContent = `${dbTotal} results`;
        document.getElementById('dbPrev').disabled = dbOffset === 0;
        document.getElementById('dbNext').disabled = dbOffset + dbLimit >= dbTotal;
        document.getElementById('dbPageInfo').textContent = `Page ${Math.floor(dbOffset/dbLimit)+1} of ${Math.max(1, Math.ceil(dbTotal/dbLimit))}`;
    } catch(e) { showToast('Database query failed', 'error'); }
}

function renderDBTable() {
    const tbody = document.getElementById('dbTabBody');
    tbody.innerHTML = '';
    dbResults.forEach(ev => {
        const tr = document.createElement('tr');
        const s = ev.service || '';
        tr.innerHTML = `<td>${ev.id}</td><td>${formatTime(ev.timestamp)}</td><td><span class="badge badge-${s}">${s}</span></td><td>${ipHTML(ev.src_ip)}</td><td>${ev.event_type||''}</td><td title="${esc(summarize(ev.data))}">${esc(summarize(ev.data))}${threatBadges(ev.data)}</td>`;
        tr.onclick = () => showEventDetail(ev);
        tbody.appendChild(tr);
    });
}

function dbSort(col) { dbSortCol = col; loadDatabaseTab(); }
function dbPage(dir) { dbOffset = Math.max(0, dbOffset + dir * dbLimit); loadDatabaseTab(); }

function exportDBResults() {
    const blob = new Blob([JSON.stringify(dbResults, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'honeypot_export.json'; a.click();
    URL.revokeObjectURL(url);
    showToast('Exported ' + dbResults.length + ' events');
}

// ── DATABASE RESET ───────────────────────────────────────────────────────────
function confirmResetDB() {
    openModal('Reset Database', `
        <div class="confirm-body">
            <p style="font-size:18px;font-weight:700;color:var(--red)">Reset Database?</p>
            <p>This will permanently delete <strong>all</strong> captured data:</p>
            <p style="color:var(--text-secondary);font-size:13px">Events, sessions, alerts, and geolocation cache.</p>
            <p class="warn">This action cannot be undone.</p>
            <div class="confirm-btns">
                <button class="btn-cancel" onclick="closeModal()">Cancel</button>
                <button class="btn-danger" onclick="executeResetDB()">Yes, Reset Everything</button>
            </div>
        </div>
    `);
}

async function executeResetDB() {
    closeModal();
    try {
        const r = await fetch('/api/database/reset', { method: 'POST' });
        const data = await r.json();
        if (r.ok) {
            showToast('Database reset complete');
            // Clear local UI state
            document.getElementById('eventBody').innerHTML = '';
            document.getElementById('alertsPanel').innerHTML = '';
            document.getElementById('dbTabBody').innerHTML = '';
            dbResults = []; dbTotal = 0;
            // Clear maps
            Object.values(overviewMarkers).forEach(m => overviewMap.removeLayer(m));
            overviewMarkers = {};
            if (fullMap) {
                Object.values(fullMarkers).forEach(m => fullMap.removeLayer(m));
                fullMarkers = {};
                document.getElementById('mapTopIPs').innerHTML = '<div style="color:var(--text-secondary);font-size:12px">No data yet</div>';
                document.getElementById('mapStatIPs').textContent = '0';
                document.getElementById('mapStatCountries').textContent = '0';
                document.getElementById('mapStatSessions').textContent = '0';
                document.getElementById('mapStatEvents').textContent = '0';
            }
            refreshStats();
            loadIPList();
        } else {
            showToast(data.error || 'Reset failed', 'error');
        }
    } catch(e) { showToast('Reset failed: ' + e.message, 'error'); }
}

// ── CONFIG TAB ───────────────────────────────────────────────────────────────
async function loadConfigTab() {
    try {
        const r = await fetch('/api/config');
        const config = await r.json();
        const grid = document.getElementById('configGrid');
        grid.innerHTML = '';
        const svcNames = ['ssh', 'http', 'ftp', 'smb', 'mysql', 'telnet', 'smtp', 'mongodb', 'vnc', 'redis', 'adb'];
        svcNames.forEach(name => {
            const svc = config[name];
            if (!svc) return;
            const card = document.createElement('div');
            card.className = 'config-card';
            card.innerHTML = `
                <h3><span class="badge badge-${name}">${name.toUpperCase()}</span> Service</h3>
                <div class="config-field">
                    <div class="config-toggle" onclick="this.querySelector('.toggle-switch').classList.toggle('on')">
                        <div class="toggle-switch ${svc.enabled?'on':''}" id="cfg-${name}-enabled"></div>
                        <span style="font-size:12px">${svc.enabled?'Enabled':'Disabled'}</span>
                    </div>
                </div>
                <div class="config-field">
                    <label>Port</label>
                    <input type="number" id="cfg-${name}-port" value="${svc.port}">
                </div>
                <div class="config-field">
                    <label>Banner</label>
                    <input type="text" id="cfg-${name}-banner" value="${esc(svc.banner||'')}">
                </div>
                <button class="config-apply" onclick="applyConfig('${name}')">Apply</button>
            `;
            grid.appendChild(card);
        });
    } catch(e) { showToast('Failed to load config', 'error'); }
}

async function applyConfig(name) {
    const enabled = document.getElementById('cfg-' + name + '-enabled').classList.contains('on');
    const port = parseInt(document.getElementById('cfg-' + name + '-port').value);
    const banner = document.getElementById('cfg-' + name + '-banner').value;
    try {
        const r = await fetch('/api/config/service/' + name, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled, port, banner }),
        });
        if (r.ok) {
            showToast(`${name.toUpperCase()} config updated`);
            loadConfigTab();
        } else {
            const d = await r.json();
            showToast(d.error || 'Update failed', 'error');
        }
    } catch(e) { showToast('Config update failed', 'error'); }
}

// ── MODALS ───────────────────────────────────────────────────────────────────
function showEventDetail(ev) {
    let html = `<div style="margin-bottom:12px">
        <span class="badge badge-${ev.service}">${ev.service}</span>
        <span style="margin-left:8px;font-size:12px;color:var(--text-secondary)">${ev.event_type}</span>
    </div>
    <table style="font-size:12px;margin-bottom:12px;width:100%">
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Event ID</td><td>${ev.id}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Session</td><td><a href="#" onclick="event.preventDefault();loadSessionById('${ev.session_id}')" style="color:var(--accent)">${ev.session_id ? ev.session_id.substring(0,8)+'...' : '-'}</a></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Source IP</td><td>${ev.src_ip}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Timestamp</td><td>${formatDateTime(ev.timestamp)}</td></tr>
    </table>`;
    if (ev.data && ev.data.threats && ev.data.threats.length) {
        html += `<div style="margin-bottom:12px"><strong style="font-size:12px;color:var(--red)">Threats Detected:</strong><ul style="font-size:12px;margin:4px 0 0 16px">`;
        ev.data.threats.forEach(t => { html += `<li><span class="badge badge-${t.severity}">${t.severity}</span> ${esc(t.name)} — ${esc(t.description)}</li>`; });
        html += `</ul></div>`;
    }
    html += `<div class="json-viewer">${esc(JSON.stringify(ev.data, null, 2))}</div>`;
    openModal('Event Detail', html);
}

async function showSessionDetail(s) {
    let html = `<table style="font-size:12px;margin-bottom:16px;width:100%">
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Session ID</td><td>${s.id}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Service</td><td><span class="badge badge-${s.service}">${s.service}</span></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Source</td><td>${s.src_ip}:${s.src_port}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Dest Port</td><td>${s.dst_port}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Started</td><td>${formatDateTime(s.started_at)}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Ended</td><td>${s.ended_at ? formatDateTime(s.ended_at) : 'Active'}</td></tr>
    </table>
    <h3 style="font-size:13px;margin-bottom:8px;color:var(--text-secondary)">EVENT TIMELINE</h3>
    <div class="timeline" id="sessionTimeline"><div style="color:var(--text-secondary);font-size:12px">Loading...</div></div>`;
    openModal('Session Detail', html);
    try {
        const r = await fetch('/api/sessions/' + s.id + '/events');
        const events = await r.json();
        const tl = document.getElementById('sessionTimeline');
        if (events.length === 0) { tl.innerHTML = '<div style="color:var(--text-secondary);font-size:12px">No events found</div>'; return; }
        tl.innerHTML = events.map(ev => `<div class="timeline-item">
            <div class="tl-time">${formatTime(ev.timestamp)}</div>
            <div class="tl-type"><span class="badge badge-${ev.service}">${ev.service}</span> ${ev.event_type}</div>
            <div class="tl-detail">${esc(summarize(ev.data))}</div>
        </div>`).join('');
    } catch(e) { document.getElementById('sessionTimeline').innerHTML = '<div style="color:var(--red);font-size:12px">Failed to load events</div>'; }
}

async function loadSessionById(sid) {
    closeModal();
    try {
        const r = await fetch('/api/sessions?limit=1000');
        const sessions = await r.json();
        const s = sessions.find(x => x.id === sid);
        if (s) showSessionDetail(s);
        else showToast('Session not found', 'error');
    } catch(e) { showToast('Failed to load session', 'error'); }
}

function showAlertDetail(al) {
    let html = `<div style="margin-bottom:12px">
        <span class="badge badge-${al.severity}">${al.severity}</span>
        <span style="margin-left:8px;font-size:12px;color:var(--text-secondary)">${al.rule_name}</span>
        ${al.acknowledged ? '<span style="margin-left:8px;color:var(--green);font-size:11px">Acknowledged</span>' : ''}
    </div>
    <table style="font-size:12px;margin-bottom:12px;width:100%">
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Alert ID</td><td>${al.id}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Source IP</td><td>${al.src_ip}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Service</td><td><span class="badge badge-${al.service}">${al.service}</span></td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Timestamp</td><td>${formatDateTime(al.timestamp)}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Event IDs</td><td>${(al.event_ids||[]).join(', ') || 'none'}</td></tr>
    </table>
    <div style="font-size:13px;margin-bottom:8px">${esc(al.message)}</div>`;
    if (!al.acknowledged) {
        html += `<button class="config-apply" onclick="ackAlert(${al.id});closeModal()">Acknowledge</button>`;
    }
    openModal('Alert Detail', html);
}

// ── IP Popover ───────────────────────────────────────────────────────────────
function showIPPopover(event, ip) {
    const pop = document.getElementById('ipPopover');
    const isBlocked = blockedIPs.has(ip);
    pop.innerHTML = `
        <div class="ip-popover-header">${esc(ip)}</div>
        ${isBlocked
            ? `<div class="ip-popover-item success" onclick="unblockIP('${esc(ip)}')">&#x2714; Unblock IP</div>`
            : `<div class="ip-popover-item danger" onclick="blockIP('${esc(ip)}')">&#x26D4; Block IP (iptables)</div>`
        }
        <div class="ip-popover-item" onclick="filterByIP('${esc(ip)}')">&#x1F50D; Filter Events</div>
        <div class="ip-popover-item" onclick="lookupGeo('${esc(ip)}')">&#x1F30D; Geo Lookup</div>
    `;
    pop.style.display = 'block';
    // Position near click
    const x = Math.min(event.clientX, window.innerWidth - 200);
    const y = Math.min(event.clientY, window.innerHeight - 180);
    pop.style.left = x + 'px';
    pop.style.top = y + 'px';
}

document.addEventListener('click', (e) => {
    const pop = document.getElementById('ipPopover');
    if (!e.target.closest('.ip-popover') && !e.target.classList.contains('ip-addr')) {
        pop.style.display = 'none';
    }
});

async function blockIP(ip) {
    document.getElementById('ipPopover').style.display = 'none';
    try {
        const r = await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        const data = await r.json();
        if (r.ok) {
            blockedIPs.add(ip);
            refreshBlockedIPStyles();
            showToast(`Blocked ${ip}` + (data.iptables_applied ? ' (iptables rule added)' : ' (tracked)'));
            if (document.getElementById('tab-firewall').classList.contains('active')) loadFirewallTab();
        } else {
            showToast(data.error || 'Block failed', 'error');
        }
    } catch(e) { showToast('Block failed: ' + e.message, 'error'); }
}

async function unblockIP(ip) {
    document.getElementById('ipPopover').style.display = 'none';
    try {
        const r = await fetch('/api/firewall/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip }),
        });
        const data = await r.json();
        if (r.ok) {
            blockedIPs.delete(ip);
            refreshBlockedIPStyles();
            showToast(`Unblocked ${ip}`);
            if (document.getElementById('tab-firewall').classList.contains('active')) loadFirewallTab();
        } else {
            showToast(data.error || 'Unblock failed', 'error');
        }
    } catch(e) { showToast('Unblock failed: ' + e.message, 'error'); }
}

function refreshBlockedIPStyles() {
    document.querySelectorAll('.ip-addr').forEach(el => {
        if (blockedIPs.has(el.textContent)) el.classList.add('blocked');
        else el.classList.remove('blocked');
    });
}

function filterByIP(ip) {
    document.getElementById('ipPopover').style.display = 'none';
    document.getElementById('evtFilterIP').value = ip;
    switchTab('events');
    loadEventsTab();
}

async function lookupGeo(ip) {
    document.getElementById('ipPopover').style.display = 'none';
    try {
        const r = await fetch('/api/geo/' + encodeURIComponent(ip));
        const geo = await r.json();
        openModal('Geo Lookup: ' + ip, `
            <table style="font-size:12px;width:100%">
                <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">IP</td><td style="color:var(--accent);font-weight:700">${esc(ip)}</td></tr>
                <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Country</td><td>${esc(geo.country||'?')}</td></tr>
                <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">City</td><td>${esc(geo.city||'?')}</td></tr>
                <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">ISP</td><td>${esc(geo.isp||'?')}</td></tr>
                <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Lat/Lon</td><td>${geo.lat||'?'}, ${geo.lon||'?'}</td></tr>
            </table>
            <div style="margin-top:12px">
                ${blockedIPs.has(ip)
                    ? `<button class="config-apply" style="background:var(--green)" onclick="unblockIP('${esc(ip)}');closeModal()">Unblock IP</button>`
                    : `<button class="config-apply" style="background:var(--red)" onclick="blockIP('${esc(ip)}');closeModal()">Block IP</button>`
                }
            </div>
        `);
    } catch(e) { showToast('Geo lookup failed', 'error'); }
}

// ── FIREWALL TAB ─────────────────────────────────────────────────────────────
async function loadFirewallTab() {
    try {
        const r = await fetch('/api/firewall/blocked');
        const data = await r.json();
        blockedIPs = new Set(data.blocked || []);
        refreshBlockedIPStyles();

        const statusEl = document.getElementById('fwIptablesStatus');
        if (statusEl) {
            statusEl.innerHTML = data.iptables_available
                ? '<span style="color:var(--green)">&#x2713; iptables is available — rules are applied to the system firewall</span>'
                : '<span style="color:var(--orange)">&#x26A0; iptables not found — IPs are tracked but not blocked at the system level</span>';
        }

        const countEl = document.getElementById('fwBlockedCount');
        if (countEl) countEl.textContent = blockedIPs.size > 0 ? `(${blockedIPs.size})` : '';

        const list = document.getElementById('fwBlockedList');
        if (blockedIPs.size === 0) {
            list.innerHTML = '<div style="color:var(--text-secondary);font-size:12px">No IPs blocked</div>';
        } else {
            list.innerHTML = [...blockedIPs].map(ip => `
                <div class="fw-ip-row">
                    <span class="ip">${esc(ip)}</span>
                    <button class="fw-unblock-btn" onclick="unblockIP('${esc(ip)}')">Unblock</button>
                </div>
            `).join('');
        }
    } catch(e) { showToast('Failed to load firewall data', 'error'); }
}

async function manualBlockIP() {
    const input = document.getElementById('fwBlockInput');
    const ip = input.value.trim();
    if (!ip) return;
    input.value = '';
    await blockIP(ip);
}

// Load blocked IPs on init
async function loadBlockedIPs() {
    try {
        const r = await fetch('/api/firewall/blocked');
        const data = await r.json();
        blockedIPs = new Set(data.blocked || []);
    } catch(e) {}
}

// ── WebSocket ────────────────────────────────────────────────────────────────
function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Pass auth token via cookie (sent automatically) and query param as fallback
    const token = document.cookie.split(';').map(c=>c.trim()).find(c=>c.startsWith('mantis_token='));
    const tokenVal = token ? token.split('=')[1] : '';
    const ws = new WebSocket(proto + '//' + location.host + '/ws' + (tokenVal ? '?token=' + encodeURIComponent(tokenVal) : ''));
    ws.onopen = () => { document.getElementById('wsStatus').textContent = 'Connected'; document.getElementById('wsDot').style.background = '#10b981'; };
    ws.onclose = () => { document.getElementById('wsStatus').textContent = 'Reconnecting...'; document.getElementById('wsDot').style.background = '#ef4444'; setTimeout(connectWS, 3000); };
    ws.onmessage = (e) => {
        try {
            const msg = JSON.parse(e.data);
            if (msg.type === 'event') { addEvent(msg.data); refreshStats(); }
            else if (msg.type === 'alert') { addAlert(msg.data); refreshStats(); }
            else if (msg.type === 'config_change') { showToast('Config updated by another client'); }
            else if (msg.type === 'ip_blocked') {
                blockedIPs.add(msg.data.ip);
                refreshBlockedIPStyles();
                if (document.getElementById('tab-firewall').classList.contains('active')) loadFirewallTab();
            }
            else if (msg.type === 'ip_unblocked') {
                blockedIPs.delete(msg.data.ip);
                refreshBlockedIPStyles();
                if (document.getElementById('tab-firewall').classList.contains('active')) loadFirewallTab();
            }
            else if (msg.type === 'database_reset') {
                showToast('Database was reset');
                document.getElementById('eventBody').innerHTML = '';
                document.getElementById('alertsPanel').innerHTML = '';
                refreshStats();
            }
        } catch(err) {}
    };
}

// ── Active Honeypots Blobs ────────────────────────────────────────────────────
async function loadActiveHoneypots() {
    try {
        const r = await fetch('/api/config');
        const config = await r.json();
        const container = document.getElementById('activeHoneypots');
        if (!container) return;
        const svcOrder = ['ssh','http','ftp','smb','mysql','telnet','smtp','mongodb','vnc','redis','adb'];
        container.innerHTML = svcOrder.map(name => {
            const svc = config[name];
            if (!svc) return '';
            const active = svc.enabled;
            return `<div class="hp-blob ${active ? 'active' : 'inactive'}"><span class="hp-dot"></span>${name.toUpperCase()} <span class="hp-port">:${svc.port}</span></div>`;
        }).join('');
    } catch(e) {}
}

// ── Init ─────────────────────────────────────────────────────────────────────
loadBlockedIPs();
loadInitial();
refreshStats();
refreshOverviewMap();
loadIPList();
loadActiveHoneypots();
setInterval(refreshStats, 10000);
setInterval(refreshOverviewMap, 30000);
setInterval(loadActiveHoneypots, 30000);
connectWS();
</script>
</body>
</html>"""
