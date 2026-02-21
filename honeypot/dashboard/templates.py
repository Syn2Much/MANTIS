"""Embedded HTML/CSS/JS dashboard with multi-tab layout, modals, and live config editing."""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MANTIS // Login</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 120 120'><path d='M60 28L48 42L72 42Z' fill='%23f59e0b'/><path d='M55 30Q45 12 30 6' stroke='%23f59e0b' stroke-width='3' fill='none'/><path d='M65 30Q75 12 90 6' stroke='%23f59e0b' stroke-width='3' fill='none'/><ellipse cx='60' cy='52' rx='8' ry='7' fill='%23f59e0b'/><path d='M54 58Q52 75 50 98Q60 104 70 98Q68 75 66 58Z' fill='%23f59e0b'/><path d='M54 46L36 34L24 44L34 50' stroke='%23f59e0b' stroke-width='3' fill='none'/><path d='M66 46L84 34L96 44L86 50' stroke='%23f59e0b' stroke-width='3' fill='none'/></svg>">
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
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 120 120'><path d='M60 28L48 42L72 42Z' fill='%23f59e0b'/><path d='M55 30Q45 12 30 6' stroke='%23f59e0b' stroke-width='3' fill='none'/><path d='M65 30Q75 12 90 6' stroke='%23f59e0b' stroke-width='3' fill='none'/><ellipse cx='60' cy='52' rx='8' ry='7' fill='%23f59e0b'/><path d='M54 58Q52 75 50 98Q60 104 70 98Q68 75 66 58Z' fill='%23f59e0b'/><path d='M54 46L36 34L24 44L34 50' stroke='%23f59e0b' stroke-width='3' fill='none'/><path d='M66 46L84 34L96 44L86 50' stroke='%23f59e0b' stroke-width='3' fill='none'/></svg>">
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
.config-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px; }
.config-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
.config-card h3 { font-size: 14px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
.config-field { margin-bottom: 10px; }
.config-field label { display: block; font-size: 11px; color: var(--text-secondary); margin-bottom: 4px; text-transform: uppercase; }
.config-field input[type="text"], .config-field input[type="number"] { width: 100%; background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text-primary); padding: 8px 12px; border-radius: 4px; font-family: inherit; font-size: 13px; }
.config-field input:focus { outline: none; border-color: var(--accent); }
.config-field textarea { width: 100%; background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text-primary); padding: 8px 12px; border-radius: 4px; font-family: inherit; font-size: 12px; resize: vertical; min-height: 50px; }
.config-field textarea:focus { outline: none; border-color: var(--accent); }
.config-field select { width: 100%; background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text-primary); padding: 8px 12px; border-radius: 4px; font-family: inherit; font-size: 13px; cursor: pointer; }
.config-field select:focus { outline: none; border-color: var(--accent); }
.config-toggle { display: flex; align-items: center; gap: 8px; cursor: pointer; }
.toggle-switch { position: relative; width: 40px; height: 22px; background: var(--border); border-radius: 11px; transition: background 0.2s; cursor: pointer; }
.toggle-switch.on { background: var(--accent); }
.toggle-switch::after { content: ''; position: absolute; width: 18px; height: 18px; background: white; border-radius: 50%; top: 2px; left: 2px; transition: left 0.2s; }
.toggle-switch.on::after { left: 20px; }
.config-apply { background: var(--accent); color: #0c0c0c; border: none; padding: 8px 20px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 600; font-family: inherit; margin-top: 8px; }
.config-apply:hover { background: #fbbf24; }
.config-section { margin-bottom: 24px; }
.config-section-title { font-size: 13px; font-weight: 700; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
.config-section-title::after { content: ''; flex: 1; height: 1px; background: var(--border); }
.config-toolbar { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }
.config-toolbar button { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-primary); padding: 8px 16px; border-radius: 4px; cursor: pointer; font-family: inherit; font-size: 12px; font-weight: 600; display: flex; align-items: center; gap: 6px; }
.config-toolbar button:hover { border-color: var(--accent); color: var(--accent); }
.config-toolbar button.primary { background: var(--accent); color: #0c0c0c; border-color: var(--accent); }
.config-toolbar button.primary:hover { background: #fbbf24; }
.config-advanced { border-top: 1px solid var(--border); margin-top: 12px; padding-top: 12px; display: none; }
.config-advanced.open { display: block; }
.config-advanced-toggle { font-size: 11px; color: var(--text-secondary); cursor: pointer; display: flex; align-items: center; gap: 4px; margin-top: 8px; }
.config-advanced-toggle:hover { color: var(--accent); }
.config-global-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
.config-global-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 16px; }
.banner-row { display: flex; gap: 8px; }
.banner-row input { flex: 1; }
.banner-row select { width: 140px; flex-shrink: 0; }

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
        <svg width="30" height="30" viewBox="0 0 120 120" style="vertical-align:middle;margin-right:10px" fill="none">
            <!-- Head — triangular with compound eyes -->
            <path d="M60 28 L48 42 L72 42 Z" fill="#f59e0b" opacity="0.9"/>
            <circle cx="53" cy="36" r="3" fill="#0c0c0c"/>
            <circle cx="67" cy="36" r="3" fill="#0c0c0c"/>
            <!-- Antennae — swept back -->
            <path d="M55 30 Q45 12 30 6" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" fill="none"/>
            <path d="M65 30 Q75 12 90 6" stroke="#f59e0b" stroke-width="2" stroke-linecap="round" fill="none"/>
            <circle cx="30" cy="6" r="2.5" fill="#f59e0b" opacity="0.7"/>
            <circle cx="90" cy="6" r="2.5" fill="#f59e0b" opacity="0.7"/>
            <!-- Thorax -->
            <ellipse cx="60" cy="52" rx="8" ry="7" fill="#f59e0b" opacity="0.85"/>
            <!-- Abdomen — elongated -->
            <path d="M54 58 Q52 75 50 98 Q60 104 70 98 Q68 75 66 58 Z" fill="#f59e0b" opacity="0.75"/>
            <!-- Segments on abdomen -->
            <line x1="53" y1="68" x2="67" y2="68" stroke="#0c0c0c" stroke-width="0.8" opacity="0.4"/>
            <line x1="52" y1="78" x2="68" y2="78" stroke="#0c0c0c" stroke-width="0.8" opacity="0.4"/>
            <line x1="51" y1="88" x2="69" y2="88" stroke="#0c0c0c" stroke-width="0.8" opacity="0.4"/>
            <!-- Raptorial forelegs — the iconic praying mantis arms -->
            <path d="M54 46 L36 34 L24 44 L34 50" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
            <path d="M66 46 L84 34 L96 44 L86 50" stroke="#f59e0b" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
            <!-- Spines on forelegs -->
            <line x1="30" y1="38" x2="27" y2="33" stroke="#f59e0b" stroke-width="1.2" stroke-linecap="round" opacity="0.6"/>
            <line x1="34" y1="36" x2="32" y2="31" stroke="#f59e0b" stroke-width="1.2" stroke-linecap="round" opacity="0.6"/>
            <line x1="90" y1="38" x2="93" y2="33" stroke="#f59e0b" stroke-width="1.2" stroke-linecap="round" opacity="0.6"/>
            <line x1="86" y1="36" x2="88" y2="31" stroke="#f59e0b" stroke-width="1.2" stroke-linecap="round" opacity="0.6"/>
            <!-- Mid legs -->
            <path d="M56 56 Q40 62 26 72" stroke="#f59e0b" stroke-width="1.8" stroke-linecap="round" fill="none"/>
            <path d="M64 56 Q80 62 94 72" stroke="#f59e0b" stroke-width="1.8" stroke-linecap="round" fill="none"/>
            <!-- Hind legs -->
            <path d="M54 66 Q38 76 22 92" stroke="#f59e0b" stroke-width="1.8" stroke-linecap="round" fill="none"/>
            <path d="M66 66 Q82 76 98 92" stroke="#f59e0b" stroke-width="1.8" stroke-linecap="round" fill="none"/>
            <!-- Wings — subtle, translucent -->
            <path d="M58 48 Q42 52 36 64 Q48 60 56 54 Z" fill="#f59e0b" opacity="0.12"/>
            <path d="M62 48 Q78 52 84 64 Q72 60 64 54 Z" fill="#f59e0b" opacity="0.12"/>
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
    <button class="tab-btn" onclick="switchTab('attackers')">Attackers</button>
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
<div class="filter-row" style="flex-wrap:wrap">
    <div class="filter-group">
        <label>Services</label>
        <div class="checkbox-group" id="evtSvcCheckboxes">
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
        <div class="checkbox-group" id="evtTypeCheckboxes">
            <label><input type="checkbox" value="connection" checked> connection</label>
            <label><input type="checkbox" value="auth_attempt" checked> auth</label>
            <label><input type="checkbox" value="command" checked> command</label>
            <label><input type="checkbox" value="request" checked> request</label>
            <label><input type="checkbox" value="query" checked> query</label>
            <label><input type="checkbox" value="file_transfer" checked> file_transfer</label>
            <label><input type="checkbox" value="ntlm_auth" checked> ntlm_auth</label>
            <label><input type="checkbox" value="disconnect" checked> disconnect</label>
        </div>
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
<div class="filter-row" style="flex-wrap:wrap">
    <div class="filter-group">
        <label>IP</label>
        <input type="text" id="sessFilterIP" placeholder="Filter by IP" list="ipList" style="width:140px">
    </div>
    <div class="filter-group">
        <label>Services</label>
        <div class="checkbox-group" id="sessSvcCheckboxes">
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
<div class="filter-row" style="flex-wrap:wrap">
    <div class="filter-group">
        <label>Severity</label>
        <div class="checkbox-group" id="alertSevCheckboxes">
            <label><input type="checkbox" value="critical" checked> critical</label>
            <label><input type="checkbox" value="high" checked> high</label>
            <label><input type="checkbox" value="medium" checked> medium</label>
            <label><input type="checkbox" value="low" checked> low</label>
            <label><input type="checkbox" value="info" checked> info</label>
        </div>
    </div>
    <div class="filter-group">
        <label>Status</label>
        <div class="checkbox-group" id="alertStatusCheckboxes">
            <label><input type="checkbox" value="unacked" checked> Unacknowledged</label>
            <label><input type="checkbox" value="acked" checked> Acknowledged</label>
        </div>
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

<!-- ═══════════════════ ATTACKERS TAB ═══════════════════ -->
<div id="tab-attackers" class="tab-content">
<div class="filter-row">
    <button class="filter-btn" onclick="loadAttackersTab()">Refresh</button>
    <button class="filter-btn secondary" onclick="exportTable('attackers','json')">Export JSON</button>
    <button class="filter-btn secondary" onclick="exportTable('attackers','csv')">Export CSV</button>
    <span style="margin-left:auto;font-size:11px;color:var(--text-secondary)" id="atkCount">0 attackers</span>
</div>
<div class="card">
    <div class="events-scroll" style="max-height:600px">
        <table class="event-table" id="atkTable">
            <thead><tr>
                <th>IP Address</th>
                <th>Country</th>
                <th>City / ISP</th>
                <th>Services Hit</th>
                <th>Events</th>
                <th>Sessions</th>
                <th>Auth Tries</th>
                <th>Commands</th>
                <th>First Seen</th>
                <th>Last Seen</th>
            </tr></thead>
            <tbody id="atkTabBody"></tbody>
        </table>
    </div>
</div>
<div class="pagination">
    <button onclick="atkPage(-1)" id="atkPrev" disabled>Prev</button>
    <span id="atkPageInfo">Page 1</span>
    <button onclick="atkPage(1)" id="atkNext">Next</button>
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
    <button class="filter-btn secondary" onclick="exportDBResults('json')">Export JSON</button>
    <button class="filter-btn secondary" onclick="exportDBResults('csv')">Export CSV</button>
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

<div class="config-toolbar" id="configToolbar">
    <button class="primary" onclick="saveConfig()">&#128190; Save Config</button>
    <button onclick="exportConfig()">&#8615; Export YAML</button>
</div>

<!-- Global Settings -->
<div class="config-section">
    <div class="config-section-title">Global Settings</div>
    <div class="config-global-grid" id="globalConfigGrid"></div>
</div>

<!-- Services -->
<div class="config-section">
    <div class="config-section-title">Honeypot Services</div>
    <div class="config-grid" id="configGrid"></div>
</div>

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
    if (data.username) { let s = String(data.username); if (data.password) s += ':' + data.password; return s; }
    if (data.command) return String(data.command);
    if (data.query) return String(data.query).substring(0, 80);
    if (data.method) return String(data.method) + ' ' + (data.path || '');
    if (data.message) return String(data.message);
    try { return JSON.stringify(data).substring(0, 80); } catch(e) { return ''; }
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
    else if (name === 'attackers') loadAttackersTab();
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
        const data = await apiFetch('/api/map');
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
        fullMapData = await apiFetch('/api/map');
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
        stats = await apiFetch('/api/stats');
        document.getElementById('statEvents').textContent = stats.total_events || 0;
        document.getElementById('statSessions').textContent = stats.total_sessions || 0;
        document.getElementById('statIPs').textContent = stats.unique_ips || 0;
        document.getElementById('statAlerts').textContent = stats.unacknowledged_alerts || 0;
        document.getElementById('statServices').textContent = Object.keys(stats.events_by_service || {}).length;
        drawDonut('serviceChart', 'serviceLegend', stats.events_by_service || {}, serviceColors);
        drawDonut('typeChart', 'typeLegend', stats.events_by_type || {}, typeColors);
    } catch(e) {}
}

async function apiFetch(url, opts) {
    const r = await fetch(url, opts);
    if (!r.ok) {
        let msg = r.statusText;
        try { const d = await r.json(); msg = d.error || msg; } catch(_) {}
        throw new Error(msg);
    }
    return r.json();
}

async function loadInitial() {
    try {
        const [events, alerts] = await Promise.all([apiFetch('/api/events?limit=50'), apiFetch('/api/alerts?limit=50')]);
        events.reverse().forEach(addEvent);
        alerts.reverse().forEach(addAlert);
    } catch(e) {}
}

// ── IP autocomplete ──────────────────────────────────────────────────────────
async function loadIPList() {
    try {
        const ips = await apiFetch('/api/ips');
        const dl = document.getElementById('ipList');
        dl.innerHTML = ips.map(ip => `<option value="${ip}">`).join('');
    } catch(e) {}
}

// ── EVENTS TAB ───────────────────────────────────────────────────────────────
let evtOffset = 0; const evtLimit = 50;
async function loadEventsTab() {
    const ip = document.getElementById('evtFilterIP').value;
    const svcBoxes = document.querySelectorAll('#evtSvcCheckboxes input:checked');
    const typeBoxes = document.querySelectorAll('#evtTypeCheckboxes input:checked');
    const services = Array.from(svcBoxes).map(c => c.value).join(',');
    const types = Array.from(typeBoxes).map(c => c.value).join(',');
    let url = `/api/events?limit=${evtLimit}&offset=${evtOffset}`;
    if (services) url += '&services=' + encodeURIComponent(services);
    if (types) url += '&types=' + encodeURIComponent(types);
    if (ip) url += '&ip=' + encodeURIComponent(ip);
    try {
        const events = await apiFetch(url);
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
    } catch(e) { showToast('Failed to load events: ' + e.message, 'error'); }
}
function evtPage(dir) { evtOffset = Math.max(0, evtOffset + dir * evtLimit); loadEventsTab(); }

// ── SESSIONS TAB ─────────────────────────────────────────────────────────────
let sessOffset = 0; const sessLimit = 50;
async function loadSessionsTab() {
    const ip = document.getElementById('sessFilterIP').value;
    const svcBoxes = document.querySelectorAll('#sessSvcCheckboxes input:checked');
    const services = Array.from(svcBoxes).map(c => c.value).join(',');
    let url = `/api/sessions?limit=${sessLimit}&offset=${sessOffset}`;
    if (ip) url += '&ip=' + encodeURIComponent(ip);
    if (services) url += '&services=' + encodeURIComponent(services);
    try {
        const sessions = await apiFetch(url);
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
    } catch(e) { showToast('Failed to load sessions: ' + e.message, 'error'); }
}
function sessPage(dir) { sessOffset = Math.max(0, sessOffset + dir * sessLimit); loadSessionsTab(); }

// ── ALERTS TAB ───────────────────────────────────────────────────────────────
let alertOffset = 0; const alertLimit = 50;
let alertTabData = [];
async function loadAlertsTab() {
    const sevBoxes = document.querySelectorAll('#alertSevCheckboxes input:checked');
    const sevs = new Set(Array.from(sevBoxes).map(c => c.value));
    const statusBoxes = document.querySelectorAll('#alertStatusCheckboxes input:checked');
    const statuses = new Set(Array.from(statusBoxes).map(c => c.value));
    const showUnacked = statuses.has('unacked');
    const showAcked = statuses.has('acked');
    let url = `/api/alerts?limit=${alertLimit}`;
    if (showUnacked && !showAcked) url += '&unacknowledged=true';
    try {
        let alerts = await apiFetch(url);
        if (sevs.size < 5) alerts = alerts.filter(a => sevs.has(a.severity));
        if (showAcked && !showUnacked) alerts = alerts.filter(a => a.acknowledged);
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
    } catch(e) { showToast('Failed to load alerts: ' + e.message, 'error'); }
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
        const data = await apiFetch(url);
        dbResults = data.events || [];
        dbTotal = data.total || 0;
        renderDBTable();
        document.getElementById('dbResultCount').textContent = `${dbTotal} results`;
        document.getElementById('dbPrev').disabled = dbOffset === 0;
        document.getElementById('dbNext').disabled = dbOffset + dbLimit >= dbTotal;
        document.getElementById('dbPageInfo').textContent = `Page ${Math.floor(dbOffset/dbLimit)+1} of ${Math.max(1, Math.ceil(dbTotal/dbLimit))}`;
    } catch(e) { showToast('Database query failed: ' + e.message, 'error'); }
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

function exportDBResults(fmt) {
    fmt = fmt || 'json';
    window.location.href = '/api/export?table=events&format=' + fmt;
    showToast('Downloading events (' + fmt.toUpperCase() + ')...');
}
function exportTable(table, fmt) {
    fmt = fmt || 'json';
    window.location.href = '/api/export?table=' + encodeURIComponent(table) + '&format=' + fmt;
    showToast('Downloading ' + table + ' (' + fmt.toUpperCase() + ')...');
}

// ── ATTACKERS TAB ────────────────────────────────────────────────────────────
let atkOffset = 0; const atkLimit = 50; let atkData = []; let atkTotal = 0;

async function loadAttackersTab() {
    try {
        const data = await apiFetch(`/api/attackers?limit=${atkLimit}&offset=${atkOffset}`);
        atkData = data.attackers || [];
        atkTotal = data.total || 0;
        document.getElementById('atkCount').textContent = `${atkTotal} attackers`;
        const tbody = document.getElementById('atkTabBody');
        tbody.innerHTML = '';
        atkData.forEach(a => {
            const tr = document.createElement('tr');
            const svcs = (a.services||[]).map(s => `<span class="badge badge-${s}">${s}</span>`).join(' ');
            const flag = a.country_code ? a.country_code : '';
            tr.innerHTML = `<td>${ipHTML(a.ip)}</td><td title="${esc(a.country)}">${flag ? flag + ' ' : ''}${esc(a.country)}</td><td title="${esc(a.isp)}">${esc(a.city||'')}${a.city&&a.isp?' / ':''}${esc(a.isp||'')}</td><td>${svcs}</td><td style="font-weight:700;color:var(--accent)">${a.event_count}</td><td>${a.session_count}</td><td style="color:${a.auth_attempts>0?'var(--red)':'var(--text-secondary)'}">${a.auth_attempts}</td><td style="color:${a.commands>0?'var(--red)':'var(--text-secondary)'}">${a.commands}</td><td>${formatDateTime(a.first_seen)}</td><td>${formatDateTime(a.last_seen)}</td>`;
            tr.onclick = () => showAttackerDetail(a);
            tbody.appendChild(tr);
        });
        document.getElementById('atkPrev').disabled = atkOffset === 0;
        document.getElementById('atkNext').disabled = atkOffset + atkLimit >= atkTotal;
        document.getElementById('atkPageInfo').textContent = `Page ${Math.floor(atkOffset/atkLimit)+1} of ${Math.max(1, Math.ceil(atkTotal/atkLimit))}`;
    } catch(e) { showToast('Failed to load attackers: ' + e.message, 'error'); }
}
function atkPage(dir) { atkOffset = Math.max(0, atkOffset + dir * atkLimit); loadAttackersTab(); }

function showAttackerDetail(a) {
    const svcs = (a.services||[]).map(s => `<span class="badge badge-${s}">${s}</span>`).join(' ');
    let html = `
    <table style="font-size:12px;margin-bottom:16px;width:100%">
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">IP Address</td><td style="color:var(--accent);font-weight:700;font-size:14px">${esc(a.ip)}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Location</td><td>${esc(a.country)}${a.city?' / '+esc(a.city):''}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">ISP / Org</td><td>${esc(a.isp||'-')}${a.org&&a.org!==a.isp?' / '+esc(a.org):''}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">AS Number</td><td>${esc(a.as_number||'-')}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Services</td><td>${svcs||'-'}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Total Events</td><td style="font-weight:700">${a.event_count}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Sessions</td><td>${a.session_count}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Auth Attempts</td><td style="color:${a.auth_attempts>0?'var(--red)':'inherit'}">${a.auth_attempts}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Commands Exec</td><td style="color:${a.commands>0?'var(--red)':'inherit'}">${a.commands}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">First Seen</td><td>${formatDateTime(a.first_seen)}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Last Seen</td><td>${formatDateTime(a.last_seen)}</td></tr>
        <tr><td style="padding:4px 12px 4px 0;color:var(--text-secondary)">Coordinates</td><td>${a.lat||'?'}, ${a.lon||'?'}</td></tr>
    </table>
    <div style="display:flex;gap:8px">
        <button class="config-apply" onclick="filterByIP('${esc(a.ip)}')" style="background:var(--accent)">View Events</button>
        ${blockedIPs.has(a.ip)
            ? `<button class="config-apply" style="background:var(--green)" onclick="unblockIP('${esc(a.ip)}');closeModal()">Unblock IP</button>`
            : `<button class="config-apply" style="background:var(--red)" onclick="blockIP('${esc(a.ip)}');closeModal()">Block IP</button>`
        }
    </div>`;
    openModal('Attacker Profile: ' + a.ip, html);
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
let _cfgSchema = {};
let _cfgPresets = {};

async function loadConfigTab() {
    try {
        const data = await apiFetch('/api/config/full');
        _cfgSchema = data._extra_schema || {};
        _cfgPresets = data._banner_presets || {};

        // ── Global settings ──
        const globalGrid = document.getElementById('globalConfigGrid');
        globalGrid.innerHTML = '';

        // Alerts card
        const alertCard = document.createElement('div');
        alertCard.className = 'config-global-card';
        alertCard.innerHTML = `
            <h3 style="font-size:13px;margin-bottom:12px">Alerts</h3>
            <div class="config-field">
                <div class="config-toggle" onclick="this.querySelector('.toggle-switch').classList.toggle('on')">
                    <div class="toggle-switch ${data.alerts?.enabled?'on':''}" id="cfg-global-alerts-enabled"></div>
                    <span style="font-size:12px">${data.alerts?.enabled?'Enabled':'Disabled'}</span>
                </div>
            </div>
            <div class="config-field">
                <label>Webhook URL</label>
                <input type="text" id="cfg-global-webhook" value="${esc(data.alerts?.webhook_url||'')}" placeholder="https://hooks.slack.com/...">
            </div>
            <button class="config-apply" onclick="applyGlobalConfig()">Apply</button>
        `;
        globalGrid.appendChild(alertCard);

        // Log level card
        const logCard = document.createElement('div');
        logCard.className = 'config-global-card';
        logCard.innerHTML = `
            <h3 style="font-size:13px;margin-bottom:12px">Logging</h3>
            <div class="config-field">
                <label>Log Level</label>
                <select id="cfg-global-loglevel">
                    ${['DEBUG','INFO','WARNING','ERROR'].map(l =>
                        `<option value="${l}" ${data.log_level===l?'selected':''}>${l}</option>`
                    ).join('')}
                </select>
            </div>
            <div class="config-field">
                <label>Database Path</label>
                <input type="text" value="${esc(data.database_path||'')}" disabled style="opacity:0.5">
            </div>
            <button class="config-apply" onclick="applyGlobalConfig()">Apply</button>
        `;
        globalGrid.appendChild(logCard);

        // ── Service cards ──
        const grid = document.getElementById('configGrid');
        grid.innerHTML = '';
        const svcNames = ['ssh','http','ftp','smb','mysql','telnet','smtp','mongodb','vnc','redis','adb'];
        svcNames.forEach(name => {
            const svc = data[name];
            if (!svc) return;
            const schema = _cfgSchema[name] || {};
            const presets = _cfgPresets[name] || [];
            const extra = svc.extra || {};

            // Banner row with optional preset dropdown
            let bannerHtml;
            if (presets.length > 0) {
                bannerHtml = `
                    <label>Banner</label>
                    <div class="banner-row">
                        <input type="text" id="cfg-${name}-banner" value="${esc(svc.banner||'')}">
                        <select onchange="if(this.value)document.getElementById('cfg-${name}-banner').value=this.value;this.selectedIndex=0">
                            <option value="">Presets</option>
                            ${presets.map(p => `<option value="${esc(p.value)}">${esc(p.label)}</option>`).join('')}
                        </select>
                    </div>`;
            } else {
                bannerHtml = `
                    <label>Banner</label>
                    <input type="text" id="cfg-${name}-banner" value="${esc(svc.banner||'')}">`;
            }

            // Extra fields for advanced section
            const schemaKeys = Object.keys(schema);
            let advancedHtml = '';
            if (schemaKeys.length > 0) {
                let fieldsHtml = '';
                schemaKeys.forEach(key => {
                    const spec = schema[key];
                    const val = extra[key] !== undefined ? extra[key] : spec.default;
                    const displayVal = Array.isArray(val) ? val.join(',') : (val||'');
                    if (spec.type === 'textarea') {
                        fieldsHtml += `<div class="config-field">
                            <label>${esc(spec.label)}</label>
                            <textarea id="cfg-${name}-extra-${key}" placeholder="${esc(spec.placeholder||'')}">${esc(displayVal)}</textarea>
                        </div>`;
                    } else {
                        fieldsHtml += `<div class="config-field">
                            <label>${esc(spec.label)}</label>
                            <input type="text" id="cfg-${name}-extra-${key}" value="${esc(displayVal)}" placeholder="${esc(spec.placeholder||'')}">
                        </div>`;
                    }
                });
                advancedHtml = `
                    <div class="config-advanced-toggle" onclick="this.nextElementSibling.classList.toggle('open');this.querySelector('span').textContent=this.nextElementSibling.classList.contains('open')?'\\u25BE Hide advanced':'\\u25B8 Show advanced'">
                        <span>&#9656; Show advanced</span>
                    </div>
                    <div class="config-advanced">${fieldsHtml}</div>`;
            }

            const card = document.createElement('div');
            card.className = 'config-card';
            card.innerHTML = `
                <h3><span class="badge badge-${name}">${name.toUpperCase()}</span> Service</h3>
                <div class="config-field">
                    <div class="config-toggle" onclick="this.querySelector('.toggle-switch').classList.toggle('on');this.querySelector('span').textContent=this.querySelector('.toggle-switch').classList.contains('on')?'Enabled':'Disabled'">
                        <div class="toggle-switch ${svc.enabled?'on':''}" id="cfg-${name}-enabled"></div>
                        <span style="font-size:12px">${svc.enabled?'Enabled':'Disabled'}</span>
                    </div>
                </div>
                <div class="config-field">
                    <label>Port</label>
                    <input type="number" id="cfg-${name}-port" value="${svc.port}" min="1" max="65535">
                </div>
                <div class="config-field">
                    ${bannerHtml}
                </div>
                ${advancedHtml}
                <button class="config-apply" onclick="applyConfig('${name}')">Apply</button>
            `;
            grid.appendChild(card);
        });
    } catch(e) { console.error(e); showToast('Failed to load config', 'error'); }
}

async function applyConfig(name) {
    const enabled = document.getElementById('cfg-' + name + '-enabled').classList.contains('on');
    const port = parseInt(document.getElementById('cfg-' + name + '-port').value);
    const banner = document.getElementById('cfg-' + name + '-banner').value;

    // Collect extra fields
    const schema = _cfgSchema[name] || {};
    const extra = {};
    Object.keys(schema).forEach(key => {
        const el = document.getElementById('cfg-' + name + '-extra-' + key);
        if (el) extra[key] = el.value;
    });

    try {
        const body = { enabled, port, banner };
        if (Object.keys(extra).length > 0) body.extra = extra;
        const r = await fetch('/api/config/service/' + name, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        if (r.ok) {
            showToast(`${name.toUpperCase()} updated`);
            loadConfigTab();
        } else {
            const d = await r.json();
            showToast(d.error || 'Update failed', 'error');
        }
    } catch(e) { showToast('Config update failed', 'error'); }
}

async function applyGlobalConfig() {
    const alertsEnabled = document.getElementById('cfg-global-alerts-enabled').classList.contains('on');
    const webhookUrl = document.getElementById('cfg-global-webhook').value;
    const logLevel = document.getElementById('cfg-global-loglevel').value;
    try {
        const r = await fetch('/api/config/global', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alerts: { enabled: alertsEnabled, webhook_url: webhookUrl || null },
                log_level: logLevel,
            }),
        });
        if (r.ok) {
            showToast('Global config updated');
        } else {
            const d = await r.json();
            showToast(d.error || 'Update failed', 'error');
        }
    } catch(e) { showToast('Global config update failed', 'error'); }
}

async function saveConfig() {
    try {
        const r = await fetch('/api/config/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        const d = await r.json();
        if (r.ok) {
            showToast(`Config saved to ${d.path}`);
        } else {
            showToast(d.error || 'Save failed', 'error');
        }
    } catch(e) { showToast('Save failed', 'error'); }
}

function exportConfig() {
    window.location.href = '/api/config/export';
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
        const events = await apiFetch('/api/sessions/' + s.id + '/events');
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
        const sessions = await apiFetch('/api/sessions?limit=1000');
        const s = sessions.find(x => x.id === sid);
        if (s) showSessionDetail(s);
        else showToast('Session not found', 'error');
    } catch(e) { showToast('Failed to load session: ' + e.message, 'error'); }
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
        const geo = await apiFetch('/api/geo/' + encodeURIComponent(ip));
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
        const data = await apiFetch('/api/firewall/blocked');
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
        const data = await apiFetch('/api/firewall/blocked');
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
            else if (msg.type === 'config_change') { showToast('Config updated by another client'); if (document.getElementById('tab-config').classList.contains('active')) loadConfigTab(); loadActiveHoneypots(); }
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
        const config = await apiFetch('/api/config');
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
