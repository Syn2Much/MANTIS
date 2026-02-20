"""HTTP honeypot with realistic login page and credential capture."""

import html
from aiohttp import web
from ..models import EventType
from ..alerts import HTTP_THREAT_PATTERNS
from . import BaseHoneypotService


def _detect_threats(data: dict) -> list[dict]:
    """Run HTTP threat patterns against event data, return list of matched threats."""
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

    threats = []
    for name, severity, regex, desc in HTTP_THREAT_PATTERNS:
        if regex.search(corpus):
            threats.append({"name": name, "severity": severity, "description": desc})
    return threats

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Portal - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
        }
        .login-box {
            background: rgba(255,255,255,0.95); border-radius: 12px;
            padding: 40px; width: 380px; box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo h1 { font-size: 24px; color: #333; }
        .logo p { color: #666; font-size: 14px; margin-top: 5px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 6px; color: #555; font-size: 14px; font-weight: 500; }
        .form-group input {
            width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 8px;
            font-size: 14px; transition: border-color 0.3s; outline: none;
        }
        .form-group input:focus { border-color: #0f3460; }
        .btn {
            width: 100%; padding: 14px; background: #0f3460; color: white; border: none;
            border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: background 0.3s;
        }
        .btn:hover { background: #1a4a7a; }
        .error { background: #fff3f3; color: #d32f2f; padding: 10px; border-radius: 6px; font-size: 13px; margin-bottom: 15px; display: none; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #999; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <h1>Admin Portal</h1>
            <p>Infrastructure Management System</p>
        </div>
        <div class="error" id="error">Invalid credentials. Please try again.</div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Enter username" required autocomplete="off">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Enter password" required>
            </div>
            <button type="submit" class="btn">Sign In</button>
        </form>
        <div class="footer">
            &copy; 2024 Infrastructure Systems &mdash; Authorized access only
        </div>
    </div>
    <script>
        if (window.location.search.includes('error=1')) {
            document.getElementById('error').style.display = 'block';
        }
    </script>
</body>
</html>"""


class HTTPHoneypot(BaseHoneypotService):
    service_name = "http"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._app = None
        self._runner = None

    async def start(self):
        port = self.config.port
        self._app = web.Application()
        self._app.router.add_get("/", self._handle_get)
        self._app.router.add_get("/{path:.*}", self._handle_get)
        self._app.router.add_post("/login", self._handle_login)
        self._app.router.add_post("/{path:.*}", self._handle_post)

        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "0.0.0.0", port)
        await site.start()
        self.logger.info("HTTP honeypot listening on port %d", port)

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()
        self.logger.info("HTTP service stopped")

    async def _handle_get(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(
            src_ip, 0, self.config.port
        )
        data = {
            "method": "GET",
            "path": request.path,
            "headers": dict(request.headers),
            "query": dict(request.query),
            "user_agent": request.headers.get("User-Agent", ""),
        }
        threats = _detect_threats(data)
        if threats:
            data["threats"] = threats
        await self._log(session, EventType.REQUEST, data)
        await self._end_session(session)
        return web.Response(text=LOGIN_PAGE, content_type="text/html")

    async def _handle_login(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)

        try:
            post_data = await request.post()
        except Exception:
            post_data = {}

        username = post_data.get("username", "")
        password = post_data.get("password", "")

        await self._log(session, EventType.AUTH_ATTEMPT, {
            "username": username,
            "password": password,
            "headers": dict(request.headers),
            "user_agent": request.headers.get("User-Agent", ""),
        })
        await self._end_session(session)

        # Always redirect back with error
        raise web.HTTPFound("/?error=1")

    async def _handle_post(self, request: web.Request) -> web.Response:
        src_ip = request.remote
        session = await self._create_session(src_ip, 0, self.config.port)

        body = ""
        try:
            body = await request.text()
        except Exception:
            pass

        data = {
            "method": "POST",
            "path": request.path,
            "headers": dict(request.headers),
            "body": body[:4096],
            "user_agent": request.headers.get("User-Agent", ""),
        }
        threats = _detect_threats(data)
        if threats:
            data["threats"] = threats
        await self._log(session, EventType.REQUEST, data)
        await self._end_session(session)
        return web.Response(text='{"error": "not found"}', status=404, content_type="application/json")
