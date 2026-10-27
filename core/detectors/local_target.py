"""A loopback-only fake target for hermetic detector tests and demos.

The server binds to ``127.0.0.1`` on an ephemeral port and exposes both
vulnerable and safe variants of three endpoints:

===========================  ==============================================
Endpoint                     Behaviour
===========================  ==============================================
``/search?q=``               boolean SQLi: TRUE -> 2 items, FALSE -> 0
``/search/safe?q=``          ignores the input; no differential
``/echo?name=``              reflects ``name`` unescaped (XSS)
``/echo/safe?name=``         HTML-escapes ``name``
``/profile?id=``             any authenticated user reads any profile
``/profile/safe?id=``        only the owner reads the profile
``/health``                  plain ``ok``
===========================  ==============================================

Every request is logged (method, path, headers) so tests can prove that only
``GET`` was sent and that a policy denial happened before the server was hit.
"""
from __future__ import annotations

import html
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlparse

ALICE_CANARY = "HNT-CANARY-ALICE-7f3a"
BOB_CANARY = "HNT-CANARY-BOB-9c2e"

_PROFILES: Dict[str, Dict[str, Any]] = {
    "1": {"id": 1, "owner": "alice", "secret": ALICE_CANARY},
    "2": {"id": 2, "owner": "bob", "secret": BOB_CANARY},
}

_TRUE_SQL = "results: 2 items (alpha, beta)"
_FALSE_SQL = "results: 0 items"


class _Handler(BaseHTTPRequestHandler):
    server_version = "HunterAIFakeTarget/1.0"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        pass

    # -- helpers -----------------------------------------------------------

    def _record(self) -> None:
        self.server.requests.append(  # type: ignore[attr-defined]
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
            }
        )

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Lab", "hunterai-fake-target")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _send_redirect(self, status: int, location: str) -> None:
        self.send_response(status)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("X-Lab", "hunterai-fake-target")
        self.end_headers()

    def _not_allowed(self) -> None:
        self._record()
        self._send(405, "method not allowed", "text/plain; charset=utf-8")

    do_POST = _not_allowed
    do_PUT = _not_allowed
    do_PATCH = _not_allowed
    do_DELETE = _not_allowed

    # -- routes ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        self._record()
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))

        if path == "/health":
            self._send(200, "ok", "text/plain; charset=utf-8")
            return

        if path == "/search":
            value = query.get("q", "")
            is_false = "' AND '1'='2" in value or "' AND '2'='3" in value
            self._send(200, _FALSE_SQL if is_false else _TRUE_SQL, "text/plain; charset=utf-8")
            return

        if path == "/search/safe":
            self._send(200, _TRUE_SQL, "text/plain; charset=utf-8")
            return

        if path == "/echo":
            name = query.get("name", "")
            self._send(200, f"<html><body>Hello, {name}</body></html>")
            return

        if path == "/echo/safe":
            name = html.escape(query.get("name", ""), quote=True)
            self._send(200, f"<html><body>Hello, {name}</body></html>")
            return

        if path in {"/fetch", "/fetch/safe"}:
            if path == "/fetch/safe":
                self._send(400, "url not allowed", "text/plain; charset=utf-8")
                return
            target_url = query.get("url", "")
            parsed_target = urlparse(target_url)
            if parsed_target.hostname not in {"127.0.0.1", "localhost"}:
                self._send(
                    400,
                    "lab only allows loopback callbacks",
                    "text/plain; charset=utf-8",
                )
                return
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(target_url, timeout=2) as response:
                    body = response.read(4096).decode("utf-8", errors="replace")
                self._send(200, body or "fetched", "text/plain; charset=utf-8")
            except Exception as exc:
                self._send(502, f"fetch failed: {exc}", "text/plain; charset=utf-8")
            return

        if path in {"/redirect", "/redirect/safe"}:
            next_url = query.get("next", "/home")
            if path == "/redirect/safe":
                if next_url.startswith("/") and not next_url.startswith("//"):
                    self._send_redirect(302, next_url)
                else:
                    self._send(400, "external redirect blocked", "text/plain; charset=utf-8")
                return
            self._send_redirect(302, next_url)
            return

        if path in {"/profile", "/profile/safe"}:
            user = self.headers.get("X-User", "")
            resource_id = query.get("id", "1")
            profile = _PROFILES.get(resource_id)
            if profile is None:
                self._send(404, "not found", "text/plain; charset=utf-8")
                return
            if not user:
                self._send(401, "authentication required", "text/plain; charset=utf-8")
                return
            if path == "/profile/safe" and user != profile["owner"]:
                self._send(403, "forbidden", "text/plain; charset=utf-8")
                return
            self._send(200, json.dumps(profile), "application/json; charset=utf-8")
            return

        self._send(404, "not found", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self._record()
        self._send(200, "ok", "text/plain; charset=utf-8")


class _FakeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.requests: List[Dict[str, Any]] = []

    def handle_error(self, request, client_address) -> None:  # noqa: D401
        pass


class LocalFakeTarget:
    """Context-managed loopback server."""

    def __init__(self) -> None:
        self._server = _FakeServer(("127.0.0.1", 0), _Handler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def requests(self) -> List[Dict[str, Any]]:
        return list(self._server.requests)

    def clear_requests(self) -> None:
        self._server.requests.clear()

    def start(self) -> "LocalFakeTarget":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> "LocalFakeTarget":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
