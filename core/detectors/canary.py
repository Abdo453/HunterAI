"""Loopback out-of-band canary for SSRF verification.

The canary binds to ``127.0.0.1:0`` and records every request it receives.  An
SSRF detector asks the target to fetch the canary URL; a callback proves that
the server made the request.  Nothing leaves the machine.
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional


class _CanaryHandler(BaseHTTPRequestHandler):
    server_version = "HunterAICanary/1.0"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        pass

    def do_GET(self) -> None:  # noqa: N802
        self.server.hits.append(  # type: ignore[attr-defined]
            {
                "method": "GET",
                "path": self.path,
                "headers": dict(self.headers),
                "timestamp": time.time(),
            }
        )
        body = b"canary-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802
        self.server.hits.append(  # type: ignore[attr-defined]
            {
                "method": "HEAD",
                "path": self.path,
                "headers": dict(self.headers),
                "timestamp": time.time(),
            }
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "9")
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802
        self.server.hits.append(  # type: ignore[attr-defined]
            {
                "method": "POST",
                "path": self.path,
                "headers": dict(self.headers),
                "timestamp": time.time(),
            }
        )
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _CanaryServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.hits: List[Dict[str, Any]] = []

    def handle_error(self, request, client_address) -> None:  # noqa: D401
        pass


class LoopbackCanary:
    """Start/stop a loopback listener and wait for a matching callback."""

    def __init__(self) -> None:
        self._server = _CanaryServer(("127.0.0.1", 0), _CanaryHandler)
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def hits(self) -> List[Dict[str, Any]]:
        return list(self._server.hits)

    def clear(self) -> None:
        self._server.hits.clear()

    def start(self) -> "LoopbackCanary":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def wait_for(self, needle: str, timeout_s: float = 2.0) -> Optional[Dict[str, Any]]:
        """Return the first hit whose path/body contains ``needle``."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            for hit in self.hits:
                if needle in str(hit.get("path", "")):
                    return hit
            time.sleep(0.02)
        return None

    def __enter__(self) -> "LoopbackCanary":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
