"""
HunterAI Embedded Local & Cloud OOB Listener Server
===================================================
Provides:
1. Local lightweight OOB HTTP server for local lab / intranet Blind SSRF verification.
2. Direct integration with OOBInteractionClient.
3. Thread-safe background execution with zero external dependencies.
"""
from __future__ import annotations

import logging
import re
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional, Tuple

from core.oob.oob_client import OOBInteractionClient

logger = logging.getLogger("hunter_ai.embedded_oob")


class EmbeddedOOBRequestHandler(BaseHTTPRequestHandler):
    client: Optional[OOBInteractionClient] = None

    def log_message(self, format, *args):
        # Suppress standard logging to prevent noise
        pass

    def do_GET(self):
        self._handle_callback("GET")

    def do_POST(self):
        self._handle_callback("POST")

    def do_HEAD(self):
        self._handle_callback("HEAD")

    def _handle_callback(self, method: str):
        path = self.path
        # Look for tokens in path: /canary_<token> or /<token> (hex token)
        token_match = re.search(r"(?:canary_)?([a-fA-F0-9]{8,16})", path)
        token = token_match.group(1).lower() if token_match else ""

        remote_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        hdrs = {k: v for k, v in self.headers.items()}

        if token and self.client:
            self.client.record_incoming_interaction(
                token=token,
                protocol="HTTP",
                remote_address=remote_ip,
                raw_query_or_path=path,
                headers=hdrs,
            )
            logger.info("[EmbeddedOOB] Registered inbound callback for token '%s' from %s", token, remote_ip)

        # Respond with standard 200 OK
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-HunterAI-OOB", "Received")
        self.end_headers()
        self.wfile.write(b"OK")


class EmbeddedOOBServer:
    """
    Lightweight embedded Out-of-Band callback server.
    Runs on loopback or local subnet to catch asynchronous SSRF, Webhooks, or redirects.
    """

    def __init__(self, oob_client: OOBInteractionClient, host: str = "0.0.0.0", port: int = 0):
        self.oob_client = oob_client
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> Tuple[str, int]:
        """Starts the server in a background daemon thread."""
        if self._running and self.server:
            return self.host, self.server.server_port

        handler = EmbeddedOOBRequestHandler
        handler.client = self.oob_client
        self.server = HTTPServer((self.host, self.port), handler)
        actual_port = self.server.server_port
        self.port = actual_port

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self._running = True
        logger.info("[EmbeddedOOB] Server listening on %s:%d", self.host, self.port)
        return self.host, self.port

    def stop(self):
        """Stops the embedded server cleanly."""
        if self._running and self.server:
            self.server.shutdown()
            self.server.server_close()
            self._running = False
            logger.info("[EmbeddedOOB] Server stopped.")

    @property
    def callback_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"
