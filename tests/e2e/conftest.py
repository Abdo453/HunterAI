"""Real-browser Playwright E2E fixtures for unified Next.js + Django ASGI stack."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from playwright.sync_api import Browser, BrowserContext, Page, sync_playwright

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
FRONTEND_DIR = REPO_ROOT / "frontend"
SCREENSHOT_DIR = Path(
    r"C:\Users\AbdelrahmanMostafa\.gemini\antigravity\brain\faa4393c-53a4-40bf-98c6-62c1c42c45d4\e2e_screenshots"
)
WORKER_SCREENSHOT_DIR = Path(
    r"C:\Users\AbdelrahmanMostafa\.gemini\antigravity\brain\967ff4b4-6f18-427e-b7bc-e0b7b25eaa1c\screenshots"
)

_STRIPPED_ENV_KEYS = (
    "GEMINI_API_KEY",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "GROQ_API_KEY",
    "TASKADE_API_KEY",
    "NVIDIA_API_KEY",
    "HUGGINGFACE_API_KEY",
    "MISTRAL_API_KEY",
    "GEMINI_MODEL",
    "OPENAI_MODEL",
    "ANTHROPIC_MODEL",
    "DEEPSEEK_MODEL",
    "GROQ_MODEL",
    "OPENROUTER_MODEL",
    "HUNTER_DEFAULT_PROVIDER",
    "HUNTER_DEFAULT_MODEL",
    "HUNTER_UNRESTRICTED",
    "HUNTER_WEB_UNRESTRICTED",
    "HUNTER_ALLOW_LOCALHOST_SCOPE",
    "HUNTER_ALLOW_PRIVATE_LAB_SCOPE",
)


def pytest_configure(config: pytest.Config) -> None:
    """Register custom E2E markers."""
    config.addinivalue_line(
        "markers",
        "live_ollama: optional browser test requiring local Ollama on 127.0.0.1:11434",
    )


def _pick_free_port(exclude: Optional[set[int]] = None) -> int:
    """Reserve a free localhost TCP port distinct from *exclude*."""
    used = exclude or set()
    for _ in range(30):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in used:
            return port
    raise RuntimeError("Failed to allocate unique ephemeral port")


def _is_port_reachable(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_http_ready(
    url: str,
    *,
    timeout_s: float,
    proc: subprocess.Popen[Any],
    log_path: Path,
    label: str,
    wait_log_substring: Optional[str] = None,
) -> None:
    """Poll *url* until HTTP < 500 or raise with tail of *log_path*."""
    deadline = time.monotonic() + timeout_s
    last_err = ""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log_tail = (
                log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
                if log_path.is_file()
                else ""
            )
            raise RuntimeError(
                f"{label} exited prematurely with code {proc.returncode}.\n{log_tail}"
            )
        if wait_log_substring and log_path.is_file():
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
            if wait_log_substring not in log_text:
                last_err = f"waiting for {wait_log_substring!r}"
                time.sleep(0.35)
                continue
        try:
            with httpx.Client(trust_env=False, timeout=15.0, follow_redirects=False) as client:
                resp = client.get(url)
            if resp.status_code < 500:
                return
            last_err = f"HTTP {resp.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(0.5)
    log_tail = (
        log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
        if log_path.is_file()
        else ""
    )
    raise TimeoutError(
        f"{label} did not become ready at {url} within {timeout_s}s ({last_err}).\n{log_tail}"
    )


def _terminate_process_tree(proc: Optional[subprocess.Popen[Any]]) -> None:
    """Cleanly terminate a subprocess and any child processes (Windows-safe)."""
    if proc is None or proc.poll() is not None:
        return
    if sys.platform.startswith("win"):
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            capture_output=True,
            check=False,
        )
    else:
        proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


class _MockVulnHandler(BaseHTTPRequestHandler):
    """Deterministic isolated vulnerable target HTTP app for E2E verification."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _handle_request(self, method: str) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            html = (
                "<!doctype html><html><head><title>VulnShop Lab</title></head>"
                "<body><h1>VulnShop</h1>"
                '<a href="/search?q=hello">Search</a>'
                '<a href="/api/orders?id=1001">Orders</a>'
                '<a href="/admin">Admin</a>'
                "</body></html>"
            ).encode("utf-8")
            self._send(200, "text/html; charset=utf-8", html)
            return

        if path == "/search":
            q = qs.get("q", [""])[0]
            # Deliberately unescaped reflection for mock target validation.
            html = f"<!doctype html><html><body><div>Results for: {q}</div></body></html>".encode(
                "utf-8"
            )
            self._send(200, "text/html; charset=utf-8", html)
            return

        if path == "/api/orders":
            order_id = qs.get("id", ["1001"])[0]
            lowered = order_id.lower()
            if "'" in order_id or '"' in order_id or " or " in lowered or "union " in lowered:
                payload = json.dumps(
                    {"error": "SQLite syntax error near token", "query_id": order_id}
                ).encode("utf-8")
                self._send(500, "application/json", payload)
                return
            orders = {
                "1001": {"order_id": 1001, "owner": "alice", "total_usd": 42.5, "method": method},
                "1002": {"order_id": 1002, "owner": "bob", "total_usd": 199.0, "secret_note": "IDOR_EXPOSED"},
            }
            if order_id in orders:
                self._send(200, "application/json", json.dumps(orders[order_id]).encode("utf-8"))
            else:
                self._send(404, "application/json", b'{"error":"order not found"}')
            return

        if path == "/admin":
            override = (self.headers.get("X-Original-URL") or "").strip()
            if override == "/admin":
                self._send(200, "application/json", b'{"admin": true, "bypass": "header"}')
            else:
                self._send(403, "application/json", b'{"error":"Forbidden"}')
            return

        self._send(404, "application/json", b'{"error":"Not Found"}')

    def do_GET(self) -> None:  # noqa: N802
        self._handle_request("GET")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or "0")
        if length > 0:
            self.rfile.read(length)
        self._handle_request("POST")


@dataclass
class E2EStack:
    """Running Django ASGI + Next.js 15 + Mock Vulnerable HTTP Server stack."""

    api_port: int
    ui_port: int
    vuln_port: int
    artex_port: int
    api_base: str
    ui_base: str
    vuln_base: str
    tmp_dir: Path
    db_path: Path
    attachments_dir: Path
    env: Dict[str, str]


@dataclass
class PageDiagnostics:
    """Collected runtime browser diagnostics asserted clean at teardown."""

    page_errors: List[str] = field(default_factory=list)
    console_errors: List[str] = field(default_factory=list)
    http_5xx: List[str] = field(default_factory=list)
    broken_assets_404: List[str] = field(default_factory=list)
    http_4xx: List[str] = field(default_factory=list)
    external_requests: List[str] = field(default_factory=list)
    allowed_error_substrings: List[str] = field(default_factory=list)

    @contextmanager
    def allow_expected_console_errors(
        self,
        *substrings: str,
        require_at_least_one: bool = False,
    ) -> Generator[None, None, None]:
        """Allow matching console.error entries ONLY within this scoped block."""
        start_idx = len(self.console_errors)
        try:
            yield
        finally:
            tail = self.console_errors[start_idx:]
            kept_tail: List[str] = []
            matched = 0
            for msg in tail:
                if any(tok in msg for tok in substrings):
                    matched += 1
                else:
                    kept_tail.append(msg)
            self.console_errors[start_idx:] = kept_tail
            if require_at_least_one:
                assert matched > 0, (
                    f"Expected at least one browser console.error matching {substrings!r}, "
                    f"saw {tail!r}"
                )

    def assert_clean(self) -> None:
        assert self.page_errors == [], f"Uncaught pageerror(s): {self.page_errors}"
        filtered_console = [
            msg
            for msg in self.console_errors
            if not any(tok in msg for tok in self.allowed_error_substrings)
        ]
        assert filtered_console == [], (
            f"Browser console.error(s): {filtered_console} | "
            f"http_5xx={self.http_5xx} | http_4xx={self.http_4xx} | 404={self.broken_assets_404}"
        )
        assert self.http_5xx == [], f"HTTP 5xx response(s): {self.http_5xx}"
        assert self.broken_assets_404 == [], f"Broken static/page 404(s): {self.broken_assets_404}"
        assert self.external_requests == [], f"External CDN request(s): {self.external_requests}"


@pytest.fixture(scope="session")
def e2e_stack(tmp_path_factory: pytest.TempPathFactory) -> Generator[E2EStack, None, None]:
    """Boot uvicorn (Django ASGI), Next.js dev server, and mock vuln HTTP server."""
    if not (FRONTEND_DIR / "node_modules").exists():
        raise RuntimeError(
            f"Missing {FRONTEND_DIR / 'node_modules'}. Install or link frontend dependencies before running E2E."
        )

    used_ports: set[int] = set()
    api_port = _pick_free_port(used_ports)
    used_ports.add(api_port)
    ui_port = _pick_free_port(used_ports)
    used_ports.add(ui_port)
    vuln_port = _pick_free_port(used_ports)
    used_ports.add(vuln_port)
    artex_port = _pick_free_port(used_ports)
    used_ports.add(artex_port)

    tmp_dir = tmp_path_factory.mktemp("hunter_e2e_stack")
    db_path = tmp_dir / "platform.sqlite3"
    attachments_dir = tmp_dir / "attachments"
    attachments_dir.mkdir(parents=True, exist_ok=True)

    api_base = f"http://127.0.0.1:{api_port}"
    ui_base = f"http://127.0.0.1:{ui_port}"
    vuln_base = f"http://127.0.0.1:{vuln_port}"

    env = os.environ.copy()
    for key in _STRIPPED_ENV_KEYS:
        env.pop(key, None)

    env.update(
        {
            "HUNTER_PIPELINE_PHASE_DELAY_S": "5.0",
            "HUNTER_PLATFORM_DB_PATH": str(db_path),
            "HUNTER_COPILOT_ATTACHMENTS_DIR": str(attachments_dir),
            "HUNTERAI_TRUSTED_ORIGINS": (
                f"http://127.0.0.1:{ui_port},http://localhost:{ui_port},http://127.0.0.1:{api_port}"
            ),
            "HUNTERAI_FRONTEND_URL": ui_base,
            "HUNTER_API_BASE": api_base,
            "NEXT_PUBLIC_HUNTER_API_BASE": api_base,
            "OLLAMA_HOST": "http://127.0.0.1:59999",
            "LM_STUDIO_HOST": "http://127.0.0.1:59998",
            "HUNTER_LLM_POLICY": "cloud_only",
            "HUNTERAI_ARTEX_URL": f"http://127.0.0.1:{artex_port}",
            "HUNTERAI_DJANGO_SECRET": "e2e-playwright-django-secret-key-32b",
            "HUNTERAI_POLICY_SECRET": "e2e-playwright-policy-secret-key-32b",
            "DJANGO_SETTINGS_MODULE": "hunter_backend.settings",
            "PYTHONUNBUFFERED": "1",
        }
    )

    vuln_server = ThreadingHTTPServer(("127.0.0.1", vuln_port), _MockVulnHandler)
    vuln_thread = threading.Thread(target=vuln_server.serve_forever, daemon=True)
    vuln_thread.start()

    uvicorn_log = tmp_dir / "uvicorn.log"
    next_log = tmp_dir / "next_dev.log"
    uvicorn_proc: Optional[subprocess.Popen[Any]] = None
    next_proc: Optional[subprocess.Popen[Any]] = None

    try:
        with uvicorn_log.open("wb") as ulog:
            uvicorn_proc = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "hunter_backend.asgi:application",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(api_port),
                    "--workers",
                    "1",
                ],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=ulog,
                stderr=subprocess.STDOUT,
            )

        _wait_http_ready(
            f"{api_base}/api/csrf",
            timeout_s=45.0,
            proc=uvicorn_proc,
            log_path=uvicorn_log,
            label="Django ASGI (uvicorn)",
        )

        next_cache_dir = FRONTEND_DIR / ".next"
        if next_cache_dir.exists():
            source_mtimes = [
                p.stat().st_mtime
                for root_name in ("app", "components", "lib")
                for p in (FRONTEND_DIR / root_name).rglob("*")
                if p.is_file()
            ]
            newest_src = max(source_mtimes, default=0.0)
            if (next_cache_dir / "BUILD_ID").exists() or newest_src > next_cache_dir.stat().st_mtime:
                shutil.rmtree(next_cache_dir, ignore_errors=True)

        npm_bin = "npm.cmd" if sys.platform.startswith("win") else shutil.which("npm") or "npm"
        with next_log.open("wb") as nlog:
            next_proc = subprocess.Popen(
                [npm_bin, "run", "dev", "--", "-p", str(ui_port)],
                cwd=str(FRONTEND_DIR),
                env=env,
                stdout=nlog,
                stderr=subprocess.STDOUT,
            )

        _wait_http_ready(
            f"{ui_base}/",
            timeout_s=90.0,
            proc=next_proc,
            log_path=next_log,
            label="Next.js 15 dev server",
            wait_log_substring="Ready in",
        )

        yield E2EStack(
            api_port=api_port,
            ui_port=ui_port,
            vuln_port=vuln_port,
            artex_port=artex_port,
            api_base=api_base,
            ui_base=ui_base,
            vuln_base=vuln_base,
            tmp_dir=tmp_dir,
            db_path=db_path,
            attachments_dir=attachments_dir,
            env=env,
        )
    finally:
        _terminate_process_tree(next_proc)
        _terminate_process_tree(uvicorn_proc)
        vuln_server.shutdown()
        vuln_server.server_close()


@pytest.fixture(scope="session")
def chromium_browser() -> Generator[Browser, None, None]:
    """Launch a single headless Chromium browser instance for the E2E session."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            yield browser
        finally:
            browser.close()


@pytest.fixture()
def e2e_page(
    chromium_browser: Browser,
    e2e_stack: E2EStack,
) -> Generator[tuple[Page, PageDiagnostics], None, None]:
    """Provide an isolated BrowserContext + Page with zero-error network/console guards."""
    context: BrowserContext = chromium_browser.new_context(
        viewport={"width": 1440, "height": 900},
        accept_downloads=True,
    )
    page = context.new_page()
    page.set_default_timeout(20000)

    diag = PageDiagnostics()
    allowed_hosts = {"127.0.0.1", "localhost", "[::1]"}

    def _on_pageerror(err: Any) -> None:
        diag.page_errors.append(str(err))

    def _on_console(msg: Any) -> None:
        if msg.type == "error":
            diag.console_errors.append(msg.text)

    def _on_request(req: Any) -> None:
        url = req.url
        if url.startswith(("data:", "blob:", "about:")):
            return
        host = (urlparse(url).hostname or "").lower()
        if host and host not in allowed_hosts:
            diag.external_requests.append(url)

    def _on_response(resp: Any) -> None:
        url = resp.url
        status = resp.status
        if status >= 500:
            diag.http_5xx.append(f"{status} {url}")
            return
        if status == 404:
            parsed = urlparse(url)
            path = parsed.path
            # Fail on broken UI routes, Next bundles, or static/vendor assets
            if (
                not path.startswith("/api/")
                or path.startswith("/_next/")
                or path.startswith("/vendor/")
                or path.startswith("/static/")
            ):
                diag.broken_assets_404.append(f"404 {url}")
            else:
                diag.http_4xx.append(f"404 {url}")
        elif status >= 400:
            diag.http_4xx.append(f"{status} {url}")

    page.on("pageerror", _on_pageerror)
    page.on("console", _on_console)
    page.on("request", _on_request)
    page.on("response", _on_response)

    try:
        yield page, diag
        diag.assert_clean()
    finally:
        context.close()


def save_verification_screenshot(page: Page, filename: str) -> Path:
    """Capture full-page screenshot in both coordinator and worker brain directories."""
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    dest = SCREENSHOT_DIR / filename
    page.screenshot(path=str(dest), full_page=True)
    WORKER_SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    shutil.copy2(dest, WORKER_SCREENSHOT_DIR / filename)
    return dest
