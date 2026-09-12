"""
HunterAI Autonomous Playwright Browser Controller
=================================================
Independent Playwright Browser Worker with full DOM automation,
traffic interception (Burp Suite proxy upstream), network logging,
and evidence artifact generation.

Evidence Directory Layout:
  browser/
     pages.json
     screenshots/
     requests.jsonl
     responses.jsonl
     cookies.json
     storage.json
     console.log
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.control_plane.policy_gate import ActionCategory, ActionRequest, PolicyGate

logger = logging.getLogger("hunter_ai.browser")

try:
    from playwright.async_api import (
        Browser,
        BrowserContext,
        Page,
        Response as PlaywrightResponse,
        Request as PlaywrightRequest,
        async_playwright,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = BrowserContext = Page = None  # type: ignore


@dataclass
class NetworkEventRecord:
    url: str
    method: str
    headers: Dict[str, str]
    post_data: Optional[str] = None
    status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    timestamp: float = field(default_factory=lambda: time.time())
    resource_type: str = "document"


class PlaywrightBrowserController:
    """
    Autonomous Browser Worker for HunterAI:
    - Launches Chromium or Firefox via Playwright.
    - Proxies traffic through Burp Suite (127.0.0.1:8080) if specified.
    - Intercepts requests, responses, websockets, and console logs.
    - Exports all navigation actions into structured Evidence artifacts.
    """

    def __init__(
        self,
        output_dir: str,
        policy_gate: PolicyGate,
        proxy: Optional[str] = None,
        headless: bool = True,
        on_network_event: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.output_dir = Path(output_dir).resolve()
        self.policy_gate = policy_gate
        self.proxy = proxy
        self.headless = headless
        self.on_network_event = on_network_event

        # Subdirectories for evidence
        self.screenshots_dir = self.output_dir / "screenshots"
        self.traces_dir = self.output_dir / "traces"
        self.downloads_dir = self.output_dir / "downloads"

        self.requests_log = self.output_dir / "requests.jsonl"
        self.responses_log = self.output_dir / "responses.jsonl"
        self.pages_json = self.output_dir / "pages.json"
        self.cookies_json = self.output_dir / "cookies.json"
        self.storage_json = self.output_dir / "storage.json"
        self.console_log = self.output_dir / "console.log"

        self._pw = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._is_running = False

        self.discovered_pages: List[Dict[str, Any]] = []

    def _ensure_dirs(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.traces_dir.mkdir(parents=True, exist_ok=True)
        self.downloads_dir.mkdir(parents=True, exist_ok=True)

    async def launch(self, browser_type: str = "chromium") -> bool:
        """Launch the browser with configured proxy and event hooks"""
        if not PLAYWRIGHT_AVAILABLE:
            logger.error("Playwright is not installed in the current environment.")
            return False

        self._ensure_dirs()
        try:
            self._pw = await async_playwright().start()
            launcher = getattr(self._pw, browser_type, self._pw.chromium)

            launch_options: Dict[str, Any] = {
                "headless": self.headless,
                "args": ["--no-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"],
            }

            # Configure Burp / upstream proxy
            if self.proxy:
                launch_options["proxy"] = {"server": self.proxy}

            try:
                self._browser = await launcher.launch(**launch_options)
            except Exception as e:
                err_msg = str(e)
                if "Executable doesn't exist" in err_msg or "playwright install" in err_msg:
                    logger.info("Playwright browser binary missing; searching for system browser or provisioning...")
                    system_browsers = [
                        "/usr/bin/chromium",
                        "/usr/bin/chromium-browser",
                        "/usr/bin/google-chrome",
                        "/usr/bin/firefox-esr",
                        "/usr/bin/firefox",
                    ]
                    sys_bin = next((b for b in system_browsers if os.path.isfile(b) and os.access(b, os.X_OK)), None)
                    if sys_bin:
                        try:
                            logger.info(f"Using system browser fallback: {sys_bin}")
                            launch_options["executable_path"] = sys_bin
                            self._browser = await launcher.launch(**launch_options)
                        except Exception:
                            launch_options.pop("executable_path", None)

                    if not self._browser:
                        import subprocess
                        import sys
                        logger.info("Running automatic provisioning: 'playwright install chromium'...")
                        try:
                            subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True, timeout=180)
                            self._browser = await launcher.launch(**launch_options)
                        except Exception as inst_err:
                            logger.error(f"Playwright auto-install failed: {inst_err}")
                            raise RuntimeError("Playwright browser missing. Please run 'playwright install chromium' in your terminal.") from e
                else:
                    raise
            self._context = await self._browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )

            # Start tracing for verification reproducibility
            try:
                await self._context.tracing.start(screenshots=True, snapshots=True)
            except Exception:
                pass

            self._page = await self._context.new_page()
            self._attach_listeners(self._page)
            self._is_running = True
            logger.info(f"Playwright {browser_type.upper()} launched successfully (proxy={self.proxy})")
            return True

        except Exception as e:
            logger.error(f"Failed to launch Playwright browser: {e}")
            await self.close()
            return False

    def _attach_listeners(self, page: Page) -> None:
        """Attach network interceptors, console logging, and dialog handling"""

        async def _on_request(req: PlaywrightRequest):
            try:
                rec = {
                    "url": req.url,
                    "method": req.method,
                    "headers": dict(req.headers),
                    "resource_type": req.resource_type,
                    "timestamp": time.time(),
                }
                # Log request
                with open(self.requests_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")

                if self.on_network_event:
                    cb_res = self.on_network_event({"type": "request", "data": rec})
                    if asyncio.iscoroutine(cb_res):
                        await cb_res
            except Exception:
                pass

        async def _on_response(resp: PlaywrightResponse):
            try:
                rec = {
                    "url": resp.url,
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "timestamp": time.time(),
                }
                with open(self.responses_log, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")

                if self.on_network_event:
                    cb_res = self.on_network_event({"type": "response", "data": rec})
                    if asyncio.iscoroutine(cb_res):
                        await cb_res
            except Exception:
                pass

        def _on_console(msg):
            try:
                with open(self.console_log, "a", encoding="utf-8") as f:
                    f.write(f"[{datetime.now().isoformat()}] [{msg.type}] {msg.text}\n")
            except Exception:
                pass

        async def _on_dialog(dialog):
            logger.info(f"Browser dialog opened: [{dialog.type}] '{dialog.message}'. Dismissing safely.")
            await dialog.dismiss()

        page.on("request", _on_request)
        page.on("response", _on_response)
        page.on("console", _on_console)
        page.on("dialog", _on_dialog)

    # ── BROWSER ACTIONS ──────────────────────────────────────────────────────

    async def goto(self, url: str, wait_until: str = "domcontentloaded", timeout: int = 30000) -> Tuple[bool, str]:
        """Navigate to URL through PolicyGate check"""
        if not self._page or not self._is_running:
            return False, "Browser not running"

        # 1. Evaluate against PolicyGate
        req = ActionRequest(
            category=ActionCategory.BROWSER_NAVIGATE,
            target=url,
            url=url,
            reason="Autonomous browser navigation and attack surface discovery",
        )
        decision = self.policy_gate.evaluate(req)
        if not decision.allowed:
            return False, f"DENIED_BY_POLICY_GATE: {decision.reason}"

        # 2. Perform Navigation
        try:
            resp = await self._page.goto(url, wait_until=wait_until, timeout=timeout)
            status_code = resp.status if resp else 0
            title = await self._page.title()

            page_info = {
                "url": url,
                "title": title,
                "status": status_code,
                "timestamp": datetime.now().isoformat(),
            }
            self.discovered_pages.append(page_info)
            with open(self.pages_json, "w", encoding="utf-8") as f:
                json.dump(self.discovered_pages, f, indent=2)

            return True, f"Navigated to {url} [HTTP {status_code}] Title: '{title}'"
        except Exception as e:
            return False, f"Navigation error: {e}"

    async def click(self, selector: str, timeout: int = 5000) -> bool:
        """Click element by CSS or XPath selector"""
        if not self._page:
            return False
        try:
            await self._page.click(selector, timeout=timeout)
            return True
        except Exception as e:
            logger.debug(f"Click failed on {selector}: {e}")
            return False

    async def fill(self, selector: str, value: str, timeout: int = 5000) -> bool:
        """Fill input field with value"""
        if not self._page:
            return False
        try:
            await self._page.fill(selector, value, timeout=timeout)
            return True
        except Exception as e:
            logger.debug(f"Fill failed on {selector}: {e}")
            return False

    async def screenshot(self, name: str = "snapshot.png") -> Optional[str]:
        """Capture screenshot and save to screenshots/ evidence dir"""
        if not self._page:
            return None
        out_path = self.screenshots_dir / name
        try:
            await self._page.screenshot(path=str(out_path), full_page=True)
            return str(out_path)
        except Exception as e:
            logger.error(f"Failed to capture screenshot {name}: {e}")
            return None

    async def evaluate_js(self, expression: str) -> Any:
        """Execute arbitrary JavaScript in the page DOM context"""
        if not self._page:
            return None
        try:
            return await self._page.evaluate(expression)
        except Exception as e:
            logger.debug(f"JS evaluation error: {e}")
            return None

    async def extract_forms(self) -> List[Dict[str, Any]]:
        """Extract all HTML forms, input elements, action endpoints, and methods"""
        js = """
        () => {
            const forms = [];
            document.querySelectorAll('form').forEach(f => {
                const inputs = [];
                f.querySelectorAll('input, select, textarea').forEach(i => {
                    inputs.push({
                        name: i.name || i.id || '',
                        type: i.type || 'text',
                        value: i.value || '',
                        placeholder: i.placeholder || ''
                    });
                });
                forms.push({
                    action: f.action || window.location.href,
                    method: (f.method || 'GET').toUpperCase(),
                    id: f.id || '',
                    inputs: inputs
                });
            });
            return forms;
        }
        """
        result = await self.evaluate_js(js)
        return result or []

    async def save_storage_state(self) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """Extract and persist cookies, localStorage, and sessionStorage"""
        if not self._context or not self._page:
            return {}, []

        # 1. Cookies
        try:
            cookies = await self._context.cookies()
            with open(self.cookies_json, "w", encoding="utf-8") as f:
                json.dump(cookies, f, indent=2)
        except Exception:
            cookies = []

        # 2. Local & Session Storage
        js_storage = """
        () => {
            const local = {};
            const session = {};
            for (let i = 0; i < localStorage.length; i++) {
                const k = localStorage.key(i);
                local[k] = localStorage.getItem(k);
            }
            for (let i = 0; i < sessionStorage.length; i++) {
                const k = sessionStorage.key(i);
                session[k] = sessionStorage.getItem(k);
            }
            return { local_storage: local, session_storage: session };
        }
        """
        storage = await self.evaluate_js(js_storage) or {}
        try:
            with open(self.storage_json, "w", encoding="utf-8") as f:
                json.dump(storage, f, indent=2)
        except Exception:
            pass

        return storage, cookies

    async def close(self) -> None:
        """Gracefully stop browser, save state, and close tracing"""
        self._is_running = False
        try:
            if self._context:
                trace_file = self.traces_dir / "engagement_trace.zip"
                try:
                    await self._context.tracing.stop(path=str(trace_file))
                except Exception:
                    pass
                await self._context.close()
            if self._browser:
                await self._browser.close()
            if self._pw:
                await self._pw.stop()
        except Exception as e:
            logger.debug(f"Error closing browser: {e}")
        finally:
            self._page = None
            self._context = None
            self._browser = None
            self._pw = None
