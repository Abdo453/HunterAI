"""
Stateful Browser Session
========================
Maintains an active, stateful browser context (Playwright / HTTP fallback):
- Preserves cookies, localStorage, sessionStorage, and auth tokens
- Intercepts and records all network activity (Fetch/XHR/WebSockets)
- Supports interactive DOM actions (click, fill, navigate)
- Persists session artifacts to data/scans/<target>/browser/
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("hunter_ai.browser_session")

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
class InterceptedRequest:
    url: str
    method: str
    resource_type: str
    headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None
    status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: time.time())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StatefulBrowserSession:
    """Manages continuous, persistent browser lifecycle across exploration"""

    def __init__(
        self,
        target_url: str,
        output_dir: Optional[Path] = None,
        headless: bool = True,
        proxy: Optional[str] = None,
        on_network_event: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ):
        self.target_url = target_url
        self.base_host = (urlparse(target_url).hostname or "target").lower()
        self.output_dir = output_dir or Path(f"data/scans/{self.base_host.replace('.', '_')}/browser")
        self.headless = headless
        self.proxy = proxy
        self.on_network_event = on_network_event

        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "screenshots").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "dom").mkdir(parents=True, exist_ok=True)

        self._pw = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._is_playwright_active = False

        # In-memory session state
        self.cookies: List[Dict[str, Any]] = []
        self.local_storage: Dict[str, str] = {}
        self.session_storage: Dict[str, str] = {}
        self.network_history: List[InterceptedRequest] = []
        self.visited_urls: Set[str] = set()
        self.discovered_urls: Set[str] = set()

        # HTTP fallback client
        self._http_client = httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            timeout=15.0,
            headers={"User-Agent": "HunterAI-Browser/2.0 (Security Explorer)"}
        )

    async def start(self) -> bool:
        """Attempts to launch Playwright browser, gracefully falling back to HTTP"""
        if PLAYWRIGHT_AVAILABLE and not os.getenv("DISABLE_PLAYWRIGHT"):
            try:
                self._pw = await async_playwright().start()
                launch_args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
                proxy_dict = {"server": self.proxy} if self.proxy else None

                self._browser = await self._pw.chromium.launch(
                    headless=self.headless,
                    args=launch_args,
                    proxy=proxy_dict
                )
                self._context = await self._browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 800}
                )
                self._page = await self._context.new_page()

                # Setup network interception
                self._page.on("request", self._handle_pw_request)
                self._page.on("response", self._handle_pw_response)

                self._is_playwright_active = True
                logger.info("StatefulBrowserSession: Playwright Chromium worker active.")
                return True
            except Exception as e:
                logger.debug(f"Playwright start failed ({e}), using async HTTP fallback.")

        self._is_playwright_active = False
        logger.info("StatefulBrowserSession: Running in HTTP-augmented exploration mode.")
        return True

    def _handle_pw_request(self, request: PlaywrightRequest) -> None:
        try:
            req_data = InterceptedRequest(
                url=request.url,
                method=request.method,
                resource_type=request.resource_type,
                headers=dict(request.headers),
                post_data=request.post_data,
            )
            self.network_history.append(req_data)
            if self.on_network_event:
                self.on_network_event(req_data.to_dict())
        except Exception:
            pass

    async def _handle_pw_response(self, response: PlaywrightResponse) -> None:
        try:
            req_url = response.url
            for r in reversed(self.network_history):
                if r.url == req_url and r.status is None:
                    r.status = response.status
                    r.response_headers = dict(response.headers)
                    break
        except Exception:
            pass

    async def navigate(self, url: str) -> Tuple[str, int, Dict[str, str]]:
        """Navigates to URL, waiting for network idle / DOM loaded"""
        self.visited_urls.add(url)
        if self._is_playwright_active and self._page:
            try:
                resp = await self._page.goto(url, wait_until="domcontentloaded", timeout=20000)
                status = resp.status if resp else 200
                headers = dict(resp.headers) if resp else {}
                content = await self._page.content()
                await self._extract_storage()
                return content, status, headers
            except Exception as e:
                logger.debug(f"Playwright navigation failed ({e}), falling back to HTTP client.")

        # HTTP Fallback
        try:
            resp = await self._http_client.get(url)
            content = resp.text
            status = resp.status_code
            headers = dict(resp.headers)
            # Record network event
            ev = InterceptedRequest(
                url=url,
                method="GET",
                resource_type="document",
                headers=dict(headers),
                status=status
            )
            self.network_history.append(ev)
            return content, status, headers
        except Exception as e:
            logger.warning(f"Session HTTP navigation error: {e}")
            return "", 0, {}

    async def interact(self, selector: str, action: str = "click") -> bool:
        """Executes safe interaction on page"""
        if self._is_playwright_active and self._page:
            try:
                elem = self._page.locator(selector).first
                if await elem.is_visible():
                    if action == "click":
                        await elem.click(timeout=3000)
                    elif action == "hover":
                        await elem.hover(timeout=3000)
                    await asyncio.sleep(0.5)
                    return True
            except Exception as e:
                logger.debug(f"Interaction error on {selector}: {e}")
        return False

    async def get_dom(self) -> str:
        if self._is_playwright_active and self._page:
            try:
                return await self._page.content()
            except Exception:
                pass
        return ""

    async def take_screenshot(self, name: str) -> Optional[str]:
        if self._is_playwright_active and self._page:
            try:
                ss_path = self.output_dir / "screenshots" / f"{name}.png"
                await self._page.screenshot(path=str(ss_path), full_page=False)
                return str(ss_path)
            except Exception:
                pass
        return None

    async def _extract_storage(self) -> None:
        if self._is_playwright_active and self._context and self._page:
            try:
                self.cookies = await self._context.cookies()
                ls = await self._page.evaluate("() => JSON.stringify(window.localStorage || {})")
                ss = await self._page.evaluate("() => JSON.stringify(window.sessionStorage || {})")
                self.local_storage = json.loads(ls) if ls else {}
                self.session_storage = json.loads(ss) if ss else {}
            except Exception:
                pass

    def save_artifacts(self) -> None:
        """Persists all session artifacts to output_dir"""
        try:
            with open(self.output_dir / "session.json", "w", encoding="utf-8") as f:
                json.dump({
                    "target_url": self.target_url,
                    "visited_urls": list(self.visited_urls),
                    "discovered_urls": list(self.discovered_urls),
                    "total_network_requests": len(self.network_history),
                    "cookies_count": len(self.cookies),
                    "playwright_active": self._is_playwright_active,
                }, f, indent=2)

            with open(self.output_dir / "cookies.json", "w", encoding="utf-8") as f:
                json.dump(self.cookies, f, indent=2)

            with open(self.output_dir / "storage.json", "w", encoding="utf-8") as f:
                json.dump({
                    "localStorage": self.local_storage,
                    "sessionStorage": self.session_storage
                }, f, indent=2)

            with open(self.output_dir / "network.jsonl", "w", encoding="utf-8") as f:
                for req in self.network_history:
                    f.write(json.dumps(req.to_dict()) + "\n")
        except Exception as e:
            logger.warning(f"Failed to persist session artifacts: {e}")

    async def close(self) -> None:
        """Gracefully closes browser and HTTP client"""
        self.save_artifacts()
        if self._is_playwright_active:
            try:
                if self._context:
                    await self._context.close()
                if self._browser:
                    await self._browser.close()
                if self._pw:
                    await self._pw.stop()
            except Exception:
                pass
        await self._http_client.aclose()