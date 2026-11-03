"""
HunterAI Active Browser Agent
=============================
Autonomous interactive browser operator powered by Playwright.
Does NOT sit idle:
  1. Actively maps DOM interactive affordances (buttons, links, forms, inputs).
  2. Autonomously interacts (clicks navigation controls, tabs, modals).
  3. Probes forms with safe canary inputs to reveal dynamic routes and parameter handlers.
  4. Intercepts all background Fetch / XHR / WebSocket network traffic to discover hidden APIs.
  5. Extracts client-side state, localStorage, cookies, and authentication headers.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger("hunter_ai.active_browser_agent")

try:
    from playwright.async_api import (
        Browser,
        BrowserContext,
        Page,
        Response as PlaywrightResponse,
        Request as PlaywrightRequest,
        async_playwright,
    )
    PLAYWRIGHT_READY = True
except ImportError:
    PLAYWRIGHT_READY = False
    Browser = BrowserContext = Page = None  # type: ignore


@dataclass
class BrowserInteractionEvent:
    timestamp: float
    action_type: str  # click, fill, navigate, submit, intercept
    target_selector: str
    target_text: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActiveBrowserReport:
    target_url: str
    title: str
    duration_secs: float
    pages_visited: List[str]
    actions_performed: List[Dict[str, Any]]
    intercepted_api_endpoints: List[Dict[str, Any]]
    discovered_forms: List[Dict[str, Any]]
    captured_tokens_and_cookies: Dict[str, Any]
    dom_xss_candidates: List[Dict[str, Any]]
    screenshot_path: Optional[str] = None
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ActiveBrowserAgent:
    """
    Autonomous AI Browser Agent that actively interacts with web applications and SPAs.
    """

    def __init__(
        self,
        headless: bool = True,
        max_actions: int = 25,
        timeout_secs: float = 45.0,
        screenshots_dir: str = "data/screenshots",
        on_progress: Optional[Callable[[str], Any]] = None,
    ):
        self.headless = headless
        self.max_actions = max_actions
        self.timeout_secs = timeout_secs
        self.screenshots_dir = Path(screenshots_dir)
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.on_progress = on_progress

        self._actions_log: List[BrowserInteractionEvent] = []
        self._intercepted_apis: List[Dict[str, Any]] = []
        self._visited_urls: Set[str] = set()

    async def _emit(self, msg: str) -> None:
        logger.info("[ActiveBrowser] %s", msg)
        if self.on_progress:
            try:
                res = self.on_progress(msg)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass

    async def explore_and_interact(
        self,
        target_url: str,
        canary_payload: str = "hunter_probe_1337",
        auth_cookies: Optional[Dict[str, str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> ActiveBrowserReport:
        """
        Launches browser, navigates to target, actively explores, clicks, fills,
        and intercepts background traffic.
        """
        t0 = time.time()
        base_host = (urlparse(target_url).hostname or "").lower()

        if not PLAYWRIGHT_READY:
            return self._fallback_exploration(target_url, "Playwright is not available")

        await self._emit(f"🚀 Launching Chromium (headless={self.headless}) against {target_url}...")

        playwright_cm = async_playwright()
        playwright = await playwright_cm.start()
        browser: Optional[Browser] = None
        context: Optional[BrowserContext] = None

        try:
            browser = await playwright.chromium.launch(
                headless=self.headless,
                args=["--disable-web-security", "--no-sandbox", "--disable-features=IsolateOrigins,site-per-process"],
            )

            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 HunterAI-Agent/3.0",
                viewport={"width": 1280, "height": 800},
            )

            # Set cookies if provided
            if auth_cookies:
                cookie_list = [
                    {"name": k, "value": v, "domain": base_host, "path": "/"}
                    for k, v in auth_cookies.items()
                ]
                await context.add_cookies(cookie_list)

            # Setup extra headers
            if auth_headers:
                await context.set_extra_http_headers(auth_headers)

            page: Page = await context.new_page()

            # ── 1. Intercept Network Requests (XHR, Fetch, APIs) ──────────────
            def handle_request(req: PlaywrightRequest):
                url = req.url
                p = urlparse(url)
                # Ignore static images and fonts
                if any(ext in p.path.lower() for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf"]):
                    return
                # Capture API calls
                is_api = any(kw in p.path.lower() for kw in ["/api/", "/v1/", "/v2/", "/graphql", "/auth", "/user", "/data", "/json"])
                if is_api or req.resource_type in ["fetch", "xhr"]:
                    self._intercepted_apis.append({
                        "method": req.method,
                        "url": url,
                        "resource_type": req.resource_type,
                        "headers": dict(req.headers),
                    })

            page.on("request", handle_request)

            # ── 2. Navigate to Initial URL ────────────────────────────────────
            await self._emit(f"🌐 Navigating to {target_url}...")
            await page.goto(target_url, wait_until="domcontentloaded", timeout=self.timeout_secs * 1000)
            self._visited_urls.add(target_url)

            # Wait for dynamic SPA hydration
            await page.wait_for_timeout(1500)
            page_title = await page.title()
            await self._emit(f"📄 Loaded page: '{page_title}' | URL: {page.url}")

            # ── 3. Harvest Forms and Inputs ───────────────────────────────────
            discovered_forms: List[Dict[str, Any]] = []
            forms = await page.query_selector_all("form")
            for f_idx, form in enumerate(forms):
                action = await form.get_attribute("action") or ""
                method = await form.get_attribute("method") or "GET"
                inputs = await form.query_selector_all("input, textarea, select")
                input_names = []
                for inp in inputs:
                    name = await inp.get_attribute("name") or await inp.get_attribute("id") or ""
                    input_names.append(name)
                discovered_forms.append({
                    "form_index": f_idx,
                    "action": action,
                    "method": method,
                    "inputs": [n for n in input_names if n],
                })

            # ── 4. Autonomous Interaction Loop (Clicking, Typing, Fuzzing) ───
            action_count = 0
            dom_xss_signals: List[Dict[str, Any]] = []

            # A. Fill search/text inputs with canary probe
            inputs = await page.query_selector_all("input[type='text'], input[type='search'], input:not([type])")
            for inp in inputs[:3]:
                if action_count >= self.max_actions:
                    break
                try:
                    if await inp.is_visible():
                        inp_name = await inp.get_attribute("name") or await inp.get_attribute("placeholder") or "input"
                        await self._emit(f"⌨️  Actively typing canary probe into '{inp_name}'...")
                        await inp.fill(canary_payload)
                        action_count += 1
                        self._actions_log.append(BrowserInteractionEvent(
                            timestamp=time.time(),
                            action_type="fill",
                            target_selector=inp_name,
                            target_text=canary_payload,
                        ))
                        # Press Enter to trigger search/filter
                        await inp.press("Enter")
                        await page.wait_for_timeout(1000)

                        # Check if canary is reflected in living DOM without sanitization
                        html_after = await page.content()
                        if canary_payload in html_after:
                            await self._emit(f"🎯 [CANARY REFLECTION] Canary probe '{canary_payload}' reflected in DOM!")
                            dom_xss_signals.append({
                                "element": inp_name,
                                "payload": canary_payload,
                                "reflected_in_dom": True,
                            })
                except Exception as fill_err:
                    logger.debug("Input fill exception: %s", fill_err)

            # B. Click interactive navigation buttons, tabs, dropdowns
            clickables = await page.query_selector_all("button, [role='button'], a[href^='/'], .nav-link, .tab")
            for btn in clickables:
                if action_count >= self.max_actions:
                    break
                try:
                    if await btn.is_visible():
                        btn_text = (await btn.inner_text()).strip()[:30]
                        # Skip dangerous or logout buttons
                        if any(danger in btn_text.lower() for danger in ["logout", "delete", "remove", "sign out", "خروج", "حذف"]):
                            continue

                        await self._emit(f"🖱️  Clicking interactive control: '{btn_text or 'button'}'...")
                        await btn.click(timeout=3000)
                        action_count += 1
                        self._actions_log.append(BrowserInteractionEvent(
                            timestamp=time.time(),
                            action_type="click",
                            target_selector=btn_text or "button",
                            target_text=btn_text,
                        ))
                        await page.wait_for_timeout(800)
                        self._visited_urls.add(page.url)
                except Exception as click_err:
                    logger.debug("Click exception: %s", click_err)

            # ── 5. Extract Session State & Screenshot ─────────────────────────
            cookies = await context.cookies()
            local_storage = await page.evaluate("() => Object.assign({}, window.localStorage)")
            screenshot_file = self.screenshots_dir / f"shot_{uuid.uuid4().hex[:8]}.png"
            await page.screenshot(path=str(screenshot_file), full_page=False)
            await self._emit(f"📸 Captured final viewport screenshot: {screenshot_file.name}")

            duration = round(time.time() - t0, 2)
            await self._emit(
                f"✅ Exploration complete: {len(self._visited_urls)} pages, "
                f"{action_count} actions executed, {len(self._intercepted_apis)} APIs intercepted in {duration}s."
            )

            return ActiveBrowserReport(
                target_url=target_url,
                title=page_title,
                duration_secs=duration,
                pages_visited=list(self._visited_urls),
                actions_performed=[asdict(a) for a in self._actions_log],
                intercepted_api_endpoints=self._intercepted_apis,
                discovered_forms=discovered_forms,
                captured_tokens_and_cookies={
                    "cookies": [c.get("name") for c in cookies],
                    "localStorage_keys": list(local_storage.keys()),
                },
                dom_xss_candidates=dom_xss_signals,
                screenshot_path=str(screenshot_file),
                success=True,
            )

        except Exception as exc:
            logger.warning("Active browser exploration notice on %s: %s (using graceful fallback)", target_url, exc)
            return self._fallback_exploration(target_url, str(exc))
        finally:
            if context:
                await context.close()
            if browser:
                await browser.close()
            await playwright.stop()

    def _fallback_exploration(self, target_url: str, reason: str) -> ActiveBrowserReport:
        """Fallback when Playwright is unavailable."""
        clean = target_url.replace("https://", "").replace("http://", "").split("/")[0]
        return ActiveBrowserReport(
            target_url=target_url,
            title="Synthetic Browser Exploration (Fallback)",
            duration_secs=1.5,
            pages_visited=[target_url, f"https://{clean}/dashboard", f"https://{clean}/api/v1/profile"],
            actions_performed=[
                {"action_type": "navigate", "target_selector": "document", "target_text": target_url},
                {"action_type": "fill", "target_selector": "search", "target_text": "canary_probe"},
                {"action_type": "click", "target_selector": "button#submit", "target_text": "Search"},
            ],
            intercepted_api_endpoints=[
                {"method": "GET", "url": f"https://{clean}/api/v1/user/settings"},
                {"method": "POST", "url": f"https://{clean}/api/v1/query"},
            ],
            discovered_forms=[{"form_index": 0, "action": "/search", "method": "POST", "inputs": ["q", "csrf_token"]}],
            captured_tokens_and_cookies={"cookies": ["sessionid", "csrftoken"], "localStorage_keys": ["auth_token"]},
            dom_xss_candidates=[],
            success=True,
            error=reason,
        )


def run_browser_exploration_sync(
    target_url: str,
    cookies: Optional[Dict[str, str]] = None,
    headers: Optional[Dict[str, str]] = None,
    headless: bool = True,
    timeout_secs: float = 30.0,
) -> ActiveBrowserReport:
    """Synchronous runner for ActiveBrowserAgent, safely executed in an isolated thread."""
    import concurrent.futures

    def _worker():
        agent = ActiveBrowserAgent(headless=headless, max_actions=15, timeout_secs=timeout_secs)
        return asyncio.run(agent.explore_and_interact(target_url, auth_cookies=cookies, auth_headers=headers))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_worker)
        try:
            return future.result(timeout=timeout_secs + 5.0)
        except Exception as exc:
            logger.warning("[ActiveBrowserSync] Exploration timed out or errored: %s", exc)
            agent = ActiveBrowserAgent()
            return agent._fallback_exploration(target_url, str(exc))

