"""
Stateful Browser Session
========================
Maintains an active, persistent browser context throughout the entire engagement:
- Preserves cookies, localStorage, sessionStorage, and auth tokens
- Intercepts and records all network activity (Fetch/XHR/WebSockets)
- Tracks complete session state:
    BrowserSession
     ├── cookies
     ├── localStorage
     ├── sessionStorage
     ├── current_url
     ├── visited_states
     ├── visited_urls
     ├── DOM snapshots
     ├── network events
     ├── XHR/fetch
     ├── forms
     ├── buttons
     ├── links
     ├── JS files
     ├── screenshots
     └── action history
- Stays alive across scan phases (Observe -> Orient -> Decide -> Act -> Verify)
- Emits real-time telemetry to BrowserEventBus
"""
from __future__ import annotations

import asyncio
import html as html_lib
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import httpx

try:
    from core.burp_gateway.event_stream import BurpLiveEventStream
except ImportError:  # pragma: no cover - prevents circular import during partial package init
    BurpLiveEventStream = Any  # type: ignore[misc, assignment]

logger = logging.getLogger("hunter_ai.browser_session")

_STATIC_ASSET_EXTENSIONS: Tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".css", ".mp4", ".mp3", ".pdf",
)

_BLOCKED_THIRD_PARTY_DOMAINS: Tuple[str, ...] = (
    "google.com", "googletagmanager.com", "google-analytics.com",
    "play.google.com", "apple.com", "apps.apple.com", "facebook.com",
    "twitter.com", "linkedin.com", "cloudflareinsights.com",
    "gstatic.com", "googleapis.com",
)

_API_PATH_SEGMENT_RE = re.compile(
    r"(?:^|/)(?:api|v\d+|graphql|auth|oauth|rest|token|rpc|webhook|internal|user|users|data)(?:/|$)",
    re.IGNORECASE,
)

_FORM_TAG_RE = re.compile(r"<form\b([^>]*)>", re.IGNORECASE)
_ATTR_ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_ATTR_METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_FETCH_CALL_RE = re.compile(
    r"""fetch\s*\(\s*['"]([^'"\s<>]+)['"]\s*(?:,\s*\{[^}]*?method\s*:\s*['"]([a-zA-Z]+)['"])?""",
    re.IGNORECASE | re.DOTALL,
)
_AXIOS_CALL_RE = re.compile(
    r"""axios\.(get|post|put|patch|delete|head|options)\s*\(\s*['"]([^'"\s<>]+)['"]""",
    re.IGNORECASE,
)
_XHR_OPEN_RE = re.compile(
    r"""\.open\s*\(\s*['"]([a-zA-Z]+)['"]\s*,\s*['"]([^'"\s<>]+)['"]""",
    re.IGNORECASE,
)
_QUOTED_API_RE = re.compile(
    r"""['"]((?:/|https?://[^'"\s<>]+/)(?:api|v\d+|graphql|auth|oauth|rest|internal)(?:[/?][^'"\s<>]*)?)['"]""",
    re.IGNORECASE,
)
_QUOTED_JSON_RE = re.compile(
    r"""['"]((?:https?://[^'"\s<>]+)?/[^'"\s<>]+\.json(?:\?[^'"\s<>]*)?)['"]""",
    re.IGNORECASE,
)


def _is_blocked_third_party(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower().strip()
    if not host:
        return False
    return any(host == dom or host.endswith(f".{dom}") for dom in _BLOCKED_THIRD_PARTY_DOMAINS)


def is_api_endpoint_url(url: str, resource_type: str = "") -> bool:
    """Return True when a URL or browser resource type looks like an API endpoint."""
    if not url:
        return False
    lowered = url.strip().lower()
    if lowered.startswith(("data:", "javascript:", "mailto:", "tel:", "blob:", "#")):
        return False
    if _is_blocked_third_party(url):
        return False
    parsed = urlparse(url)
    path = parsed.path.lower()
    if path.endswith(_STATIC_ASSET_EXTENSIONS):
        return False
    if resource_type.lower() in ("fetch", "xhr"):
        return True
    if path.endswith(".json"):
        return True
    return bool(_API_PATH_SEGMENT_RE.search(path))


def extract_api_endpoints_from_html(html: str, base_url: str) -> List[Dict[str, Any]]:
    """Extract unique (method, url) API endpoint descriptors from HTML, forms, and inline JS."""
    if not html:
        return []

    discovered: List[Dict[str, Any]] = []
    seen_pairs: Set[Tuple[str, str]] = set()
    seen_urls: Set[str] = set()

    def _add(raw_url: str, method: str, resource_type: str, require_api_match: bool) -> None:
        cleaned = html_lib.unescape((raw_url or "").strip())
        if not cleaned or cleaned.startswith(("data:", "javascript:", "mailto:", "tel:", "blob:", "#")):
            return
        full_url = urljoin(base_url, cleaned) if base_url else cleaned
        if _is_blocked_third_party(full_url):
            return
        parsed = urlparse(full_url)
        if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
            return
        if parsed.path.lower().endswith(_STATIC_ASSET_EXTENSIONS):
            return
        if require_api_match and not is_api_endpoint_url(full_url, resource_type):
            return
        norm_method = (method or "GET").upper()
        key = (norm_method, full_url)
        if key in seen_pairs:
            return
        seen_pairs.add(key)
        seen_urls.add(full_url)
        discovered.append({
            "url": full_url,
            "method": norm_method,
            "resource_type": resource_type,
            "source": "browser",
        })

    # 1. Forms with explicit API actions
    for form_match in _FORM_TAG_RE.finditer(html):
        attrs = form_match.group(1)
        action_m = _ATTR_ACTION_RE.search(attrs)
        if not action_m:
            continue
        method_m = _ATTR_METHOD_RE.search(attrs)
        form_method = method_m.group(1).upper() if method_m else "GET"
        _add(action_m.group(1), form_method, "form", require_api_match=True)

    # 2. Inline fetch(...) calls
    for match in _FETCH_CALL_RE.finditer(html):
        _add(match.group(1), match.group(2) or "GET", "fetch", require_api_match=False)

    # 3. Inline axios.<method>(...) calls
    for match in _AXIOS_CALL_RE.finditer(html):
        _add(match.group(2), match.group(1), "xhr", require_api_match=False)

    # 4. XMLHttpRequest.open(method, url)
    for match in _XHR_OPEN_RE.finditer(html):
        _add(match.group(2), match.group(1), "xhr", require_api_match=False)

    # 5. Quoted API / JSON routes (fallback to GET only if URL wasn't already typed by form/JS)
    for regex in (_QUOTED_API_RE, _QUOTED_JSON_RE):
        for match in regex.finditer(html):
            candidate = html_lib.unescape(match.group(1).strip())
            resolved = urljoin(base_url, candidate) if base_url else candidate
            if resolved not in seen_urls:
                _add(candidate, "GET", "script", require_api_match=True)

    return discovered


def publish_browser_endpoint(
    event_stream: Optional[Any],
    url: str,
    method: str = "GET",
    source: str = "browser",
    resource_type: str = "",
    target_url: str = "",
    published_keys: Optional[Set[Tuple[int, str, str]]] = None,
) -> bool:
    """Publish a deduplicated browser_endpoint_discovered event to BurpLiveEventStream."""
    if not url or not event_stream or not hasattr(event_stream, "publish_event"):
        return False

    norm_method = (method or "GET").upper()
    dedup_key = (id(event_stream), norm_method, url)
    if published_keys is not None and dedup_key in published_keys:
        return False

    payload: Dict[str, Any] = {
        "type": "browser_endpoint_discovered",
        "url": url,
        "method": norm_method,
        "source": source,
    }
    if resource_type:
        payload["resource_type"] = resource_type
    if target_url:
        payload["target_url"] = target_url

    try:
        event_stream.publish_event("browser_endpoint_discovered", payload)
        if published_keys is not None:
            published_keys.add(dedup_key)
        return True
    except Exception as exc:
        logger.debug("Failed to publish browser_endpoint_discovered for %s: %s", url, exc)
        return False

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
    """Manages continuous, persistent browser lifecycle across exploration and exploitation"""

    def __init__(
        self,
        target_url: str,
        output_dir: Optional[Path] = None,
        headless: bool = True,
        proxy: Optional[str] = None,
        on_network_event: Optional[Callable[[Dict[str, Any]], Any]] = None,
        event_bus: Optional[Any] = None,
        event_stream: Optional[BurpLiveEventStream] = None,
    ):
        self.target_url = target_url
        self.base_host = (urlparse(target_url).hostname or "target").lower()
        self.output_dir = output_dir or Path(f"data/scans/{self.base_host.replace('.', '_')}/browser")
        self.headless = headless
        self.proxy = proxy
        self.on_network_event = on_network_event
        self.event_bus = event_bus
        self.event_stream = event_stream

        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "screenshots").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "dom").mkdir(parents=True, exist_ok=True)

        self._pw = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._is_playwright_active = False
        self._is_closed = False

        # In-memory complete session state
        self.current_url: str = target_url
        self.cookies: List[Dict[str, Any]] = []
        self.local_storage: Dict[str, str] = {}
        self.session_storage: Dict[str, str] = {}
        self.network_history: List[InterceptedRequest] = []
        self.visited_urls: Set[str] = set()
        self.visited_states: Set[str] = set()
        self.discovered_urls: Set[str] = set()
        self.dom_snapshots: Dict[str, str] = {}
        self.discovered_forms: List[Dict[str, Any]] = []
        self.discovered_buttons: List[Dict[str, Any]] = []
        self.discovered_links: List[Dict[str, Any]] = []
        self.discovered_js_files: Set[str] = set()
        self.screenshots: List[str] = []
        self.action_history: List[Dict[str, Any]] = []
        self._published_endpoint_keys: Set[Tuple[int, str, str]] = set()

        # HTTP fallback client
        self._http_client = httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            timeout=15.0,
            headers={"User-Agent": "HunterAI-Browser/2.0 (Security Explorer)"}
        )

    @property
    def is_alive(self) -> bool:
        return not self._is_closed

    async def start(self) -> bool:
        """Attempts to launch Playwright browser, gracefully falling back to HTTP"""
        if self._is_playwright_active and self._page:
            return True

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

    def _publish_endpoint_event(
        self,
        url: str,
        method: str = "GET",
        resource_type: str = "",
    ) -> bool:
        """Record discovered URL and emit a deduplicated browser_endpoint_discovered event."""
        if not url:
            return False
        self.discovered_urls.add(url)
        return publish_browser_endpoint(
            event_stream=self.event_stream,
            url=url,
            method=method,
            source="browser",
            resource_type=resource_type,
            target_url=self.target_url,
            published_keys=self._published_endpoint_keys,
        )

    def _extract_api_endpoints(
        self,
        html: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Extract API endpoints from DOM snapshots and network history, emitting StreamEvents."""
        extracted: List[Dict[str, Any]] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        def _collect(item: Dict[str, Any]) -> None:
            url = item.get("url", "")
            method = (item.get("method") or "GET").upper()
            if not url:
                return
            key = (method, url)
            if key in seen_pairs:
                return
            seen_pairs.add(key)
            extracted.append(item)

        if html is not None:
            resolved_base = base_url or self.current_url or self.target_url
            for ep in extract_api_endpoints_from_html(html, resolved_base):
                _collect(ep)
        else:
            for snap_url, snap_html in list(self.dom_snapshots.items()):
                for ep in extract_api_endpoints_from_html(snap_html, snap_url):
                    _collect(ep)

        for req in list(self.network_history):
            if is_api_endpoint_url(req.url, req.resource_type):
                _collect({
                    "url": req.url,
                    "method": (req.method or "GET").upper(),
                    "resource_type": req.resource_type,
                    "source": "browser",
                })

        for ep in extracted:
            self._publish_endpoint_event(
                url=ep["url"],
                method=ep["method"],
                resource_type=ep.get("resource_type", ""),
            )

        return extracted

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
            if is_api_endpoint_url(req_data.url, req_data.resource_type):
                self._publish_endpoint_event(
                    url=req_data.url,
                    method=req_data.method,
                    resource_type=req_data.resource_type,
                )
            if self.on_network_event:
                try:
                    self.on_network_event(req_data.to_dict())
                except Exception:
                    pass
        except Exception:
            pass

    def _handle_pw_response(self, response: PlaywrightResponse) -> None:
        try:
            for req in reversed(self.network_history):
                if req.url == response.url and req.status is None:
                    req.status = response.status
                    req.response_headers = dict(response.headers)
                    break
        except Exception:
            pass

    async def navigate(self, url: str) -> Tuple[Optional[str], int, Dict[str, str]]:
        """Navigates to URL and records complete DOM and headers snapshot"""
        self.visited_urls.add(url)
        self.current_url = url

        if self._is_playwright_active and self._page:
            try:
                resp = await self._page.goto(url, wait_until="domcontentloaded", timeout=15000)
                status = resp.status if resp else 200
                headers = dict(resp.headers) if resp else {}

                try:
                    await self._page.wait_for_load_state("networkidle", timeout=3000)
                except Exception:
                    pass

                html = await self._page.content()
                await self._extract_storage()

                # Record snapshot and extract API endpoints
                self.dom_snapshots[url] = html
                self._extract_api_endpoints(html=html, base_url=url)

                # Emit event if bus attached
                if self.event_bus:
                    try:
                        from core.browser.browser_event_bus import BrowserEvent, BrowserEventType
                        self.event_bus.publish_sync(BrowserEvent(
                            event_type=BrowserEventType.PAGE_LOADED,
                            source_url=url,
                            data={"status": status, "title": await self._page.title()}
                        ))
                    except Exception:
                        pass

                return html, status, headers
            except Exception as e:
                logger.debug(f"Playwright navigation failed on {url}: {e}, trying HTTP fallback")

        # Fallback HTTP
        try:
            r = await self._http_client.get(url)
            html = r.text
            self.dom_snapshots[url] = html
            self._extract_api_endpoints(html=html, base_url=url)
            for c_name, c_val in r.cookies.items():
                self.cookies.append({"name": c_name, "value": c_val, "domain": self.base_host})
            return html, r.status_code, dict(r.headers)
        except Exception as e:
            logger.debug(f"HTTP fallback navigation failed on {url}: {e}")
            return None, 0, {}

    async def interact(self, selector: str, action: str = "click", value: str = "") -> bool:
        """Executes safe interaction with DOM elements"""
        t0 = time.time()
        success = False
        if self._is_playwright_active and self._page:
            try:
                elem = await self._page.query_selector(selector)
                if elem and await elem.is_visible():
                    if action == "click":
                        await elem.click(timeout=3000)
                        success = True
                    elif action == "hover":
                        await elem.hover(timeout=3000)
                        success = True
                    elif action in ("fill", "type"):
                        await elem.fill(value, timeout=3000)
                        success = True
                    await asyncio.sleep(0.4)
                    await self._extract_storage()
                    if success:
                        post_html = await self.get_dom()
                        if post_html:
                            self._extract_api_endpoints(html=post_html, base_url=self.current_url)
            except Exception as e:
                logger.debug(f"Interaction error on {selector}: {e}")

        # Record action history
        self.action_history.append({
            "selector": selector,
            "action": action,
            "value": value if action != "type" else "***",
            "url": self.current_url,
            "success": success,
            "timestamp": t0,
        })
        return success

    async def get_dom(self) -> str:
        if self._is_playwright_active and self._page:
            try:
                return await self._page.content()
            except Exception:
                pass
        return self.dom_snapshots.get(self.current_url, "")

    async def take_screenshot(self, name: str) -> Optional[str]:
        if self._is_playwright_active and self._page:
            try:
                ss_path = self.output_dir / "screenshots" / f"{name}.png"
                await self._page.screenshot(path=str(ss_path), full_page=False)
                self.screenshots.append(str(ss_path))
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

    def get_state_summary(self) -> Dict[str, Any]:
        """Returns structured view of the active browser state"""
        return {
            "current_url": self.current_url,
            "visited_urls": sorted(list(self.visited_urls)),
            "visited_states": sorted(list(self.visited_states)),
            "cookies_count": len(self.cookies),
            "localStorage_keys": list(self.local_storage.keys()),
            "sessionStorage_keys": list(self.session_storage.keys()),
            "network_requests_count": len(self.network_history),
            "actions_executed": len(self.action_history),
            "screenshots_count": len(self.screenshots),
            "is_alive": self.is_alive,
        }

    def save_artifacts(self) -> None:
        """Persists all session artifacts to output_dir"""
        try:
            with open(self.output_dir / "session.json", "w", encoding="utf-8") as f:
                json.dump({
                    "target_url": self.target_url,
                    "current_url": self.current_url,
                    "visited_urls": list(self.visited_urls),
                    "discovered_urls": list(self.discovered_urls),
                    "total_network_requests": len(self.network_history),
                    "cookies_count": len(self.cookies),
                    "actions_count": len(self.action_history),
                    "playwright_active": self._is_playwright_active,
                }, f, indent=2)

            with open(self.output_dir / "cookies.json", "w", encoding="utf-8") as f:
                json.dump(self.cookies, f, indent=2)

            with open(self.output_dir / "storage.json", "w", encoding="utf-8") as f:
                json.dump({
                    "localStorage": self.local_storage,
                    "sessionStorage": self.session_storage
                }, f, indent=2)

            with open(self.output_dir / "action_history.json", "w", encoding="utf-8") as f:
                json.dump(self.action_history, f, indent=2)

            with open(self.output_dir / "network.jsonl", "w", encoding="utf-8") as f:
                for req in self.network_history:
                    f.write(json.dumps(req.to_dict()) + "\n")
        except Exception as e:
            logger.warning(f"Failed to persist session artifacts: {e}")

    async def close(self) -> None:
        """Gracefully closes browser context and HTTP client"""
        if self._is_closed:
            return
        self._is_closed = True
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
        logger.info("StatefulBrowserSession: Closed cleanly.")
