"""
Playwright Browser Intelligence Engine
Provides headless browser automation, real-time network interception (XHR/Fetch), DOM/Form extraction, Accessibility (AXTree) snapshots, and interaction simulation.
Inspired by Playwright MCP & Browser Intelligence architecture.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Request, Response
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = Browser = BrowserContext = Page = Request = Response = None


@dataclass
class NetworkRequestRecord:
    url: str
    method: str
    resource_type: str                 # xhr | fetch | document | script | stylesheet | image | other
    headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None
    response_status: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class FormFieldRecord:
    name: str
    field_type: str                   # text | password | email | hidden | submit | checkbox | select | ...
    id: str = ""
    placeholder: str = ""
    value: str = ""
    required: bool = False


@dataclass
class FormRecord:
    action: str
    method: str
    form_id: str = ""
    fields: List[FormFieldRecord] = field(default_factory=list)
    buttons: List[str] = field(default_factory=list)
    purpose_guess: str = "general"     # login | register | password_reset | search | upload | contact | general


@dataclass
class BrowserInspectionResult:
    target_url: str
    title: str
    final_url: str
    status_code: int
    links: List[str] = field(default_factory=list)
    forms: List[FormRecord] = field(default_factory=list)
    inputs: List[FormFieldRecord] = field(default_factory=list)
    buttons: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    iframes: List[str] = field(default_factory=list)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    local_storage: Dict[str, str] = field(default_factory=dict)
    session_storage: Dict[str, str] = field(default_factory=dict)
    network_requests: List[NetworkRequestRecord] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    accessibility_snapshot: Dict[str, Any] = field(default_factory=dict)
    screenshot_path: Optional[str] = None
    interactive_actions: List[Dict[str, Any]] = field(default_factory=list)
    duration: float = 0.0


class PlaywrightEngine:
    """
    محرك ذكاء المتصفح المستند إلى Playwright:
    - فحص الـ DOM العميق واستخراج النماذج والروابط والسكربتات
    - مراقبة واعتراض كافة طلبات الشبكة (XHR & Fetch)
    - استخراج الـ Accessibility Tree (Semantic Feedback للـ AI)
    - محاكاة تفاعل المستخدم والتقاط التغييرات التلقائية
    - حفظ لقطات الشاشة والأدلة البصرية
    """

    def __init__(self, headless: bool = True, proxy: Optional[str] = None, timeout_seconds: float = 30.0):
        self.headless = headless
        self.proxy = proxy
        self.timeout_seconds = timeout_seconds

    async def inspect_url(
        self,
        url: str,
        screenshot_destination: Optional[Path] = None,
        simulate_interactions: bool = True,
        auth_credentials: Optional[Dict[str, str]] = None,
    ) -> BrowserInspectionResult:
        """
        فتح الرابط وفحصه بالكامل مع مراقبة الترافيك والـ DOM
        """
        t0 = time.time()
        if url.startswith(("http://", "https://", "data:", "file://")):
            target_clean = url
        else:
            target_clean = f"https://{url}"

        result = BrowserInspectionResult(
            target_url=target_clean,
            title="",
            final_url=target_clean,
            status_code=0
        )

        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("[PlaywrightEngine] Playwright is not installed in environment.")
            return result

        captured_requests: Dict[str, NetworkRequestRecord] = {}

        try:
            async with async_playwright() as p:
                launch_options = {
                    "headless": self.headless,
                    "args": ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--ignore-certificate-errors"]
                }
                if self.proxy:
                    launch_options["proxy"] = {"server": self.proxy}

                # Try Chromium -> Edge -> Chrome -> Firefox -> WebKit
                browser: Optional[Browser] = None
                launch_attempts = [
                    lambda: p.chromium.launch(**launch_options),
                    lambda: p.chromium.launch(channel="msedge", **launch_options),
                    lambda: p.chromium.launch(channel="chrome", **launch_options),
                    lambda: p.firefox.launch(**launch_options),
                    lambda: p.webkit.launch(**launch_options),
                ]

                for launcher in launch_attempts:
                    try:
                        browser = await launcher()
                        if browser:
                            break
                    except Exception as exc:
                        logger.debug(f"[Playwright] Launch attempt failed: {exc}")

                if not browser:
                    logger.warning("[Playwright] All Playwright browser engines failed to launch. Falling back to Selenium / HTTP parser.")
                    return await self._inspect_via_fallback(target_clean, screenshot_destination)

                context: BrowserContext = await browser.new_context(
                    ignore_https_errors=True,
                    viewport={"width": 1280, "height": 800},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                )
                page: Page = await context.new_page()

                # ── 1. Network Interception Hooks ─────────────────────
                async def on_request(req: Request):
                    try:
                        req_url = req.url
                        record = NetworkRequestRecord(
                            url=req_url,
                            method=req.method,
                            resource_type=req.resource_type,
                            headers=dict(req.headers),
                            post_data=req.post_data
                        )
                        captured_requests[req_url] = record
                    except Exception:
                        pass

                async def on_response(res: Response):
                    try:
                        res_url = res.url
                        if res_url in captured_requests:
                            rec = captured_requests[res_url]
                            rec.response_status = res.status
                            rec.response_headers = dict(res.headers)
                            content_type = res.headers.get("content-type", "").lower()
                            if "json" in content_type or "text" in content_type:
                                try:
                                    body = await res.text()
                                    rec.response_snippet = body[:1000]
                                except Exception:
                                    pass
                    except Exception:
                        pass

                page.on("request", on_request)
                page.on("response", on_response)

                # ── 2. Navigation ─────────────────────────────────────
                try:
                    response = await page.goto(target_clean, wait_until="load", timeout=self.timeout_seconds * 1000)
                    if response:
                        result.status_code = response.status
                except Exception as nav_exc:
                    logger.warning(f"[Playwright] Navigation warning on {target_clean}: {nav_exc}")

                result.title = await page.title()
                result.final_url = page.url

                # Optional Auto-Login if credentials provided
                if auth_credentials and auth_credentials.get("username") and auth_credentials.get("password"):
                    try:
                        await self._perform_auto_login(page, auth_credentials["username"], auth_credentials["password"])
                    except Exception as login_err:
                        logger.debug(f"[Playwright] Auto-login attempt: {login_err}")

                # ── 3. DOM & Forms Extraction ─────────────────────────
                dom_data = await self._extract_dom_intelligence(page, target_clean)
                result.links = dom_data.get("links", [])
                result.buttons = dom_data.get("buttons", [])
                result.scripts = dom_data.get("scripts", [])
                result.iframes = dom_data.get("iframes", [])

                raw_inputs = dom_data.get("inputs", [])
                result.inputs = [
                    FormFieldRecord(
                        name=inp.get("name", ""),
                        field_type=inp.get("field_type", "text"),
                        id=inp.get("id", ""),
                        placeholder=inp.get("placeholder", ""),
                        value=inp.get("value", ""),
                        required=bool(inp.get("required", False))
                    )
                    for inp in raw_inputs
                ]

                raw_forms = dom_data.get("forms", [])
                result.forms = [
                    FormRecord(
                        action=f.get("action", target_clean),
                        method=f.get("method", "GET"),
                        form_id=f.get("form_id", ""),
                        fields=[
                            FormFieldRecord(
                                name=fld.get("name", ""),
                                field_type=fld.get("field_type", "text"),
                                id=fld.get("id", ""),
                                placeholder=fld.get("placeholder", ""),
                                value=fld.get("value", ""),
                                required=bool(fld.get("required", False))
                            )
                            for fld in f.get("fields", [])
                        ],
                        buttons=f.get("buttons", []),
                        purpose_guess=f.get("purpose_guess", "general")
                    )
                    for f in raw_forms
                ]

                # ── 4. Storage & Cookies ──────────────────────────────
                try:
                    result.cookies = await context.cookies()
                    storages = await page.evaluate("""() => {
                        const ls = {};
                        const ss = {};
                        try {
                            for (let i = 0; i < localStorage.length; i++) {
                                const k = localStorage.key(i);
                                ls[k] = localStorage.getItem(k);
                            }
                        } catch(e) {}
                        try {
                            for (let i = 0; i < sessionStorage.length; i++) {
                                const k = sessionStorage.key(i);
                                ss[k] = sessionStorage.getItem(k);
                            }
                        } catch(e) {}
                        return { localStorage: ls, sessionStorage: ss };
                    }""")
                    result.local_storage = storages.get("localStorage", {})
                    result.session_storage = storages.get("sessionStorage", {})
                except Exception as st_err:
                    logger.debug(f"[Playwright] Storage extraction error: {st_err}")

                # ── 5. Accessibility Tree Snapshot (Semantic Feedback) ─
                try:
                    ax_tree = await page.accessibility.snapshot()
                    result.accessibility_snapshot = ax_tree or {}
                except Exception:
                    pass

                # ── 6. Interactive Behavior Simulation ────────────────
                if simulate_interactions:
                    actions = await self._simulate_dom_interactions(page)
                    result.interactive_actions = actions

                # ── 7. Screenshot Capture ─────────────────────────────
                if screenshot_destination:
                    screenshot_destination.parent.mkdir(parents=True, exist_ok=True)
                    await page.screenshot(path=str(screenshot_destination), full_page=True)
                    result.screenshot_path = str(screenshot_destination)

                # Consolidate captured requests & extract API endpoints
                result.network_requests = list(captured_requests.values())
                api_endpoints_set = set()
                for req in result.network_requests:
                    if req.resource_type in ("xhr", "fetch") or "/api/" in req.url or "graphql" in req.url or ".json" in req.url:
                        api_endpoints_set.add(f"{req.method} {req.url}")
                result.api_endpoints = sorted(list(api_endpoints_set))

                await context.close()
                await browser.close()

        except Exception as global_err:
            logger.error(f"[PlaywrightEngine] Error inspecting {url}: {global_err}", exc_info=True)

        result.duration = time.time() - t0
        return result

    async def _extract_dom_intelligence(self, page: Page, base_url: str) -> Dict[str, Any]:
        """استخراج تحليلي دقيق للعناصر التفاعلية في الـ DOM"""
        try:
            return await page.evaluate("""(baseUrl) => {
                // 1. Links
                const links = Array.from(document.querySelectorAll('a[href]'))
                    .map(a => a.href)
                    .filter(href => href && !href.startsWith('javascript:') && !href.startsWith('#'));

                // 2. Scripts
                const scripts = Array.from(document.querySelectorAll('script[src]'))
                    .map(s => s.src)
                    .filter(Boolean);

                // 3. iFrames
                const iframes = Array.from(document.querySelectorAll('iframe[src]'))
                    .map(f => f.src)
                    .filter(Boolean);

                // 4. Buttons
                const buttons = Array.from(document.querySelectorAll('button, input[type="button"], input[type="submit"]'))
                    .map(b => (b.innerText || b.value || b.getAttribute('aria-label') || b.id || '').trim())
                    .filter(Boolean);

                // 5. Inputs
                const inputs = Array.from(document.querySelectorAll('input, textarea, select')).map(inp => ({
                    name: inp.name || '',
                    field_type: inp.type || inp.tagName.toLowerCase(),
                    id: inp.id || '',
                    placeholder: inp.placeholder || '',
                    value: inp.type !== 'password' ? (inp.value || '') : '',
                    required: !!inp.required
                }));

                // 6. Forms
                const forms = Array.from(document.querySelectorAll('form')).map(f => {
                    const action = f.action || baseUrl;
                    const method = (f.method || 'GET').toUpperCase();
                    const formId = f.id || f.name || '';
                    const formInputs = Array.from(f.querySelectorAll('input, textarea, select')).map(inp => ({
                        name: inp.name || '',
                        field_type: inp.type || inp.tagName.toLowerCase(),
                        id: inp.id || '',
                        placeholder: inp.placeholder || '',
                        value: inp.type !== 'password' ? (inp.value || '') : '',
                        required: !!inp.required
                    }));
                    const formButtons = Array.from(f.querySelectorAll('button, input[type="submit"]'))
                        .map(b => (b.innerText || b.value || '').trim())
                        .filter(Boolean);

                    // Guess purpose
                    let purpose = 'general';
                    const namesJoined = formInputs.map(i => (i.name + ' ' + i.placeholder + ' ' + i.field_type).toLowerCase()).join(' ');
                    if (namesJoined.includes('password') && (namesJoined.includes('user') || namesJoined.includes('email') || namesJoined.includes('login'))) {
                        purpose = namesJoined.includes('confirm') || namesJoined.includes('register') || namesJoined.includes('signup') ? 'register' : 'login';
                    } else if (namesJoined.includes('search') || namesJoined.includes('query')) {
                        purpose = 'search';
                    } else if (namesJoined.includes('reset') || namesJoined.includes('forgot')) {
                        purpose = 'password_reset';
                    } else if (formInputs.some(i => i.field_type === 'file')) {
                        purpose = 'upload';
                    }

                    return {
                        action: action,
                        method: method,
                        form_id: formId,
                        fields: formInputs,
                        buttons: formButtons,
                        purpose_guess: purpose
                    };
                });

                return {
                    links: Array.from(new Set(links)),
                    scripts: Array.from(new Set(scripts)),
                    iframes: Array.from(new Set(iframes)),
                    buttons: Array.from(new Set(buttons)),
                    inputs: inputs,
                    forms: forms
                };
            }""", base_url)
        except Exception as exc:
            logger.debug(f"[Playwright] DOM extraction error: {exc}")
            return {"links": [], "scripts": [], "iframes": [], "buttons": [], "inputs": [], "forms": []}

    async def _simulate_dom_interactions(self, page: Page) -> List[Dict[str, Any]]:
        """محاكاة تفاعلية (النقر على أزرار Load More، التبويبات، والـ Dropdowns) لملاحظة استدعاءات الـ API الجديدة"""
        actions_log = []
        try:
            # Look for common interactive elements (Tabs, Load More, Pagination, Dropdowns)
            interactive_locators = [
                'button:has-text("Load More")',
                'button:has-text("Show More")',
                'button:has-text("Next")',
                '[role="tab"]',
                '.nav-link',
                '.tab-btn',
            ]
            for loc_str in interactive_locators:
                try:
                    elements = page.locator(loc_str)
                    count = await elements.count()
                    if count > 0:
                        btn = elements.first
                        if await btn.is_visible() and await btn.is_enabled():
                            btn_text = await btn.inner_text()
                            await btn.click(timeout=3000)
                            await page.wait_for_timeout(1000)
                            actions_log.append({
                                "action": "click",
                                "target": loc_str,
                                "text": btn_text.strip(),
                                "timestamp": time.time()
                            })
                            break
                except Exception:
                    continue
        except Exception as exc:
            logger.debug(f"[Playwright] Interaction simulation error: {exc}")
        return actions_log

    async def _perform_auto_login(self, page: Page, username: str, password: str) -> bool:
        """محاولة تسجيل الدخول التلقائي في حال وجود حقول اسم مستخدم وكلمة مرور"""
        user_selectors = ['input[type="text"]', 'input[type="email"]', 'input[name*="user"]', 'input[name*="login"]', '#username', '#email']
        pass_selectors = ['input[type="password"]', 'input[name*="pass"]', '#password']
        submit_selectors = ['button[type="submit"]', 'input[type="submit"]', 'button:has-text("Sign in")', 'button:has-text("Log In")', 'button:has-text("Login")']

        user_input = None
        for sel in user_selectors:
            loc = page.locator(sel)
            if await loc.count() > 0 and await loc.first.is_visible():
                user_input = loc.first
                break

        pass_input = None
        for sel in pass_selectors:
            loc = page.locator(sel)
            if await loc.count() > 0 and await loc.first.is_visible():
                pass_input = loc.first
                break

        if user_input and pass_input:
            await user_input.fill(username)
            await pass_input.fill(password)
            for sel in submit_selectors:
                loc = page.locator(sel)
                if await loc.count() > 0 and await loc.first.is_visible():
                    await loc.first.click(timeout=4000)
                    await page.wait_for_timeout(2000)
                    return True
        return False

    async def _inspect_via_fallback(self, url: str, screenshot_destination: Optional[Path] = None) -> BrowserInspectionResult:
        """
        طريقة احتياطية للفحص عبر Selenium أو HTTP Client في حال عدم توفر متصفح Playwright
        """
        import re
        import httpx
        from bs4 import BeautifulSoup

        res = BrowserInspectionResult(
            target_url=url,
            title="",
            final_url=url,
            status_code=200
        )

        try:
            # First try Selenium Controller
            from tools.browser_tools import BrowserController
            bc = BrowserController(headless=self.headless, proxy=self.proxy)
            if bc.start(visible=False):
                try:
                    bc.navigate(url)
                    res.title = bc.get_title()
                    if screenshot_destination:
                        bc.screenshot(str(screenshot_destination))
                        res.screenshot_path = str(screenshot_destination)
                    elems = bc.find_interactive_elements()
                    res.links = elems.get("links", [])
                    res.buttons = elems.get("buttons", [])
                    raw_forms = elems.get("forms", [])
                    res.forms = [
                        FormRecord(
                            action=f.get("action", url),
                            method=f.get("method", "GET"),
                            fields=[FormFieldRecord(name=i.get("name", ""), field_type=i.get("type", "text")) for i in f.get("inputs", [])],
                            purpose_guess="login" if any("pass" in str(i).lower() for i in f.get("inputs", [])) else "general"
                        )
                        for f in raw_forms
                    ]
                    res.cookies = bc.get_cookies()
                    return res
                finally:
                    bc.stop()
        except Exception:
            pass

        # Second fallback: HTTP parser
        try:
            if url.startswith("data:text/html"):
                import base64
                encoded = url.split(",")[-1]
                html_text = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            else:
                async with httpx.AsyncClient(timeout=15.0, verify=False, trust_env=False) as client:
                    r = await client.get(url)
                    res.status_code = r.status_code
                    html_text = r.text

            soup = BeautifulSoup(html_text, "html.parser")
            res.title = soup.title.string.strip() if soup.title and soup.title.string else "Parsed Document"
            res.links = [a.get("href") for a in soup.find_all("a", href=True) if a.get("href")]
            res.scripts = [s.get("src") for s in soup.find_all("script", src=True) if s.get("src")]
            res.buttons = [b.get_text(strip=True) for b in soup.find_all("button")]

            forms = []
            for f in soup.find_all("form"):
                action = f.get("action", url)
                method = f.get("method", "GET").upper()
                inputs = []
                for inp in f.find_all(["input", "textarea", "select"]):
                    inputs.append(FormFieldRecord(
                        name=inp.get("name", ""),
                        field_type=inp.get("type", inp.name),
                        placeholder=inp.get("placeholder", ""),
                        required=inp.has_attr("required")
                    ))
                purpose = "login" if any("password" in inp.field_type.lower() for inp in inputs) else "general"
                forms.append(FormRecord(action=action, method=method, fields=inputs, purpose_guess=purpose))
            res.forms = forms

            # If screenshot requested for fallback, touch empty or placeholder image
            if screenshot_destination:
                screenshot_destination.parent.mkdir(parents=True, exist_ok=True)
                screenshot_destination.write_bytes(b"")
                res.screenshot_path = str(screenshot_destination)

        except Exception as parse_err:
            logger.debug(f"[Playwright] HTML fallback parse error: {parse_err}")

        return res

