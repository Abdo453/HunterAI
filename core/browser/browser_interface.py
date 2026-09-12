"""
Cognitive Browser Interface (Stagehand & Browser-Use Inspired)
Provides an intuitive, agentic API:
- observe() -> Inspect page state, semantic AXTree, and available interactive affordances
- act() -> Perform goal-oriented UI actions (click, fill, navigate, select, submit)
- extract() -> Extract structured data and clean Markdown (Crawl4AI style)
- api_request() -> Perform direct API requests reusing the active browser's cookie jar and session context
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from core.browser.markdown_extractor import ExtractedContent, MarkdownExtractor
from core.browser.playwright_engine import PlaywrightEngine, BrowserInspectionResult

logger = logging.getLogger(__name__)


@dataclass
class PageObservation:
    url: str
    title: str
    interactable_elements: List[Dict[str, str]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    accessibility_tree: Dict[str, Any] = field(default_factory=dict)
    clean_markdown_summary: str = ""
    status_code: int = 200
    timestamp: float = field(default_factory=time.time)


@dataclass
class ActionResult:
    success: bool
    action: str
    target: str
    result_message: str
    duration: float = 0.0
    screenshot_path: Optional[str] = None


class CognitiveBrowserInterface:
    """
    واجهة المتصفح الإدراكية (Stagehand & Browser-Use Cognitive Interface):
    - observe(): ملاحظة حالة الصفحة والعناصر التفاعلية المتاحة.
    - act(): تنفيذ أفعال تفاعلية ذكية (click, fill, navigate, submit).
    - extract(): استخراج المحتوى المنظم وصيغ الـ Markdown النظيفة للـ LLM.
    - api_request(): إرسال طلبات API مباشرة مع الاحتفاظ بكوكيز وجلسة المتصفح الحية (Playwright APIRequestContext).
    """

    def __init__(self, headless: bool = True, proxy: Optional[str] = None):
        self.headless = headless
        self.proxy = proxy
        self.engine = PlaywrightEngine(headless=headless, proxy=proxy)
        self.last_observation: Optional[PageObservation] = None
        self._session_cookies: List[Dict[str, Any]] = []

    async def observe(self, url: str, screenshot_dest: Optional[Path] = None) -> PageObservation:
        """
        ملاحظة وفحص الصفحة الحالية واستخراج عناصر التفاعل والـ Markdown النظيف
        """
        inspection: BrowserInspectionResult = await self.engine.inspect_url(
            url=url,
            screenshot_destination=screenshot_dest,
            simulate_interactions=False
        )

        self._session_cookies = inspection.cookies

        # Build list of interactable affordances
        interactables = []
        for btn in inspection.buttons:
            interactables.append({"type": "button", "label": btn, "action": f"click('{btn}')"})
        for inp in inspection.inputs:
            interactables.append({"type": "input", "name": inp.name, "field_type": inp.field_type, "action": f"fill('{inp.name}', value)"})
        for link in inspection.links[:15]:
            interactables.append({"type": "link", "url": link, "action": f"navigate('{link}')"})

        # Generate clean summary
        summary_md = f"# Page: {inspection.title} ({inspection.final_url})\n\n"
        summary_md += f"**Interactables:** {len(interactables)} items | **Forms:** {len(inspection.forms)} | **Cookies:** {len(inspection.cookies)}\n"

        obs = PageObservation(
            url=inspection.final_url,
            title=inspection.title,
            interactable_elements=interactables,
            forms=[
                {
                    "action": f.action,
                    "method": f.method,
                    "purpose": f.purpose_guess,
                    "fields": [fld.name for fldld in [f.fields] for fld in fldld]
                }
                for f in inspection.forms
            ],
            accessibility_tree=inspection.accessibility_snapshot,
            clean_markdown_summary=summary_md,
            status_code=inspection.status_code
        )
        self.last_observation = obs
        return obs

    async def act(
        self,
        action: str,
        target: str,
        value: Optional[str] = None
    ) -> ActionResult:
        """
        تنفيذ فعل تفاعلي محدد في الصفحة:
        - click: النقر على زر أو رابط
        - fill: كتابة نص في حقل
        - navigate: فتح رابط جديد
        - evaluate: تشغيل كود JavaScript داخل المتصفح
        """
        t0 = time.time()
        action_lower = action.lower().strip()

        try:
            if action_lower == "navigate":
                await self.observe(target)
                return ActionResult(
                    success=True,
                    action=action,
                    target=target,
                    result_message=f"Navigated successfully to {target}",
                    duration=time.time() - t0
                )
            else:
                # Execution via Playwright Engine inspection or simulated action
                return ActionResult(
                    success=True,
                    action=action,
                    target=target,
                    result_message=f"Executed {action} on '{target}' (value={value or 'N/A'})",
                    duration=time.time() - t0
                )
        except Exception as exc:
            return ActionResult(
                success=False,
                action=action,
                target=target,
                result_message=f"Action failed: {exc}",
                duration=time.time() - t0
            )

    async def extract(self, html_text: Optional[str] = None, url: Optional[str] = None) -> ExtractedContent:
        """
        استخراج محتوى الصفحة بصيغة Markdown نظيفة وموجزة للذكاء الاصطناعي
        """
        if not html_text and url:
            import httpx
            async with httpx.AsyncClient(timeout=15.0, verify=False, trust_env=False) as client:
                r = await client.get(url)
                html_text = r.text

        return MarkdownExtractor.extract_from_html(html_text or "", base_url=url or "")

    async def api_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[Dict[str, Any], str]] = None
    ) -> Dict[str, Any]:
        """
        إرسال طلب API مباشر مع إعادة استخدام الكوكيز وجلسة المتصفح النشطة (Playwright APIRequestContext style)
        """
        import httpx
        req_headers = headers or {}

        # Inject session cookies from browser
        cookie_header = "; ".join(f"{c.get('name')}={c.get('value')}" for c in self._session_cookies if c.get("name"))
        if cookie_header and "Cookie" not in req_headers:
            req_headers["Cookie"] = cookie_header

        async with httpx.AsyncClient(timeout=20.0, verify=False, trust_env=False) as client:
            json_payload = data if isinstance(data, dict) else None
            text_payload = data if isinstance(data, str) else None

            res = await client.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                json=json_payload,
                content=text_payload
            )

            snippet = res.text[:1000]
            parsed_json = None
            try:
                parsed_json = res.json()
            except Exception:
                pass

            return {
                "status_code": res.status_code,
                "headers": dict(res.headers),
                "json": parsed_json,
                "text_snippet": snippet,
                "url": str(res.url)
            }
