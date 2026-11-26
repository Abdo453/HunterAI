"""
Browser Controller Routed Through Burp Proxy
Controls automated browser navigation and DOM inspection.
Never fabricates "Simulated Lab" HTML when network transport fails;
mock/custom transports are allowed ONLY when caller explicitly passes
``transport_fn=...`` (e.g. in isolated unit tests).
"""
from __future__ import annotations

import inspect
import logging
import re
from typing import Any, Callable, Dict, List, Optional

import httpx
from pydantic import BaseModel, Field

log = logging.getLogger("core.controllers.browser")


class BrowserNavigationResult(BaseModel):
    url: str
    status_code: int
    title: str = ""
    dom_snippet: str = ""
    proxied_via: Optional[str] = None
    links_found: List[str] = Field(default_factory=list)
    forms_found: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "OK"
    error: Optional[str] = None


class BrowserController:
    """
    Browser controller routed through optional Burp proxy.
    Fails closed with ``status="UNAVAILABLE"`` on network/transport failure
    instead of fabricating synthetic HTML.
    """

    def __init__(
        self,
        proxy_url: Optional[str] = None,
        timeout: float = 10.0,
        transport_fn: Optional[Callable[[str, Dict[str, str]], Any]] = None,
        allow_insecure_tls: bool = False,
    ):
        self.proxy_url = proxy_url
        self.timeout = timeout
        self._transport_fn = transport_fn
        self.allow_insecure_tls = allow_insecure_tls
        self.current_url: str = ""
        self.current_dom: str = ""
        self.current_title: str = ""
        self._history: List[str] = []

    async def navigate(
        self,
        url: str,
        custom_headers: Optional[Dict[str, str]] = None,
    ) -> BrowserNavigationResult:
        """Navigate to URL via live HTTP/proxy transport (or explicitly injected test transport_fn)."""
        self.current_url = url
        self._history.append(url)

        headers = dict(custom_headers or {})
        headers.setdefault("User-Agent", "HunterAI-BrowserAgent/2.0")

        try:
            if self._transport_fn is not None:
                raw = self._transport_fn(url, headers)
                if inspect.isawaitable(raw):
                    raw = await raw
                if isinstance(raw, tuple) and len(raw) >= 2:
                    status, body = int(raw[0]), str(raw[1])
                elif isinstance(raw, dict):
                    status = int(raw.get("status_code", 200))
                    body = str(raw.get("body", ""))
                else:
                    status = int(getattr(raw, "status_code", 200))
                    body = str(getattr(raw, "text", getattr(raw, "body", "")))
            else:
                client_kwargs: Dict[str, Any] = {
                    "timeout": self.timeout,
                    "verify": not self.allow_insecure_tls,
                    "trust_env": False,
                }
                if self.proxy_url:
                    client_kwargs["proxy"] = self.proxy_url
                async with httpx.AsyncClient(**client_kwargs) as client:
                    resp = await client.get(url, headers=headers)
                    status = resp.status_code
                    body = resp.text
        except Exception as exc:
            log.warning("Browser navigation failed for %s: %s (returning UNAVAILABLE)", url, exc)
            self.current_dom = ""
            self.current_title = ""
            return BrowserNavigationResult(
                url=url,
                status_code=0,
                title="",
                dom_snippet="",
                proxied_via=self.proxy_url,
                links_found=[],
                forms_found=[],
                status="UNAVAILABLE",
                error=str(exc),
            )

        self.current_dom = body

        m_title = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        self.current_title = m_title.group(1).strip() if m_title else "Untitled Page"

        links = re.findall(r'href=["\']([^"\'#>]+)["\']', body, re.IGNORECASE)

        forms = []
        for form_match in re.finditer(r"<form\s+([^>]+)>(.*?)</form>", body, re.IGNORECASE | re.DOTALL):
            attrs = form_match.group(1)
            inner = form_match.group(2)
            action_m = re.search(r'action=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            method_m = re.search(r'method=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            inputs = re.findall(r'name=["\']([^"\']+)["\']', inner, re.IGNORECASE)
            forms.append({
                "action": action_m.group(1) if action_m else url,
                "method": method_m.group(1).upper() if method_m else "GET",
                "inputs": inputs,
            })

        return BrowserNavigationResult(
            url=url,
            status_code=status,
            title=self.current_title,
            dom_snippet=body[:1000],
            proxied_via=self.proxy_url,
            links_found=links[:20],
            forms_found=forms,
            status="OK",
        )

    async def click(self, selector: str) -> Dict[str, Any]:
        """Interactive DOM clicks require a live browser driver (Playwright); report UNAVAILABLE if absent."""
        return {
            "action": "click",
            "selector": selector,
            "success": False,
            "status": "UNAVAILABLE",
            "reason": "No live DOM browser driver attached to HTTP-only BrowserController.",
            "current_url": self.current_url,
        }

    async def type(self, selector: str, text: str) -> Dict[str, Any]:
        """Interactive DOM typing requires a live browser driver (Playwright); report UNAVAILABLE if absent."""
        return {
            "action": "type",
            "selector": selector,
            "input_text": text,
            "success": False,
            "status": "UNAVAILABLE",
            "reason": "No live DOM browser driver attached to HTTP-only BrowserController.",
        }

    def read_dom(self) -> str:
        return self.current_dom

    def get_current_url(self) -> str:
        return self.current_url
