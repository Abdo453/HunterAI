"""
Page & Asset Collector
======================
Harvests complete client-side page state: HTML, inline scripts, external JS,
JSON scripts, Next.js __NEXT_DATA__, forms, links, iframes, and network traces.
"""
import html
import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from core.code_intel.models import PageAssetBundle

logger = logging.getLogger("hunter_ai.code_intel.collector")


class PageCollector:
    """Collects and organizes all page code and dynamic state"""

    @classmethod
    def collect_from_html(
        cls,
        target_url: str,
        raw_html: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        network_requests: Optional[List[Dict[str, Any]]] = None
    ) -> PageAssetBundle:
        bundle = PageAssetBundle(
            target_url=target_url,
            raw_html=raw_html,
            headers=headers or {},
            cookies=cookies or {},
            network_requests=network_requests or []
        )

        if not raw_html:
            return bundle

        soup = BeautifulSoup(raw_html, "html.parser")

        # 1. Scripts: Inline and External
        for s in soup.find_all("script"):
            src = s.get("src")
            if src:
                full_src = urljoin(target_url, src.strip())
                if full_src not in bundle.external_js_urls:
                    bundle.external_js_urls.append(full_src)
            else:
                content = s.string or s.text or ""
                s_type = (s.get("type") or "").lower()
                s_id = s.get("id") or ""
                # If it's a JSON script (application/json, __NEXT_DATA__), store in json_blocks
                if "json" in s_type or s_id == "__NEXT_DATA__":
                    try:
                        payload = json.loads(content.strip() or "{}")
                        bundle.json_blocks.append({"id": s_id, "type": s_type, "data": payload})
                        if s_id == "__NEXT_DATA__":
                            bundle.next_data = payload
                    except Exception:
                        pass
                elif content.strip():
                    bundle.inline_scripts.append(content.strip())

        # 2. Forms
        for f in soup.find_all("form"):
            action = urljoin(target_url, f.get("action", ""))
            method = (f.get("method") or "GET").upper()
            inputs = []
            for inp in f.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                        "value": inp.get("value", "")
                    })
            bundle.forms.append({"action": action, "method": method, "inputs": inputs})

        # 3. Links and Iframes
        for a in soup.find_all("a", href=True):
            full_link = urljoin(target_url, html.unescape(a["href"].strip()))
            if full_link not in bundle.links:
                bundle.links.append(full_link)

        for ifr in soup.find_all("iframe", src=True):
            full_ifr = urljoin(target_url, html.unescape(ifr["src"].strip()))
            if full_ifr not in bundle.iframes:
                bundle.iframes.append(full_ifr)

        return bundle