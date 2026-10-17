"""Soft-404 Detector — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.soft_404.schemas import Soft404Record

log = logging.getLogger("soft_404.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل صفحة Soft-404:
      - تصنيف الصفحة حسب نوعها (إدارية، API، ملف، دليل)
      - تحديد إن كانت الصفحة عالية القيمة
      - الربط بنتائج Katana أو HTTPx (إن توفرت)
    """

    def __init__(
        self,
        katana_endpoints: Optional[List[str]] = None,
        httpx_results: Optional[Dict[str, List[str]]] = None,   # url -> [related_urls]
    ):
        self.katana_endpoints = set(katana_endpoints or [])
        self.httpx_results = httpx_results or {}

    def enrich(self, record: Soft404Record) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "service_category": "web",
            "is_auth_page": False,
            "is_admin_page": False,
            "is_api_page": False,
            "is_file_page": False,
            "related_urls": [],
            "notes": [],
        }

        url_lower = record.url.lower()
        title_lower = (record.title or "").lower()

        auth_keywords = ["login", "auth", "signin", "token", "oauth", "sso", "password", "register"]
        admin_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup", "root"]
        api_keywords = ["api", "graphql", "rest", "webhook", "svc", "service"]
        file_keywords = [".php", ".asp", ".aspx", ".jsp", ".py", ".cgi", ".pl", ".json", ".xml", ".config", ".env"]

        if any(k in url_lower or k in title_lower for k in auth_keywords):
            context["is_auth_page"] = True
            context["service_category"] = "authentication"
            context["notes"].append("صفحة مصادقة — أولوية أعلى")
        if any(k in url_lower or k in title_lower for k in admin_keywords):
            context["is_admin_page"] = True
            context["service_category"] = "administration"
            context["notes"].append("صفحة إدارة — تأثير محتمل أعلى")
        if any(k in url_lower or k in title_lower for k in api_keywords):
            context["is_api_page"] = True
            context["service_category"] = "api"
            context["notes"].append("صفحة API — قد تكشف بيانات منظمة")
        if any(k in url_lower for k in file_keywords):
            context["is_file_page"] = True
            context["service_category"] = "file"
            context["notes"].append("ملف — قد يحتوي على بيانات حساسة")

        # الروابط المرتبطة من Katana
        katana_matches = [ep for ep in self.katana_endpoints if record.url in ep]
        if katana_matches:
            context["notes"].append(f"صفحة موجودة في Katana: {len(katana_matches)} مسار")

        # الروابط المرتبطة من HTTPx
        if record.url in self.httpx_results:
            context["related_urls"] = self.httpx_results[record.url]
            context["notes"].append(f"روابط مرتبطة من HTTPx: {len(self.httpx_results[record.url])} رابط")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح فحوصات إضافية بناءً على النتائج الفعلية (بدلًا من تكرار فحوصات عامة).
    """

    def advise(
        self,
        record: Soft404Record,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        يُترح قائمة بأدوات/قوالب مقترحة للفحص التكيفي.
        """
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_auth_page"):
            suggestions.append("nuclei -t http/default-credentials")
            suggestions.append("ffuf")
        if context.get("is_admin_page"):
            suggestions.append("nuclei -t http/exposed-panels")
            suggestions.append("ffuf")
        if context.get("is_api_page"):
            suggestions.append("katana -js")
            suggestions.append("nuclei -t http/misconfig")
        if context.get("is_file_page"):
            suggestions.append("nuclei -t http/exposure")
            suggestions.append("ffuf")

        # إزالة التكرار مع الحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
