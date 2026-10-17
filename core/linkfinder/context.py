"""LinkFinder JS Endpoints — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.linkfinder.schemas import JSFindingRecord

log = logging.getLogger("linkfinder.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل نقطة نهاية JS:
      - تصنيف النقطة حسب نوعها (auth, admin, api, file, directory)
      - تحديد إن كانت النقطة حساسة
      - ربطها بنتائج Katana أو HTTPx (إن توفرت)
    """

    def __init__(
        self,
        katana_endpoints: Optional[List[str]] = None,
        httpx_results: Optional[Dict[str, List[str]]] = None,
    ):
        self.katana_endpoints = set(katana_endpoints or [])
        self.httpx_results = httpx_results or {}

    def enrich(self, record: JSFindingRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "service_category": "web",
            "auth_sensitive": False,
            "admin_sensitive": False,
            "api_sensitive": False,
            "is_file_endpoint": False,
            "is_directory_endpoint": False,
            "notes": [],
        }

        endpoint_lower = record.endpoint.lower()
        source_lower = record.source_file.lower()

        auth_keywords = ["login", "auth", "signin", "token", "oauth", "sso", "password", "register"]
        admin_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup", "root"]
        api_keywords = ["api", "graphql", "rest", "webhook", "svc", "service"]
        file_keywords = [".php", ".asp", ".aspx", ".jsp", ".py", ".cgi", ".pl", ".json", ".xml", ".config", ".env"]
        dir_keywords = ["/admin", "/api", "/manage", "/config", "/setup", "/root"]

        # التصنيف بالأولوية: first-category-wins (authentication > administration > api > file > directory)
        # الفِعاليات (flags) كلها تُسجَّل — لكن service_category يُثبَّت من أعلى أولوية مطابقة
        if any(k in endpoint_lower or k in source_lower for k in auth_keywords):
            context["auth_sensitive"] = True
            context["notes"].append("نقطة مصادقة — أولوية أعلى")
            if context["service_category"] == "web":
                context["service_category"] = "authentication"
        if any(k in endpoint_lower or k in source_lower for k in admin_keywords):
            context["admin_sensitive"] = True
            context["notes"].append("نقطة إدارة — تأثير محتمل أعلى")
            if context["service_category"] == "web":
                context["service_category"] = "administration"
        if any(k in endpoint_lower or k in source_lower for k in api_keywords):
            context["api_sensitive"] = True
            context["notes"].append("نقطة API — قد تكشف بيانات منظمة")
            if context["service_category"] == "web":
                context["service_category"] = "api"
        if any(k in endpoint_lower for k in file_keywords):
            context["is_file_endpoint"] = True
            context["notes"].append("ملقع ملف — قد يحتوي على بيانات حساسة")
            if context["service_category"] == "web":
                context["service_category"] = "file"
        if any(k in endpoint_lower for k in dir_keywords):
            context["is_directory_endpoint"] = True
            context["notes"].append("دليل إداري — قد يكون معرضاً للوصول غير المصرح به")
            if context["service_category"] == "web":
                context["service_category"] = "directory"

        # الروابط المرتبطة من Katana
        katana_matches = [ep for ep in self.katana_endpoints if record.endpoint in ep]
        if katana_matches:
            context["notes"].append(f"نقط موجود في Katana: {len(katana_matches)} مسار")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح فحوصات إضافية بناءً على النتائج الفعلية (بدلًا من تكرار فحوصات عامة).
    """

    def advise(
        self,
        record: JSFindingRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        يُترح قائمة بأدوات/قوالب مقترحة للفحص التكيفي.
        """
        context = context or {}
        suggestions: List[str] = []

        if context.get("auth_sensitive"):
            suggestions.append("nuclei -t http/default-credentials")
            suggestions.append("ffuf")
        if context.get("is_admin_endpoint"):
            suggestions.append("nuclei -t http/exposed-panels")
            suggestions.append("ffuf")
        if context.get("is_api_endpoint"):
            suggestions.append("katana -js")
            suggestions.append("nuclei -t http/misconfig")
        if context.get("is_file_endpoint"):
            suggestions.append("nuclei -t http/exposure")
            suggestions.append("ffuf")
        if context.get("is_directory_endpoint"):
            suggestions.append("nuclei -t http/misconfig")

        # إزالة التكرار مع الحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
