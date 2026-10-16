"""Katana Endpoint Intelligence — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.katana.schemas import KatanaEndpointRecord, EndpointCategory

log = logging.getLogger("katana.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل نقطة نهاية من Katana:
      - الربط بين النقطة ونتائج HTTPx (التقنيات المكتشفة)
      - التصنيف حسب نوع النقطة (API، مصادقة، إدارة، ملف)
      - تحديد إن كانت النقطة حساسة
      - الربط بنقاط النهاية المكتشفة سابقًا
    """

    def __init__(
        self,
        httpx_tech: Optional[Dict[str, List[str]]] = None,   # url -> [tech1, tech2...]
        existing_endpoints: Optional[Set[str]] = None,
    ):
        self.httpx_tech = httpx_tech or {}
        self.existing_endpoints = existing_endpoints or set()

    def enrich(self, record: KatanaEndpointRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_new_endpoint": True,
            "related_tech": [],
            "service_category": "web",
            "auth_sensitive": False,
            "admin_sensitive": False,
            "api_sensitive": False,
            "notes": [],
        }

        url_lower = record.url.lower()

        # التحقق إن كانت النقطة معروفة مسبقًا
        if record.url in self.existing_endpoints:
            context["is_new_endpoint"] = False
            context["notes"].append("النقطة معروفة مسبقًا — تم زحفها سابقًا")

        # التقنيات المرتبطة
        context["related_tech"] = self.httpx_tech.get(record.url, [])

        # تصنيف الخدمة حسب الفئة
        if record.category == EndpointCategory.API:
            context["service_category"] = "api"
            context["api_sensitive"] = True
            context["notes"].append("نقطة API — قد تكشف بيانات حساسة")
        elif record.category == EndpointCategory.AUTH:
            context["service_category"] = "authentication"
            context["auth_sensitive"] = True
            context["notes"].append("نقطة مصادقة — زيادة أولوية التحليل الأمني")
        elif record.category == EndpointCategory.ADMIN:
            context["service_category"] = "administration"
            context["admin_sensitive"] = True
            context["notes"].append("نقطة إدارة — تأثير محتمل أعلى في حال الاختراق")
        elif record.category == EndpointCategory.FILE:
            context["service_category"] = "file"
            context["notes"].append("ملف مكشوف — قد يحتوي على بيانات حساسة")

        # معلمات الاستعلام
        if record.parameters:
            context["notes"].append(f"تحتوي على {len(record.parameters)} معلمة استعلام — قد تكون عرضة للتلاعب")

        # JS file
        if record.is_js:
            context["notes"].append("ملف JavaScript — قد يحتوي على نقاط نهاية مخفية أو منطق عميل-side")

        # نموذج
        if record.is_form:
            context["notes"].append("يحتوي على نموذج HTML — قد يكون عرضة لـ CSRF أو حقن البيانات")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح فحوصات إضافية بناءً على النتائج الفعلية (بدلًا من تكرار فحوصات عامة).
    """

    CATEGORY_TOOLS_MAP: Dict[str, List[str]] = {
        "api": [
            "nuclei -t http/exposed-panels",
            "nuclei -t http/misconfig",
            "katana -js",
        ],
        "auth": [
            "nuclei -t http/default-credentials",
            "nuclei -t http/brute-force",
            "ffuf",
        ],
        "administration": [
            "nuclei -t http/exposed-panels",
            "ffuf",
        ],
        "file": [
            "nuclei -t http/exposure",
            "nuclei -t http/misconfig",
        ],
        "static": [
            "nuclei -t http/vuln",
        ],
    }

    def advise(
        self,
        record: KatanaEndpointRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        يُترح قائمة بأدوات/قوالب مقترحة للفحص التكيفي.
        """
        context = context or {}
        suggestions: List[str] = []

        # بناءً على فئة النقطة
        category = record.category
        if category in self.CATEGORY_TOOLS_MAP:
            suggestions.extend(self.CATEGORY_TOOLS_MAP[category])

        # بناءً على السياق
        if context.get("auth_sensitive"):
            suggestions.append("nuclei -t http/default-credentials")
            suggestions.append("ffuf")

        if context.get("admin_sensitive"):
            suggestions.append("nuclei -t http/exposed-panels")

        if context.get("api_sensitive"):
            suggestions.append("katana -js")
            suggestions.append("nuclei -t http/misconfig")

        if context.get("is_js"):
            suggestions.append("nuclei -t http/exposed-panels")

        if record.parameters:
            suggestions.append("nuclei -t http/sqli")
            suggestions.append("nuclei -t http/xss")

        # إزالة التكرار مع الحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
