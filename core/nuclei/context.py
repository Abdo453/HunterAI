"""Nuclei Pilot — L3 Context Intelligence + L4 Adaptive Test Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.nuclei.schemas import NucleiFindingRecord

log = logging.getLogger("nuclei.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل نتيجة من نتائج وأدلة أخرى:
      - الربط بين النتيجة والنهايات المكتشفة (Katana endpoints)
      - الربط بالتقنيات المكتشفة (HTTPx tech detection)
      - تحديد إن كانت النتيجة على نقطة مصادقة أو إدارية
    """

    def __init__(self, katana_endpoints: Optional[List[str]] = None,
                 detected_tech: Optional[Set[str]] = None):
        self.katana_endpoints = set(katana_endpoints or [])
        self.detected_tech = set(detected_tech or [])

    def enrich(self, record: NucleiFindingRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_on_known_endpoint": False,
            "endpoint_category": "unknown",
            "related_tech": [],
            "auth_sensitive": False,
            "admin_sensitive": False,
            "notes": [],
        }

        url = record.matched_at.lower()

        # التحقق إن كان الرابط على نهاية معروفة من Katana
        if any(url == ep.lower() or url.startswith(ep.lower().rstrip("/") + "/") for ep in self.katana_endpoints):
            context["is_on_known_endpoint"] = True

        # تصنيف نهاية المسار
        auth_keywords = ["login", "auth", "signin", "token", "oauth", "sso", "register", "password"]
        admin_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup", "root"]
        if any(k in url for k in auth_keywords):
            context["auth_sensitive"] = True
            context["endpoint_category"] = "authentication"
        if any(k in url for k in admin_keywords):
            context["admin_sensitive"] = True
            if context["endpoint_category"] == "unknown":
                context["endpoint_category"] = "administration"

        # التقنيات المرتبطة (إذا كانت النتيجة على تقنية معينة)
        # يمكن ربطها بـ HTTPx output لاحقًا
        context["related_tech"] = sorted(self.detected_tech)

        # ملاحظات سياقية
        if context["auth_sensitive"]:
            context["notes"].append("النقطة مرتبطة بعملية مصادقة — زيادة أولوية التحقق")
        if context["admin_sensitive"]:
            context["notes"].append("النقطة مرتبطة.Panel إداري — تأثير محتمل أعلى")
        if not context["is_on_known_endpoint"]:
            context["notes"].append("الرابط غير مذكور في مخرجات Katana — قد يكون غير مُسجل مسبقًا")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح اختبارات إضافية حسب النتائج الفعلية (بدلًا من تكرار فحوصات عامة).
    """

    TEMPLATE_SUGGESTIONS = {
        "exposed-panel": ["http/exposed-panels", "http/misconfig"],
        "sqli": ["http/sqli", "http/vuln"],
        "xss": ["http/xss", "http/vuln"],
        "rce": ["http/rce", "http/vuln"],
        "idor": ["http/idor", "http/bola"],
        "default-login": ["http/default-credentials", "http/misconfig"],
        "exposure": ["http/exposure", "http/misconfig"],
    }

    def advise(self, record: NucleiFindingRecord, context: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        يُرجع قائمة بقوالب Nuclei المقترحة للفحص التكيفي.
        """
        suggestions: List[str] = []
        context = context or {}

        # بناءً على نوع القالب
        tid = record.template_id.lower()
        for key, templates in self.TEMPLATE_SUGGESTIONS.items():
            if key in tid or key in record.template_name.lower():
                suggestions.extend(templates)

        # بناءً على السياق (نقطة مصادقة → فحص معلومات اعتماد افتراضية)
        if context.get("auth_sensitive"):
            suggestions.append("http/default-credentials")
            suggestions.append("http/brute-force")

        # بناءً على التقنية المكتشفة
        tech = context.get("related_tech", [])
        for t in tech:
            if "apache" in t.lower():
                suggestions.append("http/apache")
            if "nginx" in t.lower():
                suggestions.append("http/nginx")
            if "wordpress" in t.lower():
                suggestions.append("http/wordpress")
            if "jenkins" in t.lower():
                suggestions.append("http/jenkins")

        # إزالة التكرار والحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]  # حد أقصى 8 اقتراحات لتجنب الإغراق
