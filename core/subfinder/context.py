"""Subfinder Asset Coverage — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.subfinder.schemas import SubfinderAssetRecord

log = logging.getLogger("subfinder.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل أصل فرعي:
      - الربط بين النطاق الفرعي ونتائج HTTPx (إن توفرت)
      - تصنيف النطاق الفرعي حسب نوعه (إداري، API، دعامة، إلخ)
      - تحديد إن كانت النطاقة عالية القيمة
      - الربط بنتائج Katana (إن توفرت)
    """

    def __init__(
        self,
        httpx_results: Optional[Dict[str, List[str]]] = None,
        katana_endpoints: Optional[List[str]] = None,
        nmap_ports: Optional[Dict[str, List[int]]] = None,   # subdomain -> [open ports]
    ):
        self.httpx_results = httpx_results or {}
        self.katana_endpoints = set(katana_endpoints or [])
        self.nmap_ports = nmap_ports or {}

    def enrich(self, record: SubfinderAssetRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_live_web": False,
            "related_urls": [],
            "is_administration": False,
            "is_api": False,
            "is_high_value": False,
            "open_ports": [],
            "notes": [],
        }

        subdomain = record.subdomain.lower()

        # الربط مع نتائج HTTPx
        if subdomain in self.httpx_results:
            context["is_live_web"] = True
            context["related_urls"] = self.httpx_results[subdomain]
            context["notes"].append(f"النطاق الفرعي حي عبر HTTP ({len(self.httpx_results[subdomain])} رابط)")

        # الربط مع Katana endpoints
        katana_matches = [ep for ep in self.katana_endpoints if subdomain in ep]
        if katana_matches:
            context["notes"].append(f"النطاق موجود في Katana endpoints ({len(katana_matches)} مسار)")

        # الربط مع منافذ Nmap
        ports = self.nmap_ports.get(subdomain, [])
        if ports:
            context["open_ports"] = list(ports)
            context["notes"].append(f"منافذ مفتوحة: {ports}")

        # تصنيف النطاقة حسب الاسم
        admin_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup", "root"]
        api_keywords = ["api", "graphql", "rest", "webhook", "svc", "service"]
        high_value_keywords = ["admin", "api", "dev", "staging", "test", "internal", "vpn",
                               "mail", "webmail", "portal", "backup", "git", "jenkins", "gitlab"]
        if any(kw in subdomain for kw in admin_keywords):
            context["is_administration"] = True
            context["service_category"] = "administration"
            context["notes"].append("نطاق فرعي إداري — تأثير محتمل أعلى")
        if any(kw in subdomain for kw in api_keywords):
            context["is_api"] = True
            context["service_category"] = "api"
            context["notes"].append("نطاق فرعي API — قد يكشف بيانات منظمة")

        # تصنيف عالي القيمة (قيم القصوى تتحقق على أي keyword منهم)
        if any(kw in subdomain for kw in high_value_keywords):
            context["is_high_value"] = True
            context["notes"].append("نطاق فرعي عالي القيمة — الأولوية في المعالجة")

        # ملاحظة عامة
        context["notes"].append(f"المصدر: {record.source}")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح فحوصات إضافية بناءً على النتائج الفعلية (بدلًا من تكرار فحوصات عامة).
    """

    def advise(
        self,
        record: SubfinderAssetRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        يُترح قائمة بأدوات/قوالب مقترحة للفحص التكيفي.
        """
        context = context or {}
        suggestions: List[str] = []

        # إذا كان النطاق الفرعي حيًا عبر HTTP
        if context.get("is_live_web"):
            suggestions.append("httpx")
            suggestions.append("nuclei -t http/vuln")

        # منافذ مفتوحة → فحص إصدارات الخدمات
        if context.get("open_ports"):
            suggestions.append("nmap -sV")

        # إذا كان النطاق الفرعي عالي القيمة / إداري
        if context.get("is_high_value") or context.get("is_administration"):
            suggestions.append("ffuf")
            suggestions.append("nuclei -t http/exposed-panels")

        # إذا كان النطاق الفرعي API
        if context.get("is_api"):
            suggestions.append("katana -js")
            suggestions.append("nuclei -t http/misconfig")

        # إزالة التكرار مع الحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]


# الاسم المتوقع من المستهلكين/الاختبارات — نفس السلوك
AdaptiveAdvisor = AdaptiveTestAdvisor
