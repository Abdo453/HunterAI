"""Nmap Service Fingerprint — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.nmap.schemas import NmapPortRecord

log = logging.getLogger("nmap.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل منفذ من Nmap:
      - الربط بين المنفذ ونتائج HTTPx (إن كان порт 80/443/8080 إلخ)
      - تصنيف الخدمة حسب نوعها (웹، قاعدة بيانات، إدارة، إلخ)
      - تحديد إن كانت الخدمة حساسة
      - الربط بنتائج Katana endpoints إن توفرت
    """

    def __init__(
        self,
        httpx_results: Optional[Dict[int, List[str]]] = None,   # port -> [urls]
        katana_endpoints: Optional[List[str]] = None,
    ):
        self.httpx_results = httpx_results or {}
        self.katana_endpoints = set(katana_endpoints or [])

    def enrich(self, record: NmapPortRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "service_family": "unknown",
            "is_web_service": False,
            "is_database": False,
            "is_remote_access": False,
            "is_mail": False,
            "is_dns": False,
            "related_urls": [],
            "auth_sensitive": False,
            "admin_sensitive": False,
            "notes": [],
        }

        port = record.port
        service = (record.service_name or "").lower()
        product = (record.service_product or "").lower()

        # تصنيف عائلة الخدمة
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
        db_ports = {3306, 5432, 1433, 6379, 27017, 5900, 11211}
        remote_ports = {22, 23, 3389, 5900}
        mail_ports = {25, 110, 143, 465, 587, 993, 995}
        dns_ports = {53}

        if port in web_ports or "http" in service or "nginx" in product or "apache" in product:
            context["service_family"] = "web"
            context["is_web_service"] = True
        elif port in db_ports or "mysql" in service or "postgres" in service or "redis" in service:
            context["service_family"] = "database"
            context["is_database"] = True
        elif port in remote_ports or "ssh" in service or "rdp" in service or "vnc" in service or "telnet" in service:
            context["service_family"] = "remote_access"
            context["is_remote_access"] = True
        elif port in mail_ports or "smtp" in service or "pop3" in service or "imap" in service:
            context["service_family"] = "mail"
            context["is_mail"] = True
        elif port in dns_ports or "dns" in service:
            context["service_family"] = "dns"
            context["is_dns"] = True

        # روابط HTTPx المرتبطة
        if port in self.httpx_results:
            context["related_urls"] = self.httpx_results[port]
            context["is_web_service"] = True
            context["service_family"] = "web"

        # حساسية المصادقة والإدارة
        if context["is_web_service"]:
            # التحقق من نقاط الإدارة من Katana
            admin_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config"]
            for ep in self.katana_endpoints:
                ep_lower = ep.lower()
                if any(kw in ep_lower for kw in admin_keywords):
                    context["admin_sensitive"] = True
                    context["notes"].append("نقطة إدارة مرتبطة بهذه الخدمة")
                    break

            auth_keywords = ["login", "auth", "signin", "token", "oauth"]
            for ep in self.katana_endpoints:
                ep_lower = ep.lower()
                if any(kw in ep_lower for kw in auth_keywords):
                    context["auth_sensitive"] = True
                    context["notes"].append("نقطة مصادقة مرتبطة بهذه الخدمة")
                    break

        # ملاحظات عامة
        if context["is_remote_access"]:
            context["notes"].append("خدمة الوصول عن بعد — زيادة أولوية التحقق من المصادقة")
        if context["is_database"]:
            context["notes"].append("قاعدة بيانات مكشوفة — تأثير محتمل مرتفع في حال الاختراق")
        if context["is_web_service"]:
            context["notes"].append("خدمة ويب — قد تكون عرضة لثغرات الويب الشائعة")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح فحوصات إضافية بناءً على النتائج الفعلية (بدلًا من تكرار فحوصات عامة).
    """

    SERVICE_TOOLS_MAP: Dict[str, List[str]] = {
        "web": [
            "nuclei -t http/vuln",
            "nuclei -t http/misconfig",
            "httpx",
            "katana",
        ],
        "database": [
            "nuclei -t exposed-panels",
            "sqlmap",
        ],
        "remote_access": [
            "nuclei -t ssh",
            "hydra",
            "nmap --script ssh-enum-users",
        ],
        "mail": [
            "nuclei -t smtp",
            "hydra",
        ],
        "dns": [
            "dnsx",
            "nmap --script dns-enum",
        ],
    }

    PRODUCT_TOOLS_MAP: Dict[str, List[str]] = {
        "apache": ["nuclei -t http/apache", "testssl.sh"],
        "nginx": ["nuclei -t http/nginx", "testssl.sh"],
        "iis": ["nuclei -t http/iis"],
        "mysql": ["nmap --script mysql-enum"],
        "postgresql": ["nmap --script pgsql-brute"],
        "redis": ["nmap --script redis-info"],
        "mongodb": ["nmap --script mongodb-info"],
        "ssh": ["nmap --script ssh2-enum-algos"],
        "rdp": ["nmap --script rdp-enum-encryption"],
    }

    def advise(
        self,
        record: NmapPortRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        يُترح قائمة بأدوات/قوالب مقترحة للفحص التكيفي.
        """
        context = context or {}
        suggestions: List[str] = []

        # بناءً على عائلة الخدمة
        family = context.get("service_family", "unknown")
        if family in self.SERVICE_TOOLS_MAP:
            suggestions.extend(self.SERVICE_TOOLS_MAP[family])

        # بناءً على المنتج المحدد
        product = (record.service_product or "").lower()
        for prod, tools in self.PRODUCT_TOOLS_MAP.items():
            if prod in product:
                suggestions.extend(tools)

        # بناءً على الحساسية
        if context.get("auth_sensitive"):
            suggestions.append("nuclei -t http/default-credentials")
            suggestions.append("ffuf")

        if context.get("admin_sensitive"):
            suggestions.append("nuclei -t http/exposed-panels")
            suggestions.append("ffuf")

        if context.get("is_database"):
            suggestions.append("sqlmap")

        if context.get("is_web_service"):
            suggestions.append("nuclei -t http/vuln")
            suggestions.append("katana -js")

        # إزالة التكرار مع الحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
