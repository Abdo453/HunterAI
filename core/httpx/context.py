"""HTTPx Technology Profiler — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.httpx.schemas import HTTPxAssetRecord, TechnologyProfile

log = logging.getLogger("httpx.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل أصل من نتائج وأدلة أخرى:
      - الربط بين الأصل ونتائج DNS (subfinder, amass, dnsx)
      - تصنيف الخدمة حسب نوع التقنيات المكتشفة
      - تحديد إن كان الأصل نقطة مصادقة أو إدارية من خلال المسار والعنوان
      - دمج معلومات port من nmap/naabu إن توفرت
    """

    def __init__(
        self,
        dns_records: Optional[Dict[str, List[str]]] = None,  # host -> [A, AAAA, CNAME...]
        open_ports: Optional[Dict[str, List[int]]] = None,   # host -> [80, 443, 8080...]
        katana_endpoints: Optional[List[str]] = None,
    ):
        self.dns_records = dns_records or {}
        self.open_ports = open_ports or {}
        self.katana_endpoints = set(katana_endpoints or [])

    def enrich(self, record: HTTPxAssetRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "dns_info": [],
            "open_ports_on_host": [],
            "is_on_known_endpoint": False,
            "service_category": "web",
            "auth_sensitive": False,
            "admin_sensitive": False,
            "likely_cdn_protected": False,
            "notes": [],
        }

        host = record.host.lower()
        url = record.url.lower()

        # DNS info
        if host in self.dns_records:
            context["dns_info"] = self.dns_records[host]

        # Open ports on same host
        if host in self.open_ports:
            context["open_ports_on_host"] = self.open_ports[host]

        # التحقق إن كان المسار على نهاية معروفة من Katana
        if any(url == ep.lower() or url.startswith(ep.lower().rstrip("/") + "/") for ep in self.katana_endpoints):
            context["is_on_known_endpoint"] = True

        # تصنيف الخدمة حسب التقنيات (يُحدّد الفئة الأساسية)
        techs = " ".join(record.technologies).lower()
        server = (record.web_server or "").lower()
        title = (record.title or "").lower()

        if any(k in techs or k in server or k in title for k in ["wordpress", "drupal", "joomla", "cms"]):
            context["service_category"] = "cms"
        elif any(k in techs or k in server or k in title for k in ["api", "graphql", "rest", "swagger"]):
            context["service_category"] = "api"
        elif any(k in techs or k in server or k in title for k in ["nginx", "apache", "iis"]):
            context["service_category"] = "web_server"

        # نقطة إدارية؟ (تOverride أي فئة سابقة لأنها أهم أمنيًا)
        admin_keywords = ["admin", "administrator", "manage", "dashboard", "panel", "config", "setup"]
        if any(k in url or k in title for k in admin_keywords):
            context["admin_sensitive"] = True
            context["service_category"] = "administration"

        # نقطة مصادقة؟ (إذا لم تكن إدارية بالفعل)
        auth_keywords = ["login", "auth", "signin", "token", "oauth", "sso", "register", "password"]
        if any(k in url or k in title for k in auth_keywords):
            context["auth_sensitive"] = True
            if context["service_category"] == "web":
                context["service_category"] = "authentication"

        # CDN protection
        if record.cdn or context.get("is_likely_cdn"):
            context["likely_cdn_protected"] = True
            context["notes"].append("الأصل محمي بـ CDN — التقنيات الفعلية قد تكون مخفية")

        if context["auth_sensitive"]:
            context["notes"].append("النقطة مرتبطة بمصادقة — زيادة أولوية التحليل الأمني")
        if context["admin_sensitive"]:
            context["notes"].append("النقطة مرتبطة بإدارة — تأثير محتمل أعلى في حال الاختراق")
        if not context["dns_info"]:
            context["notes"].append("لا توجد سجلات DNS مرتبطة — قد يكون أصلاً مباشراً أو جديدًا")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح فحوصات إضافية بناءً على النتائج الفعلية (بدلًا من تكرار فحوصات عامة).
    """

    TECH_TOOLS_MAP: Dict[str, List[str]] = {
        "wordpress": ["wpscan", "http/wordpress"],
        "drupal": ["droopescan", "http/drupal"],
        "joomla": ["joomscan", "http/joomla"],
        "nginx": ["http/nginx", "testssl.sh"],
        "apache": ["http/apache", "testssl.sh"],
        "iis": ["http/iis"],
        "php": ["http/exposure", "http/vuln"],
        "node.js": ["http/nodejs"],
        "python": ["http/python"],
        "ruby": ["http/ruby"],
    }

    def advise(
        self,
        record: HTTPxAssetRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        يُرجع قائمة بأدوات/قوالب مقترحة للفحص التكيفي.
        """
        context = context or {}
        suggestions: List[str] = []

        # بناءً على التقنيات المكتشفة
        techs = " ".join(record.technologies).lower()
        server = (record.web_server or "").lower()
        all_tech_text = f"{techs} {server}"

        for tech, tools in self.TECH_TOOLS_MAP.items():
            if tech in all_tech_text:
                suggestions.extend(tools)

        # بناءً على فئة الخدمة
        if context.get("service_category") == "cms":
            suggestions.append("nuclei -t http/cves")
            suggestions.append("wpscan" if "wordpress" in all_tech_text else "droopescan")
        if context.get("service_category") == "api":
            suggestions.append("katana -js")
            suggestions.append("nuclei -t http/exposed-panels")
        if context.get("auth_sensitive"):
            suggestions.append("http/default-credentials")
            suggestions.append("http/brute-force")
        if context.get("admin_sensitive"):
            suggestions.append("http/exposed-panels")
        if context.get("likely_cdn_protected"):
            suggestions.append("testssl.sh")  # للتحقق من إعدادات TLS خلف CDN

        # إزالة التكرار
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
