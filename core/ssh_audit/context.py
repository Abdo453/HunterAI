"""SSH-Audit Security Profiler — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.ssh_audit.schemas import SSHAssetRecord

log = logging.getLogger("ssh_audit.context")


class ContextEnricher:
    def __init__(
        self,
        nmap_results: Optional[Dict[int, List[str]]] = None,
        httpx_results: Optional[Dict[str, List[str]]] = None,
    ):
        self.nmap_results = nmap_results or {}
        self.httpx_results = httpx_results or {}

    def enrich(self, record: SSHAssetRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "service_category": "ssh",
            "is_ssh_service": True,
            "is_high_value": False,
            "is_web_service": False,
            "related_ports": [],
            "notes": [],
        }

        port = record.port
        server = (record.web_server or "").lower()
        banner = (record.banner or "").lower()
        content_type = (record.content_type or "").lower()

        if port != 22:
            context["notes"].append(f"منفذ غير قياسي ({port}) — قد يكون مخفياً")

        if any(k in banner for k in ["openssh", "ssh"]):
            context["notes"].append("خادم SSH موثق")

        if port in self.nmap_results:
            context["related_ports"] = self.nmap_results[port]

        # الخدمة ويب فقط إذا أشار المضمون/البنر إلى HTTP، وليس لمجرد وجود سجل httpx.
        is_web = bool(
            record.content_type and any(k in content_type for k in ("html", "xml", "json"))
            or any(k in server for k in ("http", "apache", "nginx", "iis"))
        )
        context["is_web_service"] = is_web
        if is_web:
            context["notes"].append("النفس يُخدم عبر HTTP(S) — سطح ويب")

        if record.port == 22:
            context["notes"].append("منفذ SSH القياسي —goal common للهاكرز")

        return context


class AdaptiveTestAdvisor:
    def advise(
        self,
        record: SSHAssetRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        # كشف خدمة SSH (بنر / تقنيات / نتيجة ثقة عالية) يُTrigger اقتراح كسر كلمة مرور SSH.
        ssh_indicated = bool(record.banner) or any(
            "ssh" in (t or "").lower() for t in record.technologies
        ) or "ssh" in (record.web_server or "").lower() or record.confidence_score > 0.5
        if ssh_indicated:
            suggestions.append("nmap --script ssh-brute")
            suggestions.append("hydra -L users.txt -P passwords.txt ssh://target")
        if context.get("is_high_value"):
            suggestions.append("nmap --script ssh2-enum-algos")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
