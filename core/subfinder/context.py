"""Subfinder Asset Coverage — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.subfinder.schemas import SubfinderAssetRecord

log = logging.getLogger("subfinder.context")


class ContextEnricher:
    def __init__(
        self,
        httpx_results: Optional[Dict[str, List[str]]] = None,
        nmap_ports: Optional[Dict[str, List[int]]] = None,
    ):
        self.httpx_results = httpx_results or {}
        self.nmap_ports = nmap_ports or {}

    def enrich(self, record: SubfinderAssetRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_live_web": False,
            "open_ports": [],
            "related_urls": [],
            "is_high_value": False,
            "notes": [],
        }

        sub = record.subdomain.lower()

        if sub in self.httpx_results:
            context["is_live_web"] = True
            context["related_urls"] = self.httpx_results[sub]
            context["notes"].append("النطاق الفرعي مباشر عبر HTTP")

        if sub in self.nmap_ports:
            context["open_ports"] = self.nmap_ports[sub]
            context["notes"].append(f"منافذ مفتوحة: {', '.join(map(str, self.nmap_ports[sub]))}")

        label = sub.split(".")[0] if "." in sub else sub
        high_value = {"admin", "dev", "staging", "test", "api", "internal", "vpn", "mail", "portal"}
        if label in high_value:
            context["is_high_value"] = True
            context["notes"].append("نطاق فرعي عالي القيمة — تأثير محتمل أعلى")

        if record.cdn:
            context["notes"].append("محمي بـ CDN — قد يخفي البنية التحتية الفعلية")

        return context


class AdaptiveAdvisor:
    def advise(
        self,
        record: SubfinderAssetRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_live_web"):
            suggestions.extend(["httpx", "nuclei -t http/vuln", "katana"])
        if context.get("open_ports"):
            suggestions.append("nmap -sV")
        if context.get("is_high_value"):
            suggestions.append("ffuf")
        if record.cdn:
            suggestions.append("nuclei -t http/exposed-panels")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
