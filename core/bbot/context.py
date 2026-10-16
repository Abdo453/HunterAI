"""BBOT Asset Relationship Analyzer — L3 Context + L4 Adaptive"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.bbot.schemas import BBOTAssetRecord

log = logging.getLogger("bbot.context")


class ContextEnricher:
    def enrich(self, record: BBOTAssetRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_infrastructure": False,
            "is_domain": False,
            "is_ip": False,
            "is_email": False,
            "is_high_value": False,
            "notes": [],
        }

        atype_lower = record.asset_type.lower()
        value_lower = record.asset_value.lower()

        infra_kw = ["ip", "domain", "hostname", "subdomain", "dns", "asn", "netblock"]
        domain_kw = ["domain", "subdomain", "hostname"]
        ip_kw = ["ip", "ipv4", "ipv6"]
        email_kw = ["email", "mailto"]

        if any(k in atype_lower for k in infra_kw):
            context["is_infrastructure"] = True
            context["notes"].append("أصل بنيوي — قد يكون نقطة دخول")
        if any(k in atype_lower for k in domain_kw):
            context["is_domain"] = True
        if any(k in atype_lower for k in ip_kw):
            context["is_ip"] = True
        if any(k in atype_lower for k in email_kw):
            context["is_email"] = True

        if record.source_module not in ("unknown",):
            context["notes"].append(f"مكتشف عبر وحدة: {record.source_module}")

        return context


class AdaptiveAdvisor:
    def advise(self, record: BBOTAssetRecord, context: Optional[Dict[str, Any]] = None) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_domain"):
            suggestions.extend(["subfinder", "httpx", "katana"])
        if context.get("is_ip"):
            suggestions.extend(["nmap", "testssl.sh"])
        if context.get("is_email"):
            suggestions.append("theHarvester")
        if context.get("is_infrastructure"):
            suggestions.append("nuclei -t http/exposed-panels")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
