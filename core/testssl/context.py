"""testssl.sh TLS Configuration Intelligence — L3 Context + L4 Adaptive"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional
from core.testssl.schemas import TestsslFindingRecord

log = logging.getLogger("testssl.context")


class ContextEnricher:
    def enrich(self, record: TestsslFindingRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_critical": False,
            "is_protocol_issue": False,
            "is_cipher_issue": False,
            "is_cert_issue": False,
            "notes": [],
        }

        sev_lower = record.severity.lower()
        title_lower = record.title.lower()
        desc_lower = record.description.lower()

        if sev_lower in ("critical", "high"):
            context["is_critical"] = True
            context["notes"].append("ثغرة خطيرة — أولوية فورية")

        if "protocol" in title_lower or "protocol" in desc_lower:
            context["is_protocol_issue"] = True
            context["notes"].append("مشكلة في بروتوكول TLS")
        if "cipher" in title_lower or "cipher" in desc_lower:
            context["is_cipher_issue"] = True
            context["notes"].append("مشكلة في تشفير TLS")
        if "cert" in title_lower or "cert" in desc_lower:
            context["is_cert_issue"] = True
            context["notes"].append("مشكلة في شهادة TLS")

        return context


class AdaptiveAdvisor:
    def advise(self, record: TestsslFindingRecord, context: Optional[Dict[str, Any]] = None) -> List[str]:
        context = context or {}
        suggestions: List[str] = []

        if context.get("is_critical"):
            suggestions.append("testssl.sh --severity CRITICAL")
        if context.get("is_protocol_issue"):
            suggestions.append("testssl.sh --protocol")
        if context.get("is_cipher_issue"):
            suggestions.append("testssl.sh --cipher")
        if context.get("is_cert_issue"):
            suggestions.append("testssl.sh --cert")

        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
