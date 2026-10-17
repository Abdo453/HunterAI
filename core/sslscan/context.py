"""SSLScan TLS Cipher & Protocol Intelligence — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.sslscan.schemas import SSLAssetRecord

log = logging.getLogger("sslscan.context")

LEGACY_PROTOCOLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.1"}


class ContextEnricher:
    """L3: يضيف سياقًا لكل نتيجة TLS."""

    def enrich(self, record: SSLAssetRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "tls_version_surface": [],
            "has_legacy_protocol": False,
            "has_weak_cipher": False,
            "has_known_vuln": False,
            "attack_surface": [],
            "notes": [],
        }

        for p in record.enabled_protocols:
            context["tls_version_surface"].append(p)
            if p.strip().lower() in LEGACY_PROTOCOLS:
                context["has_legacy_protocol"] = True
                context["notes"].append(f"بروتوكول قديم مفعّل: {p}")
                context["attack_surface"].append("legacy_tls")

        if record.weak_ciphers:
            context["has_weak_cipher"] = True
            context["notes"].append(f"{len(record.weak_ciphers)} تشفير ضعيف")
            context["attack_surface"].append("weak_ciphers")

        if record.heartbleed:
            context["has_known_vuln"] = True
            context["notes"].append("Heartbleed محتمل")
            context["attack_surface"].append("heartbleed")
        if record.poodle:
            context["has_known_vuln"] = True
            context["notes"].append("POODLE محتمل")
            context["attack_surface"].append("poodle")

        if not record.enabled_protocols:
            context["notes"].append("لا بروتوكولات مفعلة — قد يكون المنفذ مغلقًا أو غير TLS")

        return context


class AdaptiveTestAdvisor:
    """L4: يقترح خطوات TLS التالية بناءً على النتيجة."""

    def advise(
        self,
        record: SSLAssetRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        host = record.host
        port = record.port
        target = f"{host}:{port}"
        suggestions: List[str] = []

        suggestions.append(f"sslscan --xml=- {target}")
        suggestions.append(f"testssl.sh {target}")
        suggestions.append(f"nmap -p {port} --script ssl-enum-ciphers {host}")

        if context.get("has_legacy_protocol"):
            suggestions.append(f"nmap -p {port} --script sslv2,sslcc {host}")
        if context.get("has_known_vuln"):
            if record.heartbleed:
                suggestions.append(f"nmap -p {port} --script ssl-heartbleed {host}")
            if record.poodle:
                suggestions.append(f"nmap -p {port} --script ssl-poodle {host}")

        seen: set = set()
        unique: List[str] = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
