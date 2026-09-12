"""
Evidence Collector Engine (Shannon-Inspired)
Structured high-fidelity intake for raw responses, HTTP exchanges, and CLI traces.
"""
import hashlib
import json
import time
import uuid
from typing import Dict, Any, Optional

from agents.security_intelligence.schemas import EvidenceItem, EvidenceType, ProvenanceRecord


class EvidenceCollector:
    """
    مجمّع الأدلة الرقمية:
    يستقبل التفاعلات الخام، يحسب البصمة التشفيرية (SHA256)،
    ويولد كائنات EvidenceItem غير قابلة للتلاعب
    """

    def collect_http_evidence(
        self,
        target_url: str,
        method: str,
        request_headers: Dict[str, str],
        request_body: str,
        status_code: int,
        response_headers: Dict[str, str],
        response_body: str,
        duration: float,
        ev_type: EvidenceType = EvidenceType.RESPONSE,
        source: str = "EvidenceCollector.http"
    ) -> EvidenceItem:
        raw_payload = f"{method} {target_url} {status_code} {response_body[:5000]}"
        sha_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

        return EvidenceItem(
            id=f"EV-HTTP-{uuid.uuid4().hex[:8]}",
            type=ev_type,
            source=source,
            description=f"{method} {target_url} returned HTTP {status_code} ({len(response_body)} bytes)",
            data={
                "target_url": target_url,
                "method": method,
                "status_code": status_code,
                "duration": duration,
                "sha256_fingerprint": sha_hash,
                "request_headers": request_headers,
                "request_body_sample": request_body[:1000],
                "response_body_sample": response_body[:2000]
            },
            weight=0.60 if status_code < 400 else 0.40,
            verified=True,
            provenance=ProvenanceRecord(
                source_component="EvidenceCollector",
                confidence=1.0,
                notes=f"SHA256: {sha_hash[:16]}..."
            )
        )
