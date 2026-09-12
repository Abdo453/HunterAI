"""
Cross-Evidence Correlator (Shannon-Inspired)
Correlates multiple raw observations (Baseline vs Test vs Cross-Tenant)
to mathematically compute differential behavior and eliminate false positives.
"""
import uuid
import logging
from typing import Dict, Any, Optional

from agents.security_intelligence.schemas import EvidenceItem, EvidenceType, ProvenanceRecord

log = logging.getLogger("core.evidence.correlator")


class EvidenceCorrelator:
    """
    محرك مطابقة الأدلة التفاضلية:
    يقارن بين استجابة الأساس (Baseline) واستجابة الفحص (Probe)
    لحساب الفروق الدقيقة في السلوك وتأكيد الثغرات دون تخمين
    """

    def correlate_differential(
        self,
        baseline_evidence: EvidenceItem,
        probe_evidence: EvidenceItem,
        context_description: str = "Cross-tenant access differential"
    ) -> EvidenceItem:
        """
        مقارنة دليلي استجابة وحساب الفروقات في كود الحالة والحجم والمحتوى
        """
        base_data = baseline_evidence.data
        probe_data = probe_evidence.data

        base_status = base_data.get("status_code", 0)
        probe_status = probe_data.get("status_code", 0)

        base_body = base_data.get("response_body_sample", "")
        probe_body = probe_data.get("response_body_sample", "")

        status_diff = (base_status != probe_status)
        length_diff = abs(len(probe_body) - len(base_body))

        # Check for authorization bypass patterns (e.g. both got 200 OK with distinct tenant data)
        is_both_200 = (base_status == 200 and probe_status == 200)
        has_content_diff = (base_body != probe_body and bool(base_body) and bool(probe_body))

        is_significant_diff = status_diff or (is_both_200 and has_content_diff)

        correlated_id = f"EV-DIFF-{uuid.uuid4().hex[:8]}"
        ev_type = EvidenceType.BEHAVIOR_DIFF if is_significant_diff else EvidenceType.STATUS_CODE
        weight = 0.92 if (is_both_200 and has_content_diff) else 0.70

        return EvidenceItem(
            id=correlated_id,
            type=ev_type,
            source="EvidenceCorrelator",
            description=f"Correlated differential: {context_description}. Status diff: {status_diff}, Length delta: {length_diff} bytes.",
            data={
                "baseline_id": baseline_evidence.id,
                "probe_id": probe_evidence.id,
                "baseline_status": base_status,
                "probe_status": probe_status,
                "length_delta": length_diff,
                "is_both_200": is_both_200,
                "has_content_diff": has_content_diff,
                "is_conclusive_diff": is_significant_diff
            },
            weight=weight,
            verified=is_significant_diff,
            provenance=ProvenanceRecord(
                source_component="EvidenceCorrelator",
                confidence=weight,
                notes=f"Correlated from {baseline_evidence.id} and {probe_evidence.id}"
            )
        )
