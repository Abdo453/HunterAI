"""
Evidence Analyzer Engine
Structures, validates, and evaluates evidence artifacts collected from traffic and tests.
"""
import logging
from typing import List, Dict, Any, Optional
from agents.security_intelligence.schemas import EvidenceItem, EvidenceType

log = logging.getLogger("security_intelligence.evidence")


class EvidenceAnalyzer:
    """محلل الأدلة: فحص الأدلة وتحديد وزنها ومدى كفايتها لإثبات الفرضية الأمنية"""

    def __init__(self):
        # Default weights for evidence types
        self._type_weights = {
            EvidenceType.BEHAVIOR_DIFF: 0.90,
            EvidenceType.AUTH_ANOMALY: 0.85,
            EvidenceType.ERROR_DISCLOSURE: 0.80,
            EvidenceType.TIMING_LEAK: 0.75,
            EvidenceType.STATUS_CODE: 0.60,
            EvidenceType.PARAMETER_CONTROL: 0.65,
            EvidenceType.REQUEST: 0.40,
            EvidenceType.RESPONSE: 0.50,
            EvidenceType.CVE_MATCH: 0.85
        }

    def build_evidence_item(
        self,
        evidence_type: EvidenceType,
        source: str,
        description: str,
        data: Dict[str, Any],
        custom_weight: Optional[float] = None
    ) -> EvidenceItem:
        weight = custom_weight if custom_weight is not None else self._type_weights.get(evidence_type, 0.50)
        return EvidenceItem(
            type=evidence_type,
            source=source,
            description=description,
            data=data,
            weight=weight,
            verified=True
        )

    def evaluate_evidence_chain(self, items: List[EvidenceItem]) -> Dict[str, Any]:
        """تقييم سلسلة الأدلة وحساب الوزن التراكمي وتحديد ما إذا كانت كافية"""
        if not items:
            return {
                "total_weight": 0.0,
                "is_conclusive": False,
                "has_behavioral_diff": False,
                "summary": "No evidence items provided."
            }

        total_score = 0.0
        max_possible = 0.0
        has_diff = False

        for ev in items:
            if ev.type in [EvidenceType.BEHAVIOR_DIFF, EvidenceType.AUTH_ANOMALY]:
                has_diff = True
            w = ev.weight
            total_score += w
            max_possible += 1.0

        normalized_score = min(1.0, total_score / max(1.0, len(items) * 0.8))

        return {
            "total_weight": round(normalized_score, 3),
            "evidence_count": len(items),
            "is_conclusive": normalized_score >= 0.75 and has_diff,
            "has_behavioral_diff": has_diff,
            "summary": f"Analyzed {len(items)} evidence items. Normalized score: {normalized_score:.2f}."
        }
