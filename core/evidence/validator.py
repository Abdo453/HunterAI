"""
Evidence Validator & Proof Verifier
Validates evidentiary completeness and differential integrity before findings can be confirmed.
"""
import logging
from typing import List, Tuple

from agents.security_intelligence.schemas import EvidenceItem, EvidenceType

log = logging.getLogger("core.evidence.validator")


class EvidenceValidator:
    """
    المدقق الجنائي للأدلة:
    يتأكد من أن الأدلة كافية وغير متناقضة وتحتوي على إثباتات قطعية
    """

    _CONCLUSIVE_TYPES = {
        EvidenceType.BEHAVIOR_DIFF,
        EvidenceType.AUTH_ANOMALY,
        EvidenceType.ERROR_DISCLOSURE,
        EvidenceType.TIMING_LEAK
    }

    def validate_evidence_chain(self, items: List[EvidenceItem]) -> Tuple[bool, str]:
        if not items:
            return False, "Evidence chain is empty. Pure speculation rejected."

        has_conclusive = any(it.type in self._CONCLUSIVE_TYPES for it in items)
        if not has_conclusive:
            return False, "Evidence chain lacks conclusive differential, auth anomaly, or error leak."

        # Check evidence weights
        avg_weight = sum(getattr(it, "weight", 0.5) for it in items) / len(items)
        if avg_weight < 0.65:
            return False, f"Average evidence weight ({avg_weight:.2f}) is below confidence threshold (0.65)."

        return True, f"Evidence chain verified with {len(items)} items (Average weight: {avg_weight:.2f})."
