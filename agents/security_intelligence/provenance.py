"""
Provenance & Attribution Tracker
Ensures every security claim, finding, and hypothesis has an undeniable origin, model attribution, and evidence trail.
"""
import time
from typing import Optional, List
from agents.security_intelligence.schemas import ProvenanceRecord


class ProvenanceTracker:
    """متتبع أصل ومصدر المعلومات: يوثق مَن قال ماذا، وبأي دليل وبأي درجة ثقة"""

    @staticmethod
    def create_record(
        source_component: str,
        model_name: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
        confidence: float = 1.0,
        notes: Optional[str] = None
    ) -> ProvenanceRecord:
        return ProvenanceRecord(
            source_component=source_component,
            model_name=model_name,
            evidence_ids=evidence_ids or [],
            confidence=confidence,
            created_at=time.time(),
            notes=notes
        )
