"""
HunterAI Epistemic Trust Boundary Pipeline
==========================================
Enforces strict 6-stage trust graduation for all data ingested into HunterAI:
UNTRUSTED -> OBSERVED -> NORMALIZED -> ANALYZED -> VERIFIED -> TRUSTED_EVIDENCE

Invariants:
- Raw web content (HTML, JS, API bodies) starts as UNTRUSTED.
- Data cannot jump steps (e.g. UNTRUSTED cannot become TRUSTED_EVIDENCE without passing NORMALIZED and VERIFIED).
- Any attempt to bypass trust stages raises TrustViolationError.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TrustState(str, Enum):
    UNTRUSTED = "UNTRUSTED"
    OBSERVED = "OBSERVED"
    NORMALIZED = "NORMALIZED"
    ANALYZED = "ANALYZED"
    VERIFIED = "VERIFIED"
    TRUSTED_EVIDENCE = "TRUSTED_EVIDENCE"


class TrustViolationError(Exception):
    """Raised when an illegal transition across trust boundaries is attempted"""
    pass


@dataclass
class TrustGraduateData:
    data_id: str
    source: str
    current_state: TrustState = TrustState.UNTRUSTED
    payload: Any = None
    sanitization_audit: Dict[str, Any] = field(default_factory=dict)
    verification_hash: str = ""
    transition_history: List[Dict[str, Any]] = field(default_factory=list)

    def record_transition(self, to_state: TrustState, rationale: str):
        self.transition_history.append({
            "from_state": self.current_state.value,
            "to_state": to_state.value,
            "rationale": rationale,
            "timestamp": time.time(),
        })
        self.current_state = to_state


class TrustBoundaryPipeline:
    """Manages progression of data through epistemically verified boundaries"""

    # Permitted linear forward progression
    VALID_TRANSITIONS = {
        TrustState.UNTRUSTED: TrustState.OBSERVED,
        TrustState.OBSERVED: TrustState.NORMALIZED,
        TrustState.NORMALIZED: TrustState.ANALYZED,
        TrustState.ANALYZED: TrustState.VERIFIED,
        TrustState.VERIFIED: TrustState.TRUSTED_EVIDENCE,
    }

    @classmethod
    def ingest_untrusted(cls, data_id: str, raw_content: str, source: str = "web_socket") -> TrustGraduateData:
        """Entry point: all raw target data begins strictly UNTRUSTED"""
        data = TrustGraduateData(data_id=data_id, source=source, current_state=TrustState.UNTRUSTED, payload=raw_content)
        data.record_transition(TrustState.UNTRUSTED, "Raw ingestion from network transport")
        return data

    @classmethod
    def graduate(cls, data: TrustGraduateData, target_state: TrustState, rationale: str) -> TrustGraduateData:
        expected_next = cls.VALID_TRANSITIONS.get(data.current_state)
        if target_state != expected_next:
            raise TrustViolationError(
                f"Illegal trust graduation from {data.current_state.value} to {target_state.value}. "
                f"Required linear next stage is {expected_next.value if expected_next else 'None'}."
            )

        data.record_transition(target_state, rationale)
        return data
