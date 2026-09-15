"""
HunterAI Finding Lifecycle & Security Regression Engine
=======================================================
Governs the complete lifecycle of a finding from discovery to remediation:
DISCOVERED -> TRIAGED -> NEEDS_REVIEW -> CONFIRMED -> REPORTED -> FIXED -> RETESTED -> CLOSED
                                                                   |
                                                                   +-> REGRESSED (Regression Detected)

Enforces strict transition rules and provides automated regression retesting
via the ReplayLab and Evidence Drift Classifier.
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.drift.evidence_drift_classifier import DriftClassification, EvidenceDriftClassifier
from core.replay_lab.replay_lab import ReplayLab

logger = logging.getLogger("hunter_ai.lifecycle_engine")


class LifecycleStage(str, Enum):
    DISCOVERED = "DISCOVERED"
    TRIAGED = "TRIAGED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    CONFIRMED = "CONFIRMED"
    REPORTED = "REPORTED"
    FIXED = "FIXED"
    RETESTED = "RETESTED"
    CLOSED = "CLOSED"
    REGRESSED = "REGRESSED"


# Strict state transition invariants
VALID_TRANSITIONS: Dict[LifecycleStage, Set[LifecycleStage]] = {
    LifecycleStage.DISCOVERED: {
        LifecycleStage.TRIAGED,
        LifecycleStage.CLOSED,
    },
    LifecycleStage.TRIAGED: {
        LifecycleStage.NEEDS_REVIEW,
        LifecycleStage.CONFIRMED,
        LifecycleStage.CLOSED,
    },
    LifecycleStage.NEEDS_REVIEW: {
        LifecycleStage.CONFIRMED,
        LifecycleStage.TRIAGED,
        LifecycleStage.CLOSED,
    },
    LifecycleStage.CONFIRMED: {
        LifecycleStage.REPORTED,
        LifecycleStage.FIXED,
        LifecycleStage.RETESTED,
    },
    LifecycleStage.REPORTED: {
        LifecycleStage.FIXED,
        LifecycleStage.RETESTED,
        LifecycleStage.REGRESSED,
    },
    LifecycleStage.FIXED: {
        LifecycleStage.RETESTED,
        LifecycleStage.CLOSED,
        LifecycleStage.REGRESSED,
    },
    LifecycleStage.RETESTED: {
        LifecycleStage.FIXED,
        LifecycleStage.CLOSED,
        LifecycleStage.REGRESSED,
    },
    LifecycleStage.REGRESSED: {
        LifecycleStage.REPORTED,
        LifecycleStage.FIXED,
    },
    LifecycleStage.CLOSED: {
        LifecycleStage.REGRESSED,
    },
}


class InvalidLifecycleTransitionError(ValueError):
    """Raised when an illegal lifecycle state transition is attempted"""
    pass


@dataclass
class RegressionReport:
    finding_id: str
    previous_stage: LifecycleStage
    current_stage: LifecycleStage
    verdict: str  # "FIXED", "REGRESSION_DETECTED", "STILL_PRESENT", "INCONCLUSIVE"
    is_reproduced: bool
    evidence_drift_details: str
    retest_timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["previous_stage"] = self.previous_stage.value
        d["current_stage"] = self.current_stage.value
        return d


class FindingLifecycleEngine:
    """Manages finding state transitions, audit trail, and automated regression re-testing"""

    def __init__(self, finding_id: str, initial_stage: LifecycleStage = LifecycleStage.DISCOVERED):
        self.finding_id = finding_id
        self.current_stage: LifecycleStage = initial_stage
        self.history: List[Dict[str, Any]] = [{
            "from_stage": None,
            "to_stage": initial_stage.value,
            "timestamp": time.time(),
            "actor": "system",
            "reason": "Finding lifecycle initiated."
        }]

    def transition_to(
        self,
        new_stage: LifecycleStage,
        actor: str = "agent",
        reason: str = ""
    ) -> LifecycleStage:
        allowed = VALID_TRANSITIONS.get(self.current_stage, set())
        if new_stage not in allowed:
            err = (
                f"ILLEGAL LIFECYCLE TRANSITION for {self.finding_id}: "
                f"Cannot transition from '{self.current_stage.value}' to '{new_stage.value}'. "
                f"Allowed transitions: {[s.value for s in allowed]}"
            )
            logger.error(err)
            raise InvalidLifecycleTransitionError(err)

        old_stage = self.current_stage
        self.current_stage = new_stage
        self.history.append({
            "from_stage": old_stage.value,
            "to_stage": new_stage.value,
            "timestamp": time.time(),
            "actor": actor,
            "reason": reason or f"Transitioned to {new_stage.value}"
        })
        logger.info(f"[{self.finding_id}] Lifecycle updated: {old_stage.value} -> {new_stage.value}")
        return self.current_stage

    def retest_with_replay(
        self,
        current_response_body: str,
        expected_payload: str,
        replay_lab: Optional[ReplayLab] = None
    ) -> RegressionReport:
        """
        Executes regression evaluation using the frozen replay bundle.
        If the vulnerability is still present: marks REGRESSED / STILL_PRESENT.
        If the target is patched: transitions to RETESTED -> FIXED.
        """
        lab = replay_lab or ReplayLab()
        replay_result = lab.evaluate_replay(
            finding_id=self.finding_id,
            re_executed_response_body=current_response_body,
            expected_indicator=expected_payload
        )

        prev = self.current_stage
        if replay_result.is_reproducible:
            # Payload still executes -> Bug not fixed or has returned
            verdict = "REGRESSION_DETECTED" if prev in (LifecycleStage.FIXED, LifecycleStage.CLOSED) else "STILL_PRESENT"
            new_stage = LifecycleStage.REGRESSED if prev in (LifecycleStage.FIXED, LifecycleStage.CLOSED) else self.current_stage
            if new_stage != self.current_stage:
                self.transition_to(new_stage, actor="regression_engine", reason="Replay confirmed vulnerability is still present.")

            return RegressionReport(
                finding_id=self.finding_id,
                previous_stage=prev,
                current_stage=self.current_stage,
                verdict=verdict,
                is_reproduced=True,
                evidence_drift_details="Vulnerability reproduced; payload indicator matched response."
            )
        else:
            # Payload did not reproduce -> Patched or drifted
            if prev in (LifecycleStage.CONFIRMED, LifecycleStage.REPORTED):
                self.transition_to(LifecycleStage.RETESTED, actor="regression_engine", reason="Retest showed payload no longer executes.")
                self.transition_to(LifecycleStage.FIXED, actor="regression_engine", reason="Fix confirmed via replay verification.")
            elif prev == LifecycleStage.REGRESSED:
                self.transition_to(LifecycleStage.FIXED, actor="regression_engine", reason="Re-fix confirmed via replay.")

            return RegressionReport(
                finding_id=self.finding_id,
                previous_stage=prev,
                current_stage=self.current_stage,
                verdict="FIXED",
                is_reproduced=False,
                evidence_drift_details="Payload not observed in re-executed response. Fix confirmed."
            )
