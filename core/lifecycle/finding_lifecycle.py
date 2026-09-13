"""
HunterAI Finding Lifecycle & Remediation Tracking
=================================================
Manages full end-to-end finding lifecycle:
DISCOVERED -> TRIAGED -> NEEDS_REVIEW -> CONFIRMED -> REPORTED -> FIXED -> RETESTED -> CLOSED
"""
from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional


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


class FindingLifecycleManager:
    """Governs lifecycle transitions and verification of security fixes"""

    def __init__(self, finding_id: str):
        self.finding_id = finding_id
        self.current_stage: LifecycleStage = LifecycleStage.DISCOVERED
        self.stage_history: List[Dict[str, Any]] = [{
            "stage": LifecycleStage.DISCOVERED.value,
            "timestamp": time.time(),
            "reason": "Finding initially discovered."
        }]

    def transition_to(self, new_stage: LifecycleStage, actor: str = "agent", reason: str = "") -> LifecycleStage:
        self.current_stage = new_stage
        self.stage_history.append({
            "stage": new_stage.value,
            "timestamp": time.time(),
            "actor": actor,
            "reason": reason
        })
        return self.current_stage

    def mark_fixed(self, retest_notes: str = "Fix confirmed by replay re-test") -> LifecycleStage:
        return self.transition_to(LifecycleStage.FIXED, actor="retest_engine", reason=retest_notes)

    def mark_regressed(self, retest_notes: str = "Vulnerability re-emerged on retest") -> LifecycleStage:
        return self.transition_to(LifecycleStage.REGRESSED, actor="retest_engine", reason=retest_notes)