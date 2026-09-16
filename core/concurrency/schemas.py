"""
HunterAI Concurrency & Race Condition Testing Schemas
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class RaceTargetType(str, Enum):
    FINANCIAL_TRANSACTION = "FINANCIAL_TRANSACTION"
    COUPON_REDEMPTION = "COUPON_REDEMPTION"
    PASSWORD_RESET = "PASSWORD_RESET"
    INVITE_CODE = "INVITE_CODE"
    FILE_OPERATION = "FILE_OPERATION"


@dataclass
class RaceConditionFinding:
    """Formal finding emitted when concurrent requests cause a TOCTOU state corruption"""
    finding_id: str
    target_endpoint: str
    race_type: RaceTargetType
    parallel_requests_sent: int
    successful_requests_count: int
    pre_race_state: Dict[str, Any]
    post_race_state: Dict[str, Any]
    state_mutation_delta: Dict[str, Any]
    is_race_confirmed: bool
    evidence_proof: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "target_endpoint": self.target_endpoint,
            "race_type": self.race_type.value,
            "parallel_requests_sent": self.parallel_requests_sent,
            "successful_requests_count": self.successful_requests_count,
            "pre_race_state": self.pre_race_state,
            "post_race_state": self.post_race_state,
            "state_mutation_delta": self.state_mutation_delta,
            "is_race_confirmed": self.is_race_confirmed,
            "evidence_proof": self.evidence_proof,
        }
