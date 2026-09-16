"""
HunterAI Burp ↔ Brain Correlation Context
=========================================
Maintains strict causal provenance for every HTTP transaction passing between
HunterAI's Cognitive Brain and Burp Suite:
- engagement_id: Unique engagement / assessment identifier
- transaction_id: Persistent ID for this specific HTTP exchange
- hypothesis_id: ID of the active reasoning hypothesis driving the request
- experiment_id: ID of the structured scientific experiment
- parent_transaction_id: Upstream baseline transaction being mutated or reproduced
- identity_id: Active principal context (User A, User B, Admin, Anonymous)
- intent: Human- and machine-readable explanation of why the request is made
- action_type: Semantic action (REPLAY, EXPERIMENT, MUTATION, OBSERVE, VERIFY)

Provides automatic HTTP header injection/extraction via X-HunterAI-* standard headers.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


HEADER_PREFIX = "X-HunterAI-"
HDR_ENGAGEMENT_ID = "X-HunterAI-Engagement-ID"
HDR_TRANSACTION_ID = "X-HunterAI-Transaction-ID"
HDR_HYPOTHESIS_ID = "X-HunterAI-Hypothesis-ID"
HDR_EXPERIMENT_ID = "X-HunterAI-Experiment-ID"
HDR_PARENT_ID = "X-HunterAI-Parent-ID"
HDR_IDENTITY_ID = "X-HunterAI-Identity-ID"
HDR_INTENT = "X-HunterAI-Intent"
HDR_ACTION_TYPE = "X-HunterAI-Action-Type"


@dataclass
class BurpCorrelationContext:
    """
    Structured Correlation Context binding Burp transactions to Brain hypotheses.
    Answers: Why was this request sent? Who requested it? What hypothesis generated it?
    """
    engagement_id: str = field(default_factory=lambda: f"eng_{uuid.uuid4().hex[:8]}")
    transaction_id: str = field(default_factory=lambda: f"tx_{uuid.uuid4().hex[:10]}")
    hypothesis_id: Optional[str] = None
    experiment_id: Optional[str] = None
    parent_transaction_id: Optional[str] = None
    identity_id: Optional[str] = "ANONYMOUS"
    intent: str = "Autonomous Security Telemetry Ingestion"
    action_type: str = "OBSERVE"
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_headers(self) -> Dict[str, str]:
        """Injects correlation context into HTTP request headers."""
        hdrs = {
            HDR_ENGAGEMENT_ID: str(self.engagement_id),
            HDR_TRANSACTION_ID: str(self.transaction_id),
            HDR_IDENTITY_ID: str(self.identity_id or "ANONYMOUS"),
            HDR_INTENT: str(self.intent or ""),
            HDR_ACTION_TYPE: str(self.action_type or "OBSERVE"),
        }
        if self.hypothesis_id:
            hdrs[HDR_HYPOTHESIS_ID] = str(self.hypothesis_id)
        if self.experiment_id:
            hdrs[HDR_EXPERIMENT_ID] = str(self.experiment_id)
        if self.parent_transaction_id:
            hdrs[HDR_PARENT_ID] = str(self.parent_transaction_id)
        return hdrs

    @classmethod
    def from_headers(cls, headers: Dict[str, str]) -> BurpCorrelationContext:
        """Extracts correlation context from incoming HTTP headers (case-insensitive)."""
        norm_map = {k.lower(): v for k, v in headers.items()}

        def _get(hdr_name: str) -> Optional[str]:
            return norm_map.get(hdr_name.lower())

        return cls(
            engagement_id=_get(HDR_ENGAGEMENT_ID) or f"eng_{uuid.uuid4().hex[:8]}",
            transaction_id=_get(HDR_TRANSACTION_ID) or f"tx_{uuid.uuid4().hex[:10]}",
            hypothesis_id=_get(HDR_HYPOTHESIS_ID),
            experiment_id=_get(HDR_EXPERIMENT_ID),
            parent_transaction_id=_get(HDR_PARENT_ID),
            identity_id=_get(HDR_IDENTITY_ID) or "ANONYMOUS",
            intent=_get(HDR_INTENT) or "Passive Observation",
            action_type=_get(HDR_ACTION_TYPE) or "OBSERVE",
            created_at=time.time(),
        )

    def spawn_child(
        self,
        action_type: str = "MUTATION",
        intent: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        experiment_id: Optional[str] = None,
    ) -> BurpCorrelationContext:
        """Spawns a child correlation context rooted at this transaction."""
        return BurpCorrelationContext(
            engagement_id=self.engagement_id,
            transaction_id=f"tx_{uuid.uuid4().hex[:10]}",
            hypothesis_id=hypothesis_id or self.hypothesis_id,
            experiment_id=experiment_id or self.experiment_id,
            parent_transaction_id=self.transaction_id,
            identity_id=self.identity_id,
            intent=intent or f"Follow-up child action for {self.transaction_id}",
            action_type=action_type,
            created_at=time.time(),
            metadata=dict(self.metadata),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BurpCorrelationContext:
        valid = {
            "engagement_id", "transaction_id", "hypothesis_id", "experiment_id",
            "parent_transaction_id", "identity_id", "intent", "action_type",
            "created_at", "metadata"
        }
        filtered = {k: v for k, v in data.items() if k in valid}
        return cls(**filtered)
