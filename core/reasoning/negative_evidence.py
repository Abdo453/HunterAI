"""
HunterAI V27.0 - Nuanced Negative Evidence & Boundary Scoping
============================================================
Prevents False Negatives caused by premature pruning or universal claims:
  - Receiving HTTP 403 on (/api/resource/42, user_A) proves ONLY:
    "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT"
  - It does NOT declare the application globally secure.
  - Other resource IDs, parameters, and unexplored permutations remain "UNKNOWN"
    or "CANDIDATE" so they can still be investigated if justified.

Provides fine-grained context scoping:
  (actor_id, tenant_id, endpoint, parameter, resource_id) -> BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.negative_evidence")


@dataclass
class BoundaryScope:
    """The precise context parameters defining the security boundary."""
    endpoint: str
    http_method: str = "GET"
    actor_id: str = "anonymous"
    target_resource_id: str = ""
    target_tenant_id: str = ""
    mutation_parameter: str = ""

    @property
    def context_key(self) -> str:
        return f"{self.http_method}:{self.endpoint}:{self.actor_id}:{self.target_resource_id}:{self.mutation_parameter}"

    @property
    def context_hash(self) -> str:
        return hashlib.sha256(self.context_key.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NegativeObservation:
    """
    A concrete negative observable indicating that an attempted invariant violation
    was rejected by the application defense mechanism.
    """
    observation_id: str
    scope: BoundaryScope
    observed_status: int
    observed_body_snippet: str
    conclusion: str = "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT"
    unexplored_transitions_status: str = "UNKNOWN"
    provenance_id: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "scope": self.scope.to_dict(),
            "observed_status": self.observed_status,
            "observed_body_snippet": self.observed_body_snippet,
            "conclusion": self.conclusion,
            "unexplored_transitions_status": self.unexplored_transitions_status,
            "provenance_id": self.provenance_id,
            "timestamp": self.timestamp,
        }


class NuancedNegativeEvidenceLedger:
    """
    Tracks tested defense boundaries without making dangerous universal claims.
    Guarantees that unexplored transitions remain UNKNOWN.
    """

    def __init__(self):
        self.observations: List[NegativeObservation] = []
        self._tested_context_hashes: Set[str] = set()

    def record_defense(
        self,
        scope: BoundaryScope,
        status_code: int,
        body_snippet: str = "",
        provenance_id: str = "",
    ) -> NegativeObservation:
        obs_id = f"neg_obs_{uuid.uuid4().hex[:8]}"
        obs = NegativeObservation(
            observation_id=obs_id,
            scope=scope,
            observed_status=status_code,
            observed_body_snippet=body_snippet[:200],
            conclusion="BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT",
            unexplored_transitions_status="UNKNOWN",
            provenance_id=provenance_id,
        )
        self.observations.append(obs)
        self._tested_context_hashes.add(scope.context_hash)

        logger.info(
            f"[NEGATIVE EVIDENCE] Recorded defense: {scope.context_key} -> {status_code} "
            f"({obs.conclusion}, unexplored transitions remain UNKNOWN)"
        )
        return obs

    def is_exact_context_tested(self, scope: BoundaryScope) -> bool:
        """Checks if this exact context has already been tested and confirmed defended."""
        return scope.context_hash in self._tested_context_hashes

    def get_boundary_status(self, scope: BoundaryScope) -> str:
        """
        Returns BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT if tested,
        or UNKNOWN if this specific permutation has not yet been directly observed.
        """
        if self.is_exact_context_tested(scope):
            return "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT"
        return "UNKNOWN"

    def export_ledger(self) -> List[Dict[str, Any]]:
        return [o.to_dict() for o in self.observations]
