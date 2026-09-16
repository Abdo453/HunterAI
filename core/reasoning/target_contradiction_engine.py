"""
HunterAI Epistemic Target Contradiction Engine
=============================================
Identifies inconsistencies in the target application's security posture:
- Observed Authorization Rules vs Replay Behavior
- Status Code discrepancies with Leaked Body Content
- Perimeter Gateway claims vs Backend Reality
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.target_contradiction")


class ContradictionType(str, Enum):
    AUTHZ_MODEL_INCONSISTENCY = "AUTHZ_MODEL_INCONSISTENCY"
    STATUS_BODY_DESYNC = "STATUS_BODY_DESYNC"
    GATEWAY_BACKEND_DISCREPANCY = "GATEWAY_BACKEND_DISCREPANCY"
    STATE_TRANSITION_CONFLICT = "STATE_TRANSITION_CONFLICT"


@dataclass
class TargetContradiction:
    contradiction_id: str
    contradiction_type: ContradictionType
    endpoint: str
    claim_a: str
    claim_b: str
    differential_proof: str
    suggested_hypothesis: str
    severity: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contradiction_id": self.contradiction_id,
            "contradiction_type": self.contradiction_type.value,
            "endpoint": self.endpoint,
            "claim_a": self.claim_a,
            "claim_b": self.claim_b,
            "differential_proof": self.differential_proof,
            "suggested_hypothesis": self.suggested_hypothesis,
            "severity": self.severity,
        }


class TargetContradictionEngine:
    """
    Evaluates conflicting facts across probes to discover subtle architectural flaws.
    """

    def __init__(self):
        self.contradictions: List[TargetContradiction] = []

    def evaluate_authorization_behavior(
        self,
        endpoint: str,
        standard_response: Dict[str, Any],
        tampered_response: Dict[str, Any],
        tampering_description: str
    ) -> Optional[TargetContradiction]:
        """
        Detects when an endpoint strictly forbids access normally, but permits it
        under subtle header/parameter alterations (e.g. gateway override).
        """
        std_status = standard_response.get("status", 403)
        mod_status = tampered_response.get("status", 200)
        mod_body = tampered_response.get("body", "")

        # Contradiction: Standard request is 403 Forbidden, but tampered request returns 200 with sensitive/valid data
        has_data = len(mod_body) > 40 and not any(err in mod_body.lower() for err in ["forbidden", "denied", "error"])
        if std_status == 403 and mod_status == 200 and has_data:
            c = TargetContradiction(
                contradiction_id=f"CONTRA-{uuid.uuid4().hex[:6].upper()}",
                contradiction_type=ContradictionType.GATEWAY_BACKEND_DISCREPANCY,
                endpoint=endpoint,
                claim_a="Standard request receives HTTP 403 Forbidden (Enforced at Gateway).",
                claim_b=f"Request with {tampering_description} yields HTTP 200 OK with valid response body.",
                differential_proof=f"Status 403 vs 200 with content length delta: {len(mod_body)} bytes.",
                suggested_hypothesis=f"PERIMETER_GATEWAY_AUTH_BYPASS on {endpoint} via {tampering_description}.",
                severity="CRITICAL"
            )
            self.contradictions.append(c)
            return c
        return None

    def evaluate_status_body_desync(
        self,
        endpoint: str,
        response_status: int,
        response_body: str,
        expected_sensitive_marker: str
    ) -> Optional[TargetContradiction]:
        """
        Detects when an endpoint returns an error status code (e.g. 401/403/500)
        yet leaks full sensitive user/tenant records in the response body.
        """
        if response_status in (401, 403, 500) and expected_sensitive_marker in response_body:
            c = TargetContradiction(
                contradiction_id=f"CONTRA-{uuid.uuid4().hex[:6].upper()}",
                contradiction_type=ContradictionType.STATUS_BODY_DESYNC,
                endpoint=endpoint,
                claim_a=f"Endpoint signaled authorization failure with HTTP {response_status}.",
                claim_b=f"Response body leaked sensitive target object marker '{expected_sensitive_marker}'.",
                differential_proof=f"HTTP {response_status} with sensitive data payload in body.",
                suggested_hypothesis=f"STATUS_MASKED_INFORMATION_LEAK on {endpoint}.",
                severity="HIGH"
            )
            self.contradictions.append(c)
            return c
        return None
