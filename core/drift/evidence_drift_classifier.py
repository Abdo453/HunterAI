"""
HunterAI Evidence Drift & Replay Classifier
===========================================
When a previously confirmed vulnerability is re-tested (Replayed), if the original
vulnerable behavior is no longer observed, this engine classifies the exact cause
of divergence rather than naively announcing "Vulnerability Fixed!".

Possible Drift Classifications:
1. VULNERABILITY_GENUINELY_FIXED: Safe status, sanitized input, or proper authorization check.
2. AUTH_SESSION_EXPIRED: 401 Unauthorized or redirected to login.
3. PERMISSIONS_REVOKED: 403 Forbidden without proper remediation.
4. WAF_OR_RATE_LIMIT_BLOCKED: Cloudflare/AWS WAF challenge or HTTP 429.
5. ENDPOINT_DECOMMISSIONED: HTTP 404 / 410.
6. HOST_UNREACHABLE_OR_TIMEOUT: Network socket failure, server down.
7. INCONCLUSIVE_DIVERGENCE: Ambiguous state change requiring human operator intervention.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class DriftClassification(str, Enum):
    VULNERABILITY_GENUINELY_FIXED = "VULNERABILITY_GENUINELY_FIXED"
    AUTH_SESSION_EXPIRED = "AUTH_SESSION_EXPIRED"
    PERMISSIONS_REVOKED = "PERMISSIONS_REVOKED"
    WAF_OR_RATE_LIMIT_BLOCKED = "WAF_OR_RATE_LIMIT_BLOCKED"
    ENDPOINT_DECOMMISSIONED = "ENDPOINT_DECOMMISSIONED"
    HOST_UNREACHABLE_OR_TIMEOUT = "HOST_UNREACHABLE_OR_TIMEOUT"
    VULNERABILITY_STILL_EXISTS = "VULNERABILITY_STILL_EXISTS"
    INCONCLUSIVE_DIVERGENCE = "INCONCLUSIVE_DIVERGENCE"


@dataclass
class DriftVerdict:
    finding_id: str
    classification: DriftClassification
    confidence: float
    causal_explanation: str
    recommended_action: str
    original_status: int
    current_status: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "classification": self.classification.value,
            "confidence": round(self.confidence, 2),
            "causal_explanation": self.causal_explanation,
            "recommended_action": self.recommended_action,
            "original_status": self.original_status,
            "current_status": self.current_status,
        }


class EvidenceDriftClassifier:
    """Classifies root causes of replay divergence during regression verification"""

    WAF_SIGNATURES = ["cf-ray", "cloudflare", "awswaf", "mod_security", "captcha", "attention required"]

    @classmethod
    def classify_replay(
        cls,
        finding_id: str,
        original_evidence: Dict[str, Any],
        current_response: Dict[str, Any],
        baseline_response: Optional[Dict[str, Any]] = None
    ) -> DriftVerdict:
        orig_status = original_evidence.get("status_code", 200)
        curr_status = current_response.get("status_code", 200)
        curr_body = current_response.get("body", "")
        curr_headers = {k.lower(): v.lower() for k, v in current_response.get("headers", {}).items()}
        expected_proof = original_evidence.get("proof_nonce", "")

        # 1. Vulnerability Still Exists if proof nonce is present
        if expected_proof and expected_proof in curr_body:
            return DriftVerdict(
                finding_id=finding_id,
                classification=DriftClassification.VULNERABILITY_STILL_EXISTS,
                confidence=1.0,
                causal_explanation=f"Replay reproduced exact proof nonce '{expected_proof}'. The vulnerability is active.",
                recommended_action="Keep finding status as CONFIRMED. Escalate to engineering.",
                original_status=orig_status,
                current_status=curr_status,
            )

        # 2. Host Timeout or Unreachable
        if current_response.get("is_timeout", False) or curr_status == 0 or curr_status == 504:
            return DriftVerdict(
                finding_id=finding_id,
                classification=DriftClassification.HOST_UNREACHABLE_OR_TIMEOUT,
                confidence=0.95,
                causal_explanation="Target host is unreachable or connection timed out during replay.",
                recommended_action="Do not close finding. Re-queue replay when target host recovers.",
                original_status=orig_status,
                current_status=curr_status,
            )

        # 3. WAF or Rate Limit
        if curr_status == 429 or any(sig in curr_body.lower() for sig in cls.WAF_SIGNATURES) or any(sig in str(curr_headers) for sig in cls.WAF_SIGNATURES):
            return DriftVerdict(
                finding_id=finding_id,
                classification=DriftClassification.WAF_OR_RATE_LIMIT_BLOCKED,
                confidence=0.95,
                causal_explanation="Replay blocked by WAF challenge or HTTP 429 throttling.",
                recommended_action="Do not declare fixed. Request operator bypass token or reduce replay frequency.",
                original_status=orig_status,
                current_status=curr_status,
            )

        # 4. Auth Session Expired
        if curr_status == 401 or ("/login" in curr_body.lower() and curr_status in (302, 301, 200)):
            return DriftVerdict(
                finding_id=finding_id,
                classification=DriftClassification.AUTH_SESSION_EXPIRED,
                confidence=0.90,
                causal_explanation="Authentication credentials expired; target returned 401 or redirected to login.",
                recommended_action="Do not close finding. Refresh session credentials and re-execute replay.",
                original_status=orig_status,
                current_status=curr_status,
            )

        # 5. Endpoint Decommissioned
        if curr_status in (404, 410):
            return DriftVerdict(
                finding_id=finding_id,
                classification=DriftClassification.ENDPOINT_DECOMMISSIONED,
                confidence=0.90,
                causal_explanation=f"Target route returned HTTP {curr_status}. The endpoint appears to be removed.",
                recommended_action="Mark finding as REMOVED_WITH_ENDPOINT.",
                original_status=orig_status,
                current_status=curr_status,
            )

        # 6. Genuinely Fixed (Safe validation, input sanitized, parameterized response)
        # If baseline is 200 OK but active payload no longer leaks proof and returns clean response
        if curr_status in (200, 400) and expected_proof not in curr_body:
            return DriftVerdict(
                finding_id=finding_id,
                classification=DriftClassification.VULNERABILITY_GENUINELY_FIXED,
                confidence=0.92,
                causal_explanation="Endpoint is alive and accessible, but exploit payload is safely rejected or sanitized without proof leakage.",
                recommended_action="Mark finding as RESOLVED_VERIFIED. Record fix in SecurityMemoryGraph.",
                original_status=orig_status,
                current_status=curr_status,
            )

        # 7. Inconclusive
        return DriftVerdict(
            finding_id=finding_id,
            classification=DriftClassification.INCONCLUSIVE_DIVERGENCE,
            confidence=0.60,
            causal_explanation=f"Ambiguous response divergence: HTTP {curr_status} without clear fix or error pattern.",
            recommended_action="Flag for human peer review before altering finding status.",
            original_status=orig_status,
            current_status=curr_status,
        )
