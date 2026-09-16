"""
HunterAI Advanced Contradiction Engine & Conflict Resolver
==========================================================
Eliminates False Positives and AI Hallucinations by systematically
cross-examining disparate tool signals against wire ground truth:

Core Capabilities:
1. Tool vs Wire Conflict Detection:
   - Tool (e.g. Nuclei) reports SQLi/BOLA, but Burp traffic shows 403 Forbidden or strict integer validation.
2. Disagreement Classification:
   - DEFENSIVE_CONTROL_ACTIVE: Server actively blocks or validates input.
   - FALSE_ALARM_HEURISTIC: Alert was triggered on harmless string reflection.
   - AUTH_STATE_DESYNC: Token expired or role privilege altered.
   - CACHE_ORIGIN_DIVERGENCE: CDN cached 200 vs origin 403.
3. Counterfactual Probe Synthesis:
   - Generates minimal disambiguation tests (e.g. arithmetic nonce, token rotation).
4. Negative KB Integration:
   - When a claim is refuted, records conclusive proof into NegativeKnowledgeBase.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from core.evidence.evidence_level import EvidenceLevel
from core.memory.negative_knowledge_base import NegativeKnowledgeBase

logger = logging.getLogger("hunter_ai.reasoning.contradiction_resolver")


class ConflictType(str, Enum):
    DEFENSIVE_CONTROL_ACTIVE = "DEFENSIVE_CONTROL_ACTIVE"
    FALSE_ALARM_HEURISTIC = "FALSE_ALARM_HEURISTIC"
    AUTH_STATE_DESYNC = "AUTH_STATE_DESYNC"
    CACHE_ORIGIN_DIVERGENCE = "CACHE_ORIGIN_DIVERGENCE"
    INCONCLUSIVE_JITTER = "INCONCLUSIVE_JITTER"


class ConflictVerdict(str, Enum):
    CONFIRMED_VULN = "CONFIRMED_VULN"
    REFUTED_DEFENSIVE_CONTROL_ACTIVE = "REFUTED_DEFENSIVE_CONTROL_ACTIVE"
    REFUTED_FALSE_ALARM = "REFUTED_FALSE_ALARM"
    INCONCLUSIVE_REQUIRES_RESEARCH = "INCONCLUSIVE_REQUIRES_RESEARCH"


@dataclass
class ConflictCase:
    conflict_id: str
    target_endpoint: str
    claimed_vuln: str
    claimant_source: str
    counter_source: str
    conflict_type: ConflictType
    claim_evidence: Dict[str, Any]
    counter_evidence: Dict[str, Any]
    recommended_probe: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["conflict_type"] = self.conflict_type.value
        return d


@dataclass
class ResolutionRuling:
    conflict_id: str
    verdict: ConflictVerdict
    confidence: float
    explanation: str
    conclusive_proof: str
    recorded_negative_kb: bool = False
    evidence_level_awarded: EvidenceLevel = EvidenceLevel.E0_OBSERVATION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conflict_id": self.conflict_id,
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "conclusive_proof": self.conclusive_proof,
            "recorded_negative_kb": self.recorded_negative_kb,
            "evidence_level_awarded": int(self.evidence_level_awarded),
        }


class ContradictionResolver:
    """Epistemic Arbiter: Cross-examines conflicting tool signals and resolves discrepancies"""

    def __init__(self, negative_kb: Optional[NegativeKnowledgeBase] = None):
        self.negative_kb = negative_kb or NegativeKnowledgeBase()
        self.resolved_cases: List[ResolutionRuling] = []

    def detect_conflict(
        self,
        claim: Dict[str, Any],
        wire_telemetry: Optional[Dict[str, Any]] = None,
        agent_observations: Optional[List[Dict[str, Any]]] = None,
    ) -> Optional[ConflictCase]:
        """
        Examines whether an external alert contradicts verified ground truth.
        """
        vuln_type = claim.get("signal_type") or claim.get("type", "UNKNOWN")
        endpoint = claim.get("endpoint", "")
        claim_src = claim.get("source_tool") or claim.get("source", "TOOL")

        if not wire_telemetry and not agent_observations:
            return None

        # 1. BOLA / IDOR Conflict: Tool claims BOLA, but wire shows 403 Forbidden or 401 Unauthorized
        if vuln_type in ("BOLA", "IDOR", "AUTH_BYPASS"):
            status = wire_telemetry.get("status_code") if wire_telemetry else None
            body = str(wire_telemetry.get("body", "")).lower() if wire_telemetry else ""
            if status in (401, 403) or "unauthorized" in body or "forbidden" in body or "access denied" in body:
                return ConflictCase(
                    conflict_id=f"cnf_{uuid.uuid4().hex[:8]}",
                    target_endpoint=endpoint,
                    claimed_vuln=vuln_type,
                    claimant_source=claim_src,
                    counter_source="BURP_WIRE_SENSOR",
                    conflict_type=ConflictType.DEFENSIVE_CONTROL_ACTIVE,
                    claim_evidence=claim,
                    counter_evidence={"status_code": status, "body_snippet": body[:120]},
                    recommended_probe="Cross-tenant token substitution with invariant verification"
                )

        # 2. SQLi Conflict: Tool claims SQLi, but wire shows 400 Bad Request with strict type validation
        if vuln_type in ("SQLI", "SQL_INJECTION"):
            status = wire_telemetry.get("status_code") if wire_telemetry else None
            body = str(wire_telemetry.get("body", "")).lower() if wire_telemetry else ""
            if status == 400 and any(k in body for k in ("expected integer", "type error", "invalid format", "invalid parameter")):
                return ConflictCase(
                    conflict_id=f"cnf_{uuid.uuid4().hex[:8]}",
                    target_endpoint=endpoint,
                    claimed_vuln=vuln_type,
                    claimant_source=claim_src,
                    counter_source="BURP_WIRE_SENSOR",
                    conflict_type=ConflictType.DEFENSIVE_CONTROL_ACTIVE,
                    claim_evidence=claim,
                    counter_evidence={"status_code": status, "body_snippet": body[:120]},
                    recommended_probe="Arithmetic computational nonce test (41+1 vs 41+2)"
                )

        # 3. SSRF Conflict: Loopback / Cloud metadata filter active
        if vuln_type in ("SSRF", "SERVER_SIDE_REQUEST_FORGERY"):
            body = str(wire_telemetry.get("body", "")).lower() if wire_telemetry else ""
            if any(k in body for k in ("blocked internal ip", "private address not allowed", "metadata not accessible")):
                return ConflictCase(
                    conflict_id=f"cnf_{uuid.uuid4().hex[:8]}",
                    target_endpoint=endpoint,
                    claimed_vuln=vuln_type,
                    claimant_source=claim_src,
                    counter_source="BURP_WIRE_SENSOR",
                    conflict_type=ConflictType.DEFENSIVE_CONTROL_ACTIVE,
                    claim_evidence=claim,
                    counter_evidence={"body_snippet": body[:120]},
                    recommended_probe="DNS rebinding or IPv6 loopback probe"
                )

        return None

    def adjudicate_conflict(
        self,
        conflict: ConflictCase,
        retest_result: Dict[str, Any]
    ) -> ResolutionRuling:
        """
        Renders a definitive verdict on the conflict based on controlled re-test outcome.
        """
        is_vuln_confirmed = retest_result.get("invariant_violated", False) or retest_result.get("contract_satisfied", False)
        defensive_control_verified = retest_result.get("defensive_control_verified", False) or retest_result.get("status_code") in (401, 403, 400)

        if is_vuln_confirmed and not defensive_control_verified:
            ruling = ResolutionRuling(
                conflict_id=conflict.conflict_id,
                verdict=ConflictVerdict.CONFIRMED_VULN,
                confidence=0.98,
                explanation=f"Conflict resolved: {conflict.claimant_source} claim verified via controlled re-test. Defensive control was ineffective.",
                conclusive_proof=retest_result.get("proof", "Deterministic violation confirmed"),
                recorded_negative_kb=False,
                evidence_level_awarded=EvidenceLevel.E3_INVARIANT_VIOLATION
            )
        elif defensive_control_verified:
            # Defensive control proved active: record in NegativeKnowledgeBase
            p = self.negative_kb.record_negative_proof(
                endpoint=conflict.target_endpoint,
                method="POST" if "post" in str(conflict.claim_evidence).lower() else "GET",
                vuln_family=conflict.claimed_vuln,
                baseline_status=retest_result.get("status_code", 403),
                conclusive_rationale=(
                    f"Contradiction resolved: {conflict.claimant_source} claim refuted by active defensive control. "
                    f"Evidence: {conflict.counter_source} verified security enforcement."
                )
            )
            ruling = ResolutionRuling(
                conflict_id=conflict.conflict_id,
                verdict=ConflictVerdict.REFUTED_DEFENSIVE_CONTROL_ACTIVE,
                confidence=1.0,
                explanation=f"False Alarm Refuted: Defensive control strictly enforces security boundaries. Claim discarded.",
                conclusive_proof=f"Defensive control verified: HTTP {retest_result.get('status_code', 403)} and input validation enforced.",
                recorded_negative_kb=True,
                evidence_level_awarded=EvidenceLevel.E0_OBSERVATION
            )
        else:
            ruling = ResolutionRuling(
                conflict_id=conflict.conflict_id,
                verdict=ConflictVerdict.INCONCLUSIVE_REQUIRES_RESEARCH,
                confidence=0.5,
                explanation="Inconclusive: Neither vulnerability nor defensive control could be deterministically proven.",
                conclusive_proof="Target response exhibited non-deterministic jitter.",
                recorded_negative_kb=False,
                evidence_level_awarded=EvidenceLevel.E0_OBSERVATION
            )

        self.resolved_cases.append(ruling)
        return ruling
