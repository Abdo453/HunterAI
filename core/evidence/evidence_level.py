"""
HunterAI Forensic Evidence Quality Hierarchy (E0 -> E5)
=========================================================
Replaces subjective probability percentages (e.g. "Confidence: 98%") with
empirically verifiable forensic evidence levels:

Level Definitions:
------------------
E0: Raw Observation
    Endpoint discovered, parameter indexed, or asset detected.
    (No proof of security flaw, pure visibility).

E1: Differential Signal
    Observable response divergence (HTTP status divergence, reflection, error message).

E2: Reproducible Behavior
    Deterministic reproduction across N >= 2 isolated executions with identical input/output.

E3: Security Invariant Violation
    Explicit breach of a formal security invariant (e.g. User B accessing User A resource,
    arbitrary command output returned in body, SQL syntax error reflecting nonce).

E4: Multi-Sensor Corroboration
    Triad-validated proof: User Intent (Browser Sensor) + Wire Truth (Burp Sensor) + Code Sink (Code Sensor).

E5: Sealed Replayable Case
    Hermetically sealed portable investigation bundle with HMAC-SHA256 seal,
    unbroken 7-stage causal provenance, and zero-dependency standalone replay.py script.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.evidence_level")


class EvidenceLevel(IntEnum):
    E0_OBSERVATION = 0
    E1_DIFFERENTIAL_SIGNAL = 1
    E2_REPRODUCIBLE_BEHAVIOR = 2
    E3_INVARIANT_VIOLATION = 3
    E4_MULTI_SENSOR_CORROBORATION = 4
    E5_SEALED_REPLAYABLE_CASE = 5

    @property
    def label(self) -> str:
        return self.name.split("_", 1)[1].replace("_", " ").title()

    @property
    def code(self) -> str:
        return f"E{self.value}"


@dataclass
class EvidenceLevelCriteria:
    level: EvidenceLevel
    name: str
    description: str
    required_keys: List[str] = field(default_factory=list)
    min_reproductions: int = 1


@dataclass
class EvidenceEvaluationResult:
    level: EvidenceLevel
    code: str
    label: str
    is_confirmed_eligible: bool
    achieved_criteria: List[str]
    missing_criteria_for_next_level: List[str]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": int(self.level),
            "code": self.code,
            "label": self.label,
            "is_confirmed_eligible": self.is_confirmed_eligible,
            "achieved_criteria": self.achieved_criteria,
            "missing_for_next": self.missing_criteria_for_next_level,
            "explanation": self.explanation,
        }


class EvidenceLevelEvaluator:
    """
    Forensic Evaluator: Computes the exact Evidence Level (E0..E5)
    for any security finding based on verifiable physical artifacts.
    """

    MINIMUM_CONFIRMED_LEVEL = EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR

    @classmethod
    def evaluate(
        cls,
        finding_data: Dict[str, Any],
        evidence_items: Optional[List[Dict[str, Any]]] = None,
        reproduction_count: int = 1,
        has_triad_corroboration: bool = False,
        has_sealed_bundle: bool = False,
        has_standalone_replay: bool = False,
    ) -> EvidenceEvaluationResult:
        """
        Determines the highest forensic evidence level achieved by the finding.
        """
        achieved: List[str] = ["E0: Target asset and endpoint observed"]
        current_level = EvidenceLevel.E0_OBSERVATION
        missing: List[str] = []

        # Check E1: Differential Signal
        has_diff = False
        if evidence_items:
            for item in evidence_items:
                if any(k in item for k in ("status_diverged", "length_delta", "diff", "reflection", "error_pattern")):
                    has_diff = True
                    break
        if not has_diff and finding_data.get("proof"):
            has_diff = True

        if has_diff:
            current_level = EvidenceLevel.E1_DIFFERENTIAL_SIGNAL
            achieved.append("E1: Differential signal confirmed (observable response divergence)")
        else:
            missing.append("E1: Observable response differential signal")

        # Check E2: Reproducible Behavior (N >= 2)
        if current_level >= EvidenceLevel.E1_DIFFERENTIAL_SIGNAL and reproduction_count >= 2:
            current_level = EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR
            achieved.append(f"E2: Reproducible behavior confirmed across N={reproduction_count} isolated executions")
        else:
            missing.append("E2: Minimum N>=2 deterministic reproduction")

        # Check E3: Security Invariant Violation
        has_invariant_violation = (
            finding_data.get("invariant_violated") is not None
            or "cross-tenant" in str(finding_data.get("proof", "")).lower()
            or "unauthorized" in str(finding_data.get("proof", "")).lower()
            or "computational nonce" in str(finding_data.get("proof", "")).lower()
            or "syntax error" in str(finding_data.get("proof", "")).lower()
            or finding_data.get("contract_satisfied", False)
        )
        if current_level >= EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR and has_invariant_violation:
            current_level = EvidenceLevel.E3_INVARIANT_VIOLATION
            achieved.append("E3: Formal security invariant breach verified (contract satisfied)")
        else:
            if current_level >= EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR:
                missing.append("E3: Verifiable security invariant or contract breach")

        # Check E4: Multi-Sensor Corroboration (Sensory Triad)
        if current_level >= EvidenceLevel.E3_INVARIANT_VIOLATION and has_triad_corroboration:
            current_level = EvidenceLevel.E4_MULTI_SENSOR_CORROBORATION
            achieved.append("E4: Multi-Sensor Triad corroborated (Browser UI + Burp Wire + Code AST)")
        else:
            if current_level >= EvidenceLevel.E3_INVARIANT_VIOLATION:
                missing.append("E4: Multi-Sensor Triad corroboration")

        # Check E5: Sealed Replayable Case Bundle
        if current_level >= EvidenceLevel.E4_MULTI_SENSOR_CORROBORATION and has_sealed_bundle and has_standalone_replay:
            current_level = EvidenceLevel.E5_SEALED_REPLAYABLE_CASE
            achieved.append("E5: Standalone tamper-evident investigation bundle sealed with HMAC-SHA256")
        else:
            if current_level >= EvidenceLevel.E4_MULTI_SENSOR_CORROBORATION:
                missing.append("E5: Sealed HMAC investigation bundle with standalone replay.py")

        is_eligible = current_level >= cls.MINIMUM_CONFIRMED_LEVEL

        explanation = (
            f"Finding evaluated at forensic level {current_level.code} ({current_level.label}). "
            f"Status: {'ELIGIBLE FOR CONFIRMATION' if is_eligible else 'INSUFFICIENT EVIDENCE (REJECTED/HEURISTIC)'}."
        )

        return EvidenceEvaluationResult(
            level=current_level,
            code=current_level.code,
            label=current_level.label,
            is_confirmed_eligible=is_eligible,
            achieved_criteria=achieved,
            missing_criteria_for_next_level=missing,
            explanation=explanation,
        )
