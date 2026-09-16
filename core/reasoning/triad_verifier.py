"""
HunterAI V27.0 - Metamorphic Triad Verifier (B x C x E1 x E2)
============================================================
Provides rigorous causal differentiation between real security behavior,
benign input handling, dynamic jitter, and noise:
  - B  (Baseline):   Unperturbed normal transaction
  - C  (Control):    Harmless syntactic mutation (no exploit semantics)
  - E1 (Security 1): Primary security probe mutation
  - E2 (Security 2): Semantically equivalent metamorphic probe mutation

Core Epistemic Rules:
  1. Observation != Vulnerability
  2. PoE != Vulnerability Proof
  3. C == E1 implies False Positive (benign mutation produced identical shift)
  4. B == E1 implies Ineffective Probe (zero observable differentiation)
  5. E1 != E2 in expected invariant implies Contradiction -> UNVERIFIED / PARTIALLY_VERIFIED
  6. E1 == E2 conforming to predicted causal invariant proves causal differentiation
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.triad_verifier")


@dataclass
class TransactionSnapshot:
    """Standardized representation of an observed HTTP transaction in the triad."""
    request_id: str = ""
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    body_length: int = 0
    round_trip_ms: float = 0.0
    extracted_tokens: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.body and not self.body_length:
            self.body_length = len(self.body)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TransactionSnapshot:
        if not data:
            return cls()
        body_str = str(data.get("body") or data.get("resp_body") or "")
        hdrs = data.get("headers") or data.get("resp_headers") or {}
        hdrs_normalized = {str(k).lower(): str(v) for k, v in hdrs.items()}
        status = int(data.get("status_code") or data.get("status") or 200)
        req_id = str(data.get("request_id") or data.get("tx_id") or "")
        return cls(
            request_id=req_id,
            status_code=status,
            headers=hdrs_normalized,
            body=body_str,
            body_length=len(body_str),
            round_trip_ms=float(data.get("round_trip_ms") or 0.0),
            extracted_tokens=list(data.get("extracted_tokens", [])),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TriadBundle:
    """The four-part interaction bundle for metamorphic causal verification."""
    hypothesis_id: str
    target_endpoint: str
    baseline: TransactionSnapshot
    control: TransactionSnapshot
    experiment_1: TransactionSnapshot
    experiment_2: TransactionSnapshot
    expected_metamorphic_relation: str = ""
    target_parameter: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "target_endpoint": self.target_endpoint,
            "baseline": self.baseline.to_dict(),
            "control": self.control.to_dict(),
            "experiment_1": self.experiment_1.to_dict(),
            "experiment_2": self.experiment_2.to_dict(),
            "expected_metamorphic_relation": self.expected_metamorphic_relation,
            "target_parameter": self.target_parameter,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class TriadVerificationResult:
    is_causally_differentiated: bool
    control_divergence_explained: bool
    metamorphic_consistency: bool
    contradiction_detected: bool
    confidence_score: float
    rationale: str
    diff_metrics: Dict[str, Any] = field(default_factory=dict)
    epistemic_verdict: str = "UNVERIFIED"  # CONFIRMED, REJECTED, UNVERIFIED, PARTIALLY_VERIFIED

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TriadVerifier:
    """
    Evaluates the B x C x E1 x E2 triad deterministically.
    Ensures that response differences are causally tied to security semantics,
    not benign input variation or server-side dynamic jitter.
    """

    @classmethod
    def verify_triad(
        cls,
        bundle: TriadBundle,
        custom_invariant_evaluator: Optional[Callable[[TransactionSnapshot, TransactionSnapshot], Tuple[bool, str]]] = None,
    ) -> TriadVerificationResult:
        b = bundle.baseline
        c = bundle.control
        e1 = bundle.experiment_1
        e2 = bundle.experiment_2

        # Compute basic structural metrics
        len_diff_bc = abs(c.body_length - b.body_length)
        len_diff_ce1 = abs(e1.body_length - c.body_length)
        len_diff_e1e2 = abs(e2.body_length - e1.body_length)

        status_change_c = (c.status_code != b.status_code)
        status_change_e1 = (e1.status_code != c.status_code)
        status_consistent_e = (e1.status_code == e2.status_code)

        diff_metrics = {
            "len_diff_bc": len_diff_bc,
            "len_diff_ce1": len_diff_ce1,
            "len_diff_e1e2": len_diff_e1e2,
            "status_b": b.status_code,
            "status_c": c.status_code,
            "status_e1": e1.status_code,
            "status_e2": e2.status_code,
        }

        # 1. Metamorphic Invariant Evaluation across E1 and E2 (Check Contradiction first)
        if custom_invariant_evaluator:
            invariant_passed, invariant_reason = custom_invariant_evaluator(e1, e2)
            if not invariant_passed:
                # Contradiction: E1 claimed something, but metamorphic variation E2 refuted it
                return TriadVerificationResult(
                    is_causally_differentiated=False,
                    control_divergence_explained=True,
                    metamorphic_consistency=False,
                    contradiction_detected=True,
                    confidence_score=0.35,
                    rationale=f"Metamorphic Contradiction: E1 and E2 yielded inconsistent invariant results ({invariant_reason}).",
                    diff_metrics=diff_metrics,
                    epistemic_verdict="PARTIALLY_VERIFIED",
                )
        else:
            # Default structural metamorphic check: E1 and E2 must have concordant status
            if not status_consistent_e:
                return TriadVerificationResult(
                    is_causally_differentiated=False,
                    control_divergence_explained=True,
                    metamorphic_consistency=False,
                    contradiction_detected=True,
                    confidence_score=0.40,
                    rationale=f"Metamorphic Contradiction: Status divergence between E1 ({e1.status_code}) and E2 ({e2.status_code}).",
                    diff_metrics=diff_metrics,
                    epistemic_verdict="PARTIALLY_VERIFIED",
                )

        # 2. Check for Zero Differentiation (E1 produced no change from B or C)
        if e1.status_code == b.status_code and e1.status_code == c.status_code and len_diff_ce1 < 5 and abs(e1.body_length - b.body_length) < 5:
            return TriadVerificationResult(
                is_causally_differentiated=False,
                control_divergence_explained=True,
                metamorphic_consistency=False,
                contradiction_detected=False,
                confidence_score=0.1,
                rationale="Probe E1 produced no meaningful differentiation from Baseline (B) or Control (C).",
                diff_metrics=diff_metrics,
                epistemic_verdict="UNVERIFIED",
            )

        # 3. Check for Control Equivalence (C produced the exact same shift as E1 and E2)
        # If adding benign text causes identical response as E1, behavior is benign input handling.
        if e1.status_code == c.status_code and abs(e1.body_length - c.body_length) < 5 and e1.body == c.body:
            return TriadVerificationResult(
                is_causally_differentiated=False,
                control_divergence_explained=False,
                metamorphic_consistency=False,
                contradiction_detected=False,
                confidence_score=0.05,
                rationale="Control mutation (C) produced identical response as security probe (E1). Effect is benign input handling or noise.",
                diff_metrics=diff_metrics,
                epistemic_verdict="REJECTED",
            )

        # 4. Successful Causal Differentiation
        return TriadVerificationResult(
            is_causally_differentiated=True,
            control_divergence_explained=True,
            metamorphic_consistency=True,
            contradiction_detected=False,
            confidence_score=0.95,
            rationale="Causal Triad passed: E1 differentiated from Control (C) and confirmed by Metamorphic probe (E2).",
            diff_metrics=diff_metrics,
            epistemic_verdict="CONFIRMED",
        )
