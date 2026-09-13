"""
HunterAI Scientific Experiment Engine
=====================================
Applies the scientific method and tripartite control testing:
1. Baseline: Unmodified request establishing normal target response.
2. Harmless Control: Benign mutated input (e.g. arithmetic equality '1=1').
3. Active Test: Candidate payload designed to trigger vulnerability.

Inviolable Decision Equations:
Condition 1: Baseline ≈ Harmless Control (Ensures environment stability)
Condition 2: Active Test ≠ Harmless Control (Proves causality of probe)
If Baseline ≠ Harmless Control: Target is unstable; claim is non-causal.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ExperimentPhase(str, Enum):
    HYPOTHESIS = "HYPOTHESIS"
    BASELINE_PROBE = "BASELINE_PROBE"
    HARMLESS_CONTROL = "HARMLESS_CONTROL"
    ACTIVE_PROBE = "ACTIVE_PROBE"
    DIFFERENTIAL_ANALYSIS = "DIFFERENTIAL_ANALYSIS"
    EVIDENCE_VERIFICATION = "EVIDENCE_VERIFICATION"


@dataclass
class TripartiteObservation:
    baseline_status: int
    baseline_length: int
    baseline_body: str
    control_status: int
    control_length: int
    control_body: str
    active_status: int
    active_length: int
    active_body: str
    expected_canary: Optional[str] = None


@dataclass
class ExperimentResult:
    is_conclusive: bool
    is_causal_vulnerability: bool
    baseline_stable: bool
    active_divergent: bool
    confidence: float
    rationale: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ScientificExperimentEngine:
    """Rigorous scientific hypothesis tester enforcing tripartite control logic"""

    @classmethod
    def evaluate_tripartite_experiment(cls, obs: TripartiteObservation) -> ExperimentResult:
        # Step 1: Evaluate Baseline Stability against Harmless Control
        status_match = (obs.baseline_status == obs.control_status)
        len_delta = abs(obs.baseline_length - obs.control_length)
        # Allow slight dynamic content drift (e.g. CSRF token, timestamp <= 50 bytes)
        baseline_stable = status_match and (len_delta <= 50)

        if not baseline_stable:
            return ExperimentResult(
                is_conclusive=False,
                is_causal_vulnerability=False,
                baseline_stable=False,
                active_divergent=False,
                confidence=0.10,
                rationale=(
                    f"INCONCLUSIVE: Target environment is non-deterministic. "
                    f"Harmless control diverged from baseline (Status: {obs.baseline_status} vs {obs.control_status}, "
                    f"Length Δ: {len_delta} bytes). Cannot prove causality."
                )
            )

        # Step 2: Evaluate Active Test divergence against Harmless Control
        # A. High-order proof: Canary token executed/reflected in active test but NOT in control
        if obs.expected_canary and (obs.expected_canary in obs.active_body) and (obs.expected_canary not in obs.control_body):
            return ExperimentResult(
                is_conclusive=True,
                is_causal_vulnerability=True,
                baseline_stable=True,
                active_divergent=True,
                confidence=0.99,
                rationale=f"CONFIRMED: Proof of execution canary '{obs.expected_canary}' verified exclusively in active test."
            )

        # B. Behavioral divergence: Active test triggered error, status change, or massive length change
        active_status_divergent = (obs.active_status != obs.control_status)
        active_len_delta = abs(obs.active_length - obs.control_length)
        active_divergent = active_status_divergent or (active_len_delta > 100)

        if active_divergent:
            return ExperimentResult(
                is_conclusive=True,
                is_causal_vulnerability=True,
                baseline_stable=True,
                active_divergent=True,
                confidence=0.85,
                rationale=(
                    f"CONFIRMED: Statistically significant divergence observed in active test "
                    f"(Status: {obs.active_status} vs Control {obs.control_status}, Length Δ: {active_len_delta} bytes)."
                )
            )

        # Active test produced no divergence from harmless control
        return ExperimentResult(
            is_conclusive=True,
            is_causal_vulnerability=False,
            baseline_stable=True,
            active_divergent=False,
            confidence=0.95,
            rationale="SAFE: Active test produced identical behavior to harmless control."
        )
