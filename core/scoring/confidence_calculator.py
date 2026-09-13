"""
HunterAI Multidimensional Confidence Calculator
================================================
Eliminates arbitrary LLM confidence floats. Computes confidence deterministically
from 6 verifiable empirical factors:
1. Evidence Score (0.30): PoE verification strength (arithmetic/canary proof)
2. Differential Signal (0.25): Baseline vs Probe vs Control difference
3. Reproducibility (0.15): Number of independent successful reproductions
4. Tool Agreement (0.15): Consensus across Burp, Browser, HTTP diff, PoE
5. Negative Test Result (0.15): Control/benign probe produced neutral output
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class ConfidenceFactors:
    evidence_score: float = 0.0          # 0.0 to 1.0 (Proof of Execution strength)
    differential_signal: float = 0.0     # 0.0 to 1.0 (Distinct baseline vs probe diff)
    reproducibility: float = 0.0         # 0.0 or 1.0 (Independent reproduction)
    tool_agreement: float = 0.0          # 0.0 to 1.0 (Consensus between tools)
    negative_test_result: float = 1.0    # 1.0 = benign control was normal, 0.0 = control also triggered anomaly
    is_reflection_only: bool = False     # Input echoed without DOM context breakout


class MultidimensionalConfidenceCalculator:
    """Deterministic Confidence Calculator enforcing strict empirical caps"""

    @classmethod
    def calculate(cls, factors: ConfidenceFactors) -> float:
        # Inviolable Cap 1: Reflection without execution cannot be confirmed
        if factors.is_reflection_only:
            return 0.05

        # Inviolable Cap 2: If benign control payload also triggered anomaly, behavior is NOT causal
        if factors.negative_test_result < 0.5:
            return 0.15

        # Weighted calculation
        raw_score = (
            0.30 * min(1.0, max(0.0, factors.evidence_score)) +
            0.25 * min(1.0, max(0.0, factors.differential_signal)) +
            0.15 * min(1.0, max(0.0, factors.reproducibility)) +
            0.15 * min(1.0, max(0.0, factors.tool_agreement)) +
            0.15 * min(1.0, max(0.0, factors.negative_test_result))
        )

        return round(raw_score, 2)
