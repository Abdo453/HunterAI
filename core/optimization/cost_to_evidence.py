"""
HunterAI Cost-to-Evidence Optimizer
===================================
Optimizes active testing plans to achieve decisive forensic evidence with the
minimum number of HTTP requests and socket round-trips.

Equation:
Maximize: InformationGain(E)
Subject to: Min Requests & Zero Destructive Actions
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class ExperimentCandidate:
    experiment_id: str
    name: str
    expected_information_gain: float  # 0.0 to 100.0
    request_cost: int                 # Number of HTTP requests
    is_state_mutating: bool = False
    is_definitive_nonce: bool = False

    @property
    def efficiency_ratio(self) -> float:
        if self.request_cost <= 0:
            return 0.0
        # Boost definitive nonces because they produce 100% court-grade proof
        weight = 1.25 if self.is_definitive_nonce else 1.0
        return (self.expected_information_gain / self.request_cost) * weight


@dataclass
class OptimizedExperimentPlan:
    target_threshold: float
    total_expected_gain: float
    total_request_cost: int
    selected_experiments: List[ExperimentCandidate] = field(default_factory=list)
    omitted_experiments: List[ExperimentCandidate] = field(default_factory=list)
    savings_percentage: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_threshold": self.target_threshold,
            "total_expected_gain": round(self.total_expected_gain, 1),
            "total_request_cost": self.total_request_cost,
            "selected_count": len(self.selected_experiments),
            "selected_experiments": [e.name for e in self.selected_experiments],
            "omitted_count": len(self.omitted_experiments),
            "savings_percentage": f"{round(self.savings_percentage, 1)}%",
        }


class CostToEvidenceOptimizer:
    """Greedy knapsack optimizer prioritizing maximum information yield per request"""

    @classmethod
    def optimize_plan(
        cls,
        candidates: List[ExperimentCandidate],
        target_evidence_threshold: float = 80.0
    ) -> OptimizedExperimentPlan:
        if not candidates:
            return OptimizedExperimentPlan(target_evidence_threshold, 0.0, 0)

        # Sort candidates descending by efficiency ratio
        sorted_candidates = sorted(candidates, key=lambda c: c.efficiency_ratio, reverse=True)

        selected: List[ExperimentCandidate] = []
        omitted: List[ExperimentCandidate] = []
        accumulated_gain = 0.0
        accumulated_cost = 0

        # Greedy selection until evidence threshold is satisfied
        for cand in sorted_candidates:
            if accumulated_gain < target_evidence_threshold:
                selected.append(cand)
                accumulated_gain += cand.expected_information_gain
                accumulated_cost += cand.request_cost
            else:
                omitted.append(cand)

        total_unoptimized_cost = sum(c.request_cost for c in candidates)
        savings = (
            ((total_unoptimized_cost - accumulated_cost) / total_unoptimized_cost) * 100.0
            if total_unoptimized_cost > 0 else 0.0
        )

        return OptimizedExperimentPlan(
            target_threshold=target_evidence_threshold,
            total_expected_gain=accumulated_gain,
            total_request_cost=accumulated_cost,
            selected_experiments=selected,
            omitted_experiments=omitted,
            savings_percentage=max(0.0, savings)
        )
