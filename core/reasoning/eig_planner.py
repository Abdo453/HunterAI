"""
HunterAI V27.0 - Deterministic EIG Experiment Planner
=====================================================
Strictly deterministic Expected Information Gain (EIG) experiment planner.
Eradicates LLM hallucination or arbitrary priority picking.

Decision Pipeline:
  1. Scope Constraint Filter (Scope Guard)
  2. Risk Budget Constraint Filter (Risk Manager)
  3. Attack Surface Dependency Check (Prerequisites satisfied in Graph)
  4. Negative Evidence Boundary Filter (Avoid re-testing exact defended context)
  5. Deterministic EIG Scoring:
       EIG(E) = (ΔH(Belief) * Novelty(Context) * InvariantWeight) / (RiskCost * Latency)
  6. Deterministic Queue Ordering & Next Experiment Selection
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from core.burp_gateway.experiment_contract import ExperimentContract
from core.reasoning.attack_surface_graph import AttackSurfaceGraph, EpistemicStatus
from core.reasoning.negative_evidence import BoundaryScope, NuancedNegativeEvidenceLedger

logger = logging.getLogger("hunter_ai.eig_planner")


class PlanSelectionStatus(str, Enum):
    SCHEDULED = "SCHEDULED"
    SKIPPED_SCOPE = "SKIPPED_SCOPE"
    SKIPPED_RISK = "SKIPPED_RISK"
    BLOCKED_DEPENDENCY = "BLOCKED_DEPENDENCY"
    PRUNED_NEGATIVE_BOUNDARY = "PRUNED_NEGATIVE_BOUNDARY"
    EXECUTED = "EXECUTED"


@dataclass
class PlannedExperiment:
    contract: ExperimentContract
    composite_score: float = 0.0
    information_gain: float = 0.25
    novelty_score: float = 1.0
    invariant_weight: float = 1.0
    risk_cost: float = 0.5
    latency_estimate: float = 0.2
    status: PlanSelectionStatus = PlanSelectionStatus.SCHEDULED
    filter_reason: Optional[str] = None
    enqueued_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract": self.contract.to_dict(),
            "composite_score": round(self.composite_score, 4),
            "information_gain": round(self.information_gain, 4),
            "novelty_score": round(self.novelty_score, 4),
            "invariant_weight": round(self.invariant_weight, 4),
            "risk_cost": round(self.risk_cost, 4),
            "latency_estimate": round(self.latency_estimate, 4),
            "status": self.status.value,
            "filter_reason": self.filter_reason,
            "enqueued_at": self.enqueued_at,
        }


class DeterministicEIGPlanner:
    """
    Ranks and selects candidate experiments using purely deterministic mathematical filters.
    The LLM proposes candidate hypotheses; this planner enforces ground-truth feasibility.
    """

    def __init__(
        self,
        surface_graph: AttackSurfaceGraph,
        negative_ledger: NuancedNegativeEvidenceLedger,
        allowed_scope: Optional[List[str]] = None,
        global_risk_budget: float = 50.0,
    ):
        self.surface_graph = surface_graph
        self.negative_ledger = negative_ledger
        self.allowed_scope = allowed_scope or ["target.local"]
        self.global_risk_budget = global_risk_budget
        self.risk_consumed: float = 0.0

        self.queue: List[PlannedExperiment] = []
        self.history: List[PlannedExperiment] = []
        self.endpoint_probe_counts: Dict[str, int] = {}

        self.category_priors: Dict[str, float] = {
            "CROSS_TENANT_ISOLATION_BREACH": 0.50,
            "VERTICAL_PRIVILEGE_ESCALATION": 0.50,
            "HORIZONTAL_BOLA_IDOR": 0.50,
            "COMMAND_INJECTION": 0.50,
            "SQLI": 0.50,
            "DOUBLE_EXECUTION": 0.50,
            "STEP_SKIPPING": 0.50,
            "REVOKED_SESSION_REUSE": 0.50,
        }

    def _is_in_scope(self, endpoint: str) -> bool:
        if not self.allowed_scope:
            return True
        ep_lower = endpoint.lower()
        return any(s.lower() in ep_lower for s in self.allowed_scope) or self.surface_graph.target_domain.lower() in ep_lower

    def _calculate_novelty(self, endpoint: str) -> float:
        count = self.endpoint_probe_counts.get(endpoint, 0)
        return 1.0 / (1.0 + 0.5 * count)

    def _get_invariant_weight(self, category: str) -> float:
        weights = {
            "COMMAND_INJECTION": 1.00,
            "CROSS_TENANT_ISOLATION_BREACH": 1.00,
            "SQLI": 0.95,
            "VERTICAL_PRIVILEGE_ESCALATION": 0.95,
            "HORIZONTAL_BOLA_IDOR": 0.90,
            "DOUBLE_EXECUTION": 0.85,
            "STEP_SKIPPING": 0.80,
            "REVOKED_SESSION_REUSE": 0.75,
        }
        return weights.get(category, 0.60)

    def _calculate_entropy_gain(self, category: str) -> float:
        p = self.category_priors.get(category, 0.50)
        # Bernoulli variance ΔH = p * (1 - p)
        return max(0.01, p * (1.0 - p))

    def evaluate_and_enqueue(self, contract: ExperimentContract) -> PlannedExperiment:
        endpoint = contract.target_endpoint or "/"
        cat = getattr(contract, "category", "GENERAL")
        risk = max(0.1, float(getattr(contract, "risk_budget", 0.5)))
        latency = 0.25

        planned = PlannedExperiment(
            contract=contract,
            risk_cost=risk,
            latency_estimate=latency,
            invariant_weight=self._get_invariant_weight(cat),
            information_gain=self._calculate_entropy_gain(cat),
            novelty_score=self._calculate_novelty(endpoint),
        )

        # 1. Scope Constraint Filter
        if not self._is_in_scope(endpoint):
            planned.status = PlanSelectionStatus.SKIPPED_SCOPE
            planned.filter_reason = f"Endpoint '{endpoint}' is outside authorized scope."
            self.queue.append(planned)
            return planned

        # 2. Dependency / State Prerequisite Constraint Filter
        precondition = getattr(contract, "state_precondition", None)
        if precondition and precondition in self.surface_graph.nodes:
            state_node = self.surface_graph.nodes[precondition]
            if state_node.epistemic_status in (EpistemicStatus.REJECTED, EpistemicStatus.BLOCKED):
                planned.status = PlanSelectionStatus.BLOCKED_DEPENDENCY
                planned.filter_reason = f"Prerequisite state '{precondition}' is in invalid state ({state_node.epistemic_status.value})."
                self.queue.append(planned)
                return planned

        # 3. Negative Evidence Exact Boundary Filter
        actor_id = contract.identity_context
        res_id = str(contract.mutation_plan.get("resource_id", ""))
        scope = BoundaryScope(
            endpoint=endpoint,
            http_method=getattr(contract, "http_method", "GET"),
            actor_id=actor_id,
            target_resource_id=res_id,
        )
        if self.negative_ledger.is_exact_context_tested(scope):
            planned.status = PlanSelectionStatus.PRUNED_NEGATIVE_BOUNDARY
            planned.filter_reason = f"Exact context {scope.context_key} already proven defended."
            self.queue.append(planned)
            return planned

        # 4. Risk Budget Constraint Filter
        if self.risk_consumed + risk > self.global_risk_budget:
            planned.status = PlanSelectionStatus.SKIPPED_RISK
            planned.filter_reason = "Exceeds remaining global risk budget."
            self.queue.append(planned)
            return planned

        # 5. Deterministic Composite Score Calculation
        # EIG = (ΔH * Novelty * InvariantWeight) / (RiskCost * Latency)
        planned.composite_score = (
            (planned.information_gain * planned.novelty_score * planned.invariant_weight)
            / (planned.risk_cost * planned.latency_estimate)
        )
        planned.status = PlanSelectionStatus.SCHEDULED

        self.queue.append(planned)
        self.queue.sort(key=lambda p: p.composite_score, reverse=True)
        return planned

    def enqueue_candidates(self, contracts: List[ExperimentContract]) -> int:
        for c in contracts:
            self.evaluate_and_enqueue(c)
        return sum(1 for p in self.queue if p.status == PlanSelectionStatus.SCHEDULED)

    def select_next_experiment(self) -> Optional[ExperimentContract]:
        """Selects highest ranked experiment whose status is SCHEDULED."""
        for item in self.queue:
            if item.status == PlanSelectionStatus.SCHEDULED:
                if self.risk_consumed + item.risk_cost <= self.global_risk_budget:
                    item.status = PlanSelectionStatus.EXECUTED
                    self.risk_consumed += item.risk_cost
                    self.endpoint_probe_counts[item.contract.target_endpoint] = (
                        self.endpoint_probe_counts.get(item.contract.target_endpoint, 0) + 1
                    )
                    return item.contract
                else:
                    item.status = PlanSelectionStatus.SKIPPED_RISK
                    item.filter_reason = "Risk budget exceeded at dispatch time."

        return None
