"""
HunterAI V27.0 - Bayesian Experiment Scheduler
===============================================
Information-Theoretic Security Experiment Scheduler.
Prioritizes experiments to maximize Information Gain (ΔI) while minimizing
risk, operational footprint, and execution latency.

Ranking Formula:
  Rank(E) = (ΔI(Belief) * Novelty * Evidence_Value) / (Risk_Cost * Latency)

Orchestrator Loop:
  Observe -> Generate Candidates -> Rank/Deduplicate -> Select Next ->
  Execute (BCSL) -> Update Beliefs & Prune -> Loop
"""
from __future__ import annotations

import logging
import math
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from core.burp_gateway.experiment_contract import ExperimentContract

logger = logging.getLogger("hunter_ai.experiment_scheduler")


class ExperimentQueueStatus(str, Enum):
    QUEUED = "QUEUED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    PRUNED = "PRUNED"
    SKIPPED_RISK = "SKIPPED_RISK"


@dataclass
class ScheduledExperiment:
    contract: ExperimentContract
    rank_score: float = 0.0
    information_gain: float = 0.25
    novelty_score: float = 1.0
    evidence_value: float = 1.0
    risk_cost: float = 0.5
    latency_estimate: float = 0.2
    status: ExperimentQueueStatus = ExperimentQueueStatus.QUEUED
    enqueued_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    prune_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract": self.contract.to_dict(),
            "rank_score": round(self.rank_score, 4),
            "information_gain": round(self.information_gain, 4),
            "novelty_score": round(self.novelty_score, 4),
            "evidence_value": round(self.evidence_value, 4),
            "risk_cost": round(self.risk_cost, 4),
            "latency_estimate": round(self.latency_estimate, 4),
            "status": self.status.value,
            "enqueued_at": self.enqueued_at,
            "completed_at": self.completed_at,
            "prune_reason": self.prune_reason,
        }


class BayesianExperimentScheduler:
    """
    Ranks, schedules, and prunes autonomous experiments based on Bayesian
    uncertainty reduction and risk optimization.
    """

    def __init__(self, global_risk_budget: float = 50.0):
        self.global_risk_budget = global_risk_budget
        self.risk_consumed: float = 0.0
        self.queue: List[ScheduledExperiment] = []
        self.history: List[ScheduledExperiment] = []
        self.endpoint_probe_counts: Dict[str, int] = {}
        self.category_priors: Dict[str, float] = {
            "CROSS_TENANT_ISOLATION_BREACH": 0.50,
            "VERTICAL_PRIVILEGE_ESCALATION": 0.50,
            "HORIZONTAL_BOLA_IDOR": 0.50,
            "REVOKED_SESSION_REUSE": 0.50,
            "STEP_SKIPPING": 0.50,
            "DOUBLE_EXECUTION": 0.50,
            "PREMATURE_INVOCATION": 0.50,
            "POST_COMPLETION_TAMPER": 0.50,
            "ILLEGAL_STATE_JUMP": 0.50,
        }

    def _calculate_evidence_value(self, category: str) -> float:
        """Assigns theoretical evidence value based on vulnerability impact."""
        values = {
            "CROSS_TENANT_ISOLATION_BREACH": 1.00,
            "VERTICAL_PRIVILEGE_ESCALATION": 0.95,
            "HORIZONTAL_BOLA_IDOR": 0.90,
            "DOUBLE_EXECUTION": 0.85,
            "REVOKED_SESSION_REUSE": 0.80,
            "STEP_SKIPPING": 0.75,
            "ILLEGAL_STATE_JUMP": 0.70,
            "PREMATURE_INVOCATION": 0.65,
            "POST_COMPLETION_TAMPER": 0.60,
        }
        return values.get(category, 0.50)

    def _calculate_information_gain(self, category: str) -> float:
        """
        Computes expected Shannon entropy / variance reduction:
        Maximal uncertainty (prior = 0.5) gives ΔI = 0.25.
        Near certainty (prior = 0.05 or 0.95) gives ΔI near 0.04.
        """
        p = self.category_priors.get(category, 0.50)
        # Variance of Bernoulli: p * (1 - p)
        return max(0.01, p * (1.0 - p))

    def _calculate_novelty(self, endpoint: str) -> float:
        """Novelty decays hyperbolically with the number of times an endpoint was probed."""
        count = self.endpoint_probe_counts.get(endpoint, 0)
        return 1.0 / (1.0 + 0.5 * count)

    def enqueue_candidate(self, contract: ExperimentContract) -> ScheduledExperiment:
        """
        Calculates scores, ranks, and enqueues an individual ExperimentContract.
        """
        cat = getattr(contract, "category", "GENERAL")
        endpoint = contract.target_endpoint or "/"

        delta_i = self._calculate_information_gain(cat)
        novelty = self._calculate_novelty(endpoint)
        ev_val = self._calculate_evidence_value(cat)
        risk_cost = max(0.1, float(getattr(contract, "risk_budget", 0.5)))
        latency = 0.25

        # Rank formula: (ΔI * Novelty * EvidenceValue) / (RiskCost * Latency)
        rank = (delta_i * novelty * ev_val) / (risk_cost * latency)

        scheduled = ScheduledExperiment(
            contract=contract,
            rank_score=rank,
            information_gain=delta_i,
            novelty_score=novelty,
            evidence_value=ev_val,
            risk_cost=risk_cost,
            latency_estimate=latency,
            status=ExperimentQueueStatus.QUEUED,
        )
        self.queue.append(scheduled)
        # Keep queue sorted descending by rank
        self.queue.sort(key=lambda s: s.rank_score, reverse=True)
        return scheduled

    def enqueue_candidates(self, contracts: List[ExperimentContract]) -> int:
        """Enqueues a batch of contracts and returns count of enqueued items."""
        for c in contracts:
            self.enqueue_candidate(c)
        return len(contracts)

    def select_next_experiment(self) -> Optional[ExperimentContract]:
        """
        Selects the highest-ranked viable experiment that fits within the global risk budget.
        """
        for item in self.queue:
            if item.status == ExperimentQueueStatus.QUEUED:
                if self.risk_consumed + item.risk_cost <= self.global_risk_budget:
                    item.status = ExperimentQueueStatus.EXECUTING
                    return item.contract
                else:
                    item.status = ExperimentQueueStatus.SKIPPED_RISK
                    item.prune_reason = "Exceeds remaining global risk budget"

        return None

    def record_execution_result(
        self,
        contract: ExperimentContract,
        verdict: str,
        is_proven_vulnerability: bool = False,
    ):
        """
        Updates internal Bayesian priors, records execution, and increments probe counts.
        """
        cat = getattr(contract, "category", "GENERAL")
        endpoint = contract.target_endpoint or "/"

        # Update endpoint probe count
        self.endpoint_probe_counts[endpoint] = self.endpoint_probe_counts.get(endpoint, 0) + 1

        # Deduct risk
        risk_cost = float(getattr(contract, "risk_budget", 0.5))
        self.risk_consumed += risk_cost

        # Find matching scheduled item in queue
        matched_item: Optional[ScheduledExperiment] = None
        for item in self.queue:
            if item.contract.experiment_id == contract.experiment_id or (
                item.contract.hypothesis_id == contract.hypothesis_id and item.status == ExperimentQueueStatus.EXECUTING
            ):
                matched_item = item
                break

        if matched_item:
            matched_item.status = ExperimentQueueStatus.COMPLETED
            matched_item.completed_at = time.time()
            self.history.append(matched_item)
            self.queue.remove(matched_item)

        # Bayesian Prior Update
        current_p = self.category_priors.get(cat, 0.50)
        if is_proven_vulnerability:
            # Shift prior upward (vulnerability exists in this subsystem)
            new_p = min(0.95, current_p + 0.15)
        else:
            # Shift prior downward (boundary is enforced)
            new_p = max(0.05, current_p - 0.15)
        self.category_priors[cat] = new_p

        logger.info(
            f"[SCHEDULER] Completed {contract.experiment_id} ({cat}): "
            f"verdict={verdict}, prior {current_p:.2f} -> {new_p:.2f}"
        )

    def prune_equivalent_experiments(
        self,
        category: Optional[str] = None,
        target_endpoint: Optional[str] = None,
        reason: str = "Defense boundary verified; equivalent probes pruned",
    ) -> int:
        """
        Online Dynamic Pruning:
        When an invariant boundary is confirmed (e.g. 403 on tenant A -> tenant B),
        all equivalent candidate experiments targeting the same invariant or endpoint
        are removed from the queue to prevent redundant noise and unnecessary HTTP traffic.
        """
        pruned_count = 0
        remaining_queue: List[ScheduledExperiment] = []

        for item in self.queue:
            if item.status != ExperimentQueueStatus.QUEUED:
                remaining_queue.append(item)
                continue

            match_cat = (category is None) or (getattr(item.contract, "category", "") == category)
            match_ep = (target_endpoint is None) or (item.contract.target_endpoint == target_endpoint)

            if match_cat and match_ep:
                item.status = ExperimentQueueStatus.PRUNED
                item.prune_reason = reason
                item.completed_at = time.time()
                self.history.append(item)
                pruned_count += 1
            else:
                remaining_queue.append(item)

        self.queue = remaining_queue
        logger.info(f"[SCHEDULER] Pruned {pruned_count} equivalent experiments ({reason}).")
        return pruned_count

    def get_status_summary(self) -> Dict[str, Any]:
        """Returns JSON metrics of the scheduling state."""
        return {
            "global_risk_budget": self.global_risk_budget,
            "risk_consumed": round(self.risk_consumed, 2),
            "remaining_risk": round(max(0.0, self.global_risk_budget - self.risk_consumed), 2),
            "queued_count": sum(1 for item in self.queue if item.status == ExperimentQueueStatus.QUEUED),
            "executing_count": sum(1 for item in self.queue if item.status == ExperimentQueueStatus.EXECUTING),
            "completed_count": len(self.history),
            "pruned_count": sum(1 for item in self.history if item.status == ExperimentQueueStatus.PRUNED),
            "category_priors": {k: round(v, 3) for k, v in self.category_priors.items()},
        }
