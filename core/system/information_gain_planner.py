"""
HunterAI Information Gain Planner (Phase 14)
============================================
Optimizes exploration via data-driven decision making:
  1. calculate_information_gain(task, data): estimates value of an action
  2. select_next_task(): chooses highest expected-value task
  3. update_memory(): refines internal model based on outcomes
"""
from __future__ import annotations

import logging
import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.eig_planner")


@dataclass
class TaskCandidate:
    task_id: str
    action: str
    target: str
    estimated_gain: float = 0.0
    cost: float = 1.0
    executed: bool = False
    outcome: Optional[Dict[str, Any]] = None

    @property
    def expected_value(self) -> float:
        """Expected value = gain / max(cost, 0.01)"""
        return self.estimated_gain / max(self.cost, 0.01)


class InformationGainPlanner:
    """
    Prioritizes reconnaissance and testing actions by their estimated
    information gain relative to their execution cost.
    """
    def __init__(self):
        self._candidates: Dict[str, TaskCandidate] = {}
        self._memory: Dict[str, Any] = {
            "domain_coverage": 0.0,
            "endpoint_coverage": 0.0,
            "confirmed_vulns": [],
            "explored_tasks": [],
        }
        self._action_base_gains: Dict[str, float] = {
            "subdomain_enum": 8.0,
            "port_scan": 5.0,
            "http_probe": 4.0,
            "crawl": 7.0,
            "fuzz_params": 6.0,
            "js_analysis": 5.5,
            "nuclei_scan": 9.0,
            "differential_test": 10.0,
            "verify_finding": 10.0,
            "report": 1.0,
        }
        self._action_base_costs: Dict[str, float] = {
            "subdomain_enum": 1.0,
            "port_scan": 2.0,
            "http_probe": 1.5,
            "crawl": 2.0,
            "fuzz_params": 3.0,
            "js_analysis": 1.5,
            "nuclei_scan": 5.0,
            "differential_test": 4.0,
            "verify_finding": 3.5,
            "report": 0.5,
        }

    def add_candidate(self, task_id: str, action: str, target: str, metadata: Optional[Dict[str, Any]] = None) -> TaskCandidate:
        base_gain = self._action_base_gains.get(action, 3.0)
        base_cost = self._action_base_costs.get(action, 2.0)

        # Adjust gain based on memory context
        if action == "subdomain_enum" and self._memory["domain_coverage"] > 0.8:
            base_gain *= 0.3  # Diminishing returns
        if action == "verify_finding" and len(self._memory["confirmed_vulns"]) == 0:
            base_gain *= 1.5  # High value when no findings yet

        cand = TaskCandidate(
            task_id=task_id,
            action=action,
            target=target,
            estimated_gain=round(base_gain, 3),
            cost=round(base_cost, 3),
        )
        self._candidates[task_id] = cand
        return cand

    def calculate_information_gain(self, task_id: str, data: Dict[str, Any]) -> float:
        """
        Estimates information gain value for a task based on observable data signals.
        Signals: novel endpoints, unique parameters, new subdomains discovered, etc.
        """
        base = self._candidates.get(task_id)
        if not base:
            return 0.0

        gain = base.estimated_gain

        # Boost for novel discovery signals
        new_endpoints = len(data.get("new_endpoints", []))
        new_params = len(data.get("new_parameters", []))
        new_subdomains = len(data.get("new_subdomains", []))
        has_vuln_signal = bool(data.get("vuln_signal"))

        # Logarithmic information gain model
        if new_endpoints > 0:
            gain += 2.0 * math.log1p(new_endpoints)
        if new_params > 0:
            gain += 1.5 * math.log1p(new_params)
        if new_subdomains > 0:
            gain += 3.0 * math.log1p(new_subdomains)
        if has_vuln_signal:
            gain += 5.0

        return round(gain, 3)

    def select_next_task(self) -> Optional[TaskCandidate]:
        """
        Selects the pending task with highest expected value (EV = gain / cost).
        """
        pending = [c for c in self._candidates.values() if not c.executed]
        if not pending:
            return None
        return max(pending, key=lambda c: c.expected_value)

    def mark_executed(self, task_id: str, outcome: Dict[str, Any]) -> None:
        cand = self._candidates.get(task_id)
        if cand:
            cand.executed = True
            cand.outcome = outcome

    def update_memory(self, task_id: str, outcome: Dict[str, Any]) -> None:
        """
        Refines internal memory model based on task outcomes,
        updating coverage estimates and confirmed vulnerabilities.
        """
        cand = self._candidates.get(task_id)
        if not cand:
            return

        self.mark_executed(task_id, outcome)
        self._memory["explored_tasks"].append(task_id)

        # Update coverage estimates
        total_candidates = max(len(self._candidates), 1)
        explored = len(self._memory["explored_tasks"])
        self._memory["domain_coverage"] = min(1.0, round(explored / total_candidates, 3))

        new_eps = outcome.get("new_endpoints", [])
        if new_eps:
            current = int(self._memory.get("endpoint_count", 0))
            self._memory["endpoint_count"] = current + len(new_eps)

        # Track confirmed vulnerabilities
        if outcome.get("verdict") == "CONFIRMED":
            vuln_record = {
                "task_id": task_id,
                "vuln_type": outcome.get("vuln_type", "UNKNOWN"),
                "endpoint": outcome.get("endpoint", cand.target),
                "confirmed_at": time.time(),
            }
            self._memory["confirmed_vulns"].append(vuln_record)

        logger.info("InformationGainPlanner memory updated: domain_coverage=%.2f, confirmed_vulns=%d",
                    self._memory["domain_coverage"],
                    len(self._memory["confirmed_vulns"]))

    def get_memory_snapshot(self) -> Dict[str, Any]:
        return dict(self._memory)

    def ranked_candidates(self) -> List[TaskCandidate]:
        """Returns all pending candidates sorted by expected value descending."""
        pending = [c for c in self._candidates.values() if not c.executed]
        return sorted(pending, key=lambda c: c.expected_value, reverse=True)
