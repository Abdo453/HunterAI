"""
HunterAI / ARTEX Dependency-Chain Attack Planner
================================================
Implements the Planner's Multi-Round Shared Todolist:
- Manages serial, mutually-dependent attack chains (e.g. Discovery -> Auth Bypass -> Lateral Movement -> PrivEsc).
- Enforces strict prerequisite gates: subsequent intents are dispatched only when
  prerequisite steps are done and their required facts exist in the graph.
- Ensures atomic, orderly progression across asynchronous multi-agent cycles.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from core.architecture.dual_graph import DualGraphManager, ExplorationKind, ExplorationNode

logger = logging.getLogger("hunter_ai.dependency_planner")


class MilestoneStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    BLOCKED = "blocked"


@dataclass
class AttackMilestone:
    milestone_id: str
    stage_name: str
    description: str
    target_asset_id: Optional[str] = None
    prerequisite_ids: List[str] = field(default_factory=list)
    status: MilestoneStatus = MilestoneStatus.PENDING
    assigned_intent_id: Optional[str] = None
    required_fact_keyword: Optional[str] = None
    produced_fact_ids: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class DependencyChainPlanner:
    """
    Stateful attack planner that schedules dependent tasks sequentially.
    """

    def __init__(self, task_id: str, graph: DualGraphManager):
        self.task_id = task_id
        self.graph = graph
        self.milestones: Dict[str, AttackMilestone] = {}
        self.execution_order: List[str] = []

    def add_milestone(
        self,
        stage_name: str,
        description: str,
        target_asset_id: Optional[str] = None,
        prerequisites: Optional[List[str]] = None,
        required_fact_keyword: Optional[str] = None,
    ) -> AttackMilestone:
        mid = f"m_{uuid.uuid4().hex[:6]}"
        m = AttackMilestone(
            milestone_id=mid,
            stage_name=stage_name,
            description=description,
            target_asset_id=target_asset_id,
            prerequisite_ids=prerequisites or [],
            required_fact_keyword=required_fact_keyword,
        )
        self.milestones[mid] = m
        self.execution_order.append(mid)
        return m

    def evaluate_and_dispatch_next(self) -> Optional[ExplorationNode]:
        """
        Evaluates prerequisites for all milestones (marking blocked ones accordingly),
        then dispatches an intent for the first milestone that is ready.
        """
        next_eligible: Optional[AttackMilestone] = None

        for mid in self.execution_order:
            m = self.milestones[mid]
            if m.status in (MilestoneStatus.DONE, MilestoneStatus.IN_PROGRESS):
                continue

            # Check prerequisites
            prereqs_met = True
            for pid in m.prerequisite_ids:
                prereq = self.milestones.get(pid)
                if not prereq or prereq.status != MilestoneStatus.DONE:
                    prereqs_met = False
                    break

            if not prereqs_met:
                m.status = MilestoneStatus.BLOCKED
                continue

            # Check if required fact is present in graph if specified
            if m.required_fact_keyword:
                facts = [
                    n for n in self.graph.exploration_nodes.values()
                    if n.kind == ExplorationKind.FACT and m.required_fact_keyword.lower() in n.title.lower()
                ]
                if not facts:
                    m.status = MilestoneStatus.BLOCKED
                    continue

            # Prerequisites and facts satisfied
            m.status = MilestoneStatus.PENDING
            if next_eligible is None:
                next_eligible = m

        if next_eligible:
            m = next_eligible
            intent_node = self.graph.add_exploration_node(
                kind=ExplorationKind.INTENT,
                title=f"Execute: {m.stage_name} - {m.description}",
                task_id=self.task_id,
                state="open",
                payload={
                    "milestone_id": m.milestone_id,
                    "target_asset_id": m.target_asset_id,
                    "stage_name": m.stage_name,
                },
                anchored_asset_ids=[m.target_asset_id] if m.target_asset_id else None,
            )

            m.status = MilestoneStatus.IN_PROGRESS
            m.assigned_intent_id = intent_node.id
            m.updated_at = time.time()
            logger.info("[Planner] Dispatched Intent %s for Milestone %s", intent_node.id, m.stage_name)
            return intent_node

        return None

    def mark_milestone_completed(self, milestone_id: str, fact_id: Optional[str] = None) -> bool:
        m = self.milestones.get(milestone_id)
        if not m:
            return False
        m.status = MilestoneStatus.DONE
        m.updated_at = time.time()
        if fact_id:
            m.produced_fact_ids.append(fact_id)
        logger.info("[Planner] Milestone %s marked DONE.", m.stage_name)
        return True

    def get_progress_overview(self) -> Dict[str, Any]:
        return {
            "total_milestones": len(self.milestones),
            "completed": len([m for m in self.milestones.values() if m.status == MilestoneStatus.DONE]),
            "in_progress": len([m for m in self.milestones.values() if m.status == MilestoneStatus.IN_PROGRESS]),
            "pending": len([m for m in self.milestones.values() if m.status == MilestoneStatus.PENDING]),
            "blocked": len([m for m in self.milestones.values() if m.status == MilestoneStatus.BLOCKED]),
        }
