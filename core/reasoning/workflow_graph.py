"""
HunterAI V27.0 - Business Logic Workflow Graph
==============================================
Models multi-step business logic state transitions and automatically synthesizes
candidate sequence violations:
  REGISTER -> LOGIN -> CREATE -> APPROVE -> EXECUTE -> COMPLETE

Candidate Sequence Violations:
  - Step Skipping:           CREATE -> EXECUTE (Bypassing Approval)
  - Premature Invocation:    REGISTER -> EXECUTE
  - Double Execution/Spend:  APPROVE -> APPROVE or PAY -> PAY
  - Post-Completion Tamper:  COMPLETE -> EXECUTE
  - Revoked Invocation:      REVOKED -> EXECUTE

Distinguishes:
  Candidate Transition != Vulnerability (It is an experimental candidate)
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.workflow_graph")


class CandidateTransitionType(str, Enum):
    STEP_SKIPPING = "STEP_SKIPPING"                    # e.g., Create -> Execute (Skipped Approval)
    PREMATURE_INVOCATION = "PREMATURE_INVOCATION"      # e.g., Register -> Execute
    DOUBLE_EXECUTION = "DOUBLE_EXECUTION"              # e.g., Approve -> Approve (Replay/Race)
    POST_COMPLETION_TAMPER = "POST_COMPLETION_TAMPER"  # e.g., Complete -> Mutate
    REVOKED_REPLAY = "REVOKED_REPLAY"                  # e.g., Session Revoked -> Execute


@dataclass
class WorkflowStep:
    step_id: str
    name: str
    order_index: int
    endpoint: str
    http_method: str = "POST"
    required_role: str = "USER"
    predecessors: List[str] = field(default_factory=list)
    state_tokens_produced: List[str] = field(default_factory=list)
    state_tokens_required: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CandidateWorkflowTransition:
    transition_id: str
    transition_type: CandidateTransitionType
    source_step_id: str
    target_step_id: str
    violated_precondition: str
    suggested_hypothesis: str
    expected_negative_observable: str = "HTTP 400 Bad Request / HTTP 409 Conflict / Precondition Failed"
    mutation_recipe: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["transition_type"] = self.transition_type.value
        return d


class WorkflowGraphEngine:
    """
    Infers and models business workflows, systematically generating candidate
    sequence violation experiments for the Experiment Generator.
    """

    def __init__(self):
        self.workflows: Dict[str, List[WorkflowStep]] = {}

    def register_workflow(self, workflow_name: str, steps: List[WorkflowStep]):
        """Registers a named ordered workflow."""
        sorted_steps = sorted(steps, key=lambda s: s.order_index)
        self.workflows[workflow_name] = sorted_steps
        logger.info(f"[WORKFLOW GRAPH] Registered workflow '{workflow_name}' with {len(sorted_steps)} steps.")

    def infer_workflow_from_traffic(self, workflow_name: str, transactions: List[Dict[str, Any]]):
        """Infers an ordered workflow progression from observed traffic transactions."""
        steps: List[WorkflowStep] = []
        for idx, tx in enumerate(transactions):
            url = tx.get("url") or tx.get("path") or "/"
            method = (tx.get("method") or "POST").upper()
            step_id = f"step_{idx+1}_{method.lower()}_{uuid.uuid4().hex[:4]}"
            step = WorkflowStep(
                step_id=step_id,
                name=f"Step {idx+1}: {method} {url}",
                order_index=idx + 1,
                endpoint=url,
                http_method=method,
                predecessors=[steps[-1].step_id] if steps else [],
            )
            steps.append(step)

        self.register_workflow(workflow_name, steps)

    def generate_candidate_transitions(self, workflow_name: str) -> List[CandidateWorkflowTransition]:
        """
        Synthesizes candidate sequence violation experiments:
          - Skips (Step i -> Step i+2)
          - Premature (Step 1 -> Step Last)
          - Double Execution (Step i -> Step i)
          - Backward Tamper (Step Last -> Step i)
        """
        steps = self.workflows.get(workflow_name, [])
        if len(steps) < 2:
            return []

        candidates: List[CandidateWorkflowTransition] = []

        # 1. Step Skipping: Jump over intermediate steps
        for i in range(len(steps)):
            for j in range(i + 2, len(steps)):
                src = steps[i]
                dst = steps[j]
                skipped = [s.name for s in steps[i+1:j]]
                candidates.append(CandidateWorkflowTransition(
                    transition_id=f"cand_skip_{src.step_id}_to_{dst.step_id}",
                    transition_type=CandidateTransitionType.STEP_SKIPPING,
                    source_step_id=src.step_id,
                    target_step_id=dst.step_id,
                    violated_precondition=f"Skipped mandatory intermediate step(s): {', '.join(skipped)}",
                    suggested_hypothesis=f"Application allows jumping directly from '{src.name}' to '{dst.name}', bypassing business logic validation.",
                    mutation_recipe={
                        "target_endpoint": dst.endpoint,
                        "method": dst.http_method,
                        "simulate_predecessors": [src.step_id],
                        "omitted_predecessors": [s.step_id for s in steps[i+1:j]],
                    }
                ))

        # 2. Premature Invocation: Direct jump from Initial step to Final execution
        initial_step = steps[0]
        final_step = steps[-1]
        candidates.append(CandidateWorkflowTransition(
            transition_id=f"cand_premature_{initial_step.step_id}_to_{final_step.step_id}",
            transition_type=CandidateTransitionType.PREMATURE_INVOCATION,
            source_step_id=initial_step.step_id,
            target_step_id=final_step.step_id,
            violated_precondition="Executing final action without prior workflow registration",
            suggested_hypothesis=f"Executing final action '{final_step.name}' directly from initial state without prerequisites.",
            mutation_recipe={
                "target_endpoint": final_step.endpoint,
                "method": final_step.http_method,
            }
        ))

        # 3. Double Execution (Replay / Race Candidate)
        for s in steps:
            if s.http_method in ("POST", "PUT", "PATCH"):
                candidates.append(CandidateWorkflowTransition(
                    transition_id=f"cand_double_{s.step_id}",
                    transition_type=CandidateTransitionType.DOUBLE_EXECUTION,
                    source_step_id=s.step_id,
                    target_step_id=s.step_id,
                    violated_precondition="Re-executing state-mutating transition after completion",
                    suggested_hypothesis=f"State-mutating step '{s.name}' can be re-executed multiple times without idempotency protection.",
                    mutation_recipe={
                        "target_endpoint": s.endpoint,
                        "method": s.http_method,
                        "replay_count": 2,
                    }
                ))

        # 4. Post-Completion Tamper
        for s in steps[:-1]:
            if s.http_method in ("POST", "PUT"):
                candidates.append(CandidateWorkflowTransition(
                    transition_id=f"cand_tamper_after_complete_{s.step_id}",
                    transition_type=CandidateTransitionType.POST_COMPLETION_TAMPER,
                    source_step_id=final_step.step_id,
                    target_step_id=s.step_id,
                    violated_precondition="Mutating order details after workflow finalization",
                    suggested_hypothesis=f"Modifying parameters of '{s.name}' after final completion '{final_step.name}'.",
                    mutation_recipe={
                        "target_endpoint": s.endpoint,
                        "method": s.http_method,
                    }
                ))

        return candidates

    def export_graph(self) -> Dict[str, Any]:
        """Returns JSON representation of all registered workflows."""
        return {
            "workflows_count": len(self.workflows),
            "workflows": {
                name: [s.to_dict() for s in step_list]
                for name, step_list in self.workflows.items()
            }
        }
