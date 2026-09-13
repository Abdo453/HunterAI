"""
HunterAI Agent Decision Trace
=============================
Provides a forensically auditable record of agent reasoning without capturing or
storing opaque LLM chain-of-thought tokens.

Canonical Epistemic Step:
Observation -> Available Evidence -> Decision -> Policy Check -> Action -> Result
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DecisionTraceStep:
    step_id: str
    timestamp: float = field(default_factory=time.time)
    observation_summary: str = ""
    available_evidence: List[str] = field(default_factory=list)
    decision_rationale: str = ""
    policy_check_result: str = "ALLOW"  # "ALLOW", "DENY", "APPROVAL_REQUIRED"
    policy_receipt_id: str = ""
    selected_action: str = ""
    action_result: str = ""
    state_mutation_occurred: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "timestamp": self.timestamp,
            "observation": self.observation_summary,
            "evidence_count": len(self.available_evidence),
            "evidence": self.available_evidence,
            "decision": self.decision_rationale,
            "policy_check": self.policy_check_result,
            "policy_receipt": self.policy_receipt_id,
            "action": self.selected_action,
            "result": self.action_result,
            "mutated_state": self.state_mutation_occurred,
        }


class AgentDecisionTrace:
    """Immutable, chronological trace log for autonomous agent decisions"""

    def __init__(self, trace_id: str, target: str):
        self.trace_id = trace_id
        self.target = target
        self.steps: List[DecisionTraceStep] = []
        self._step_counter = 0

    def record_step(
        self,
        observation: str,
        evidence: List[str],
        decision: str,
        policy_result: str = "ALLOW",
        policy_receipt: str = "",
        action: str = "",
        result: str = "",
        mutated: bool = False
    ) -> DecisionTraceStep:
        self._step_counter += 1
        step_id = f"TRC-{self.trace_id[:8]}-{self._step_counter:03d}"
        step = DecisionTraceStep(
            step_id=step_id,
            observation_summary=observation,
            available_evidence=evidence,
            decision_rationale=decision,
            policy_check_result=policy_result,
            policy_receipt_id=policy_receipt,
            selected_action=action,
            action_result=result,
            state_mutation_occurred=mutated
        )
        self.steps.append(step)
        return step

    def format_timeline_ascii(self) -> str:
        lines = [
            f"=== Agent Decision Trace: {self.trace_id} ({self.target}) ===",
            f"Total Auditable Steps: {len(self.steps)}",
            "-" * 60
        ]
        for s in self.steps:
            lines.append(f"[{s.step_id}] Observation: {s.observation_summary}")
            lines.append(f"    Evidence  : {', '.join(s.available_evidence) if s.available_evidence else 'None'}")
            lines.append(f"    Decision  : {s.decision_rationale}")
            lines.append(f"    Policy    : {s.policy_check_result} (Receipt: {s.policy_receipt_id or 'N/A'})")
            lines.append(f"    Action    : {s.selected_action} -> Result: {s.action_result}")
            lines.append("." * 60)
        return "\n".join(lines)


class DecisionTraceLogger:
    """Singleton repository for active traces"""
    _traces: Dict[str, AgentDecisionTrace] = {}

    @classmethod
    def get_or_create_trace(cls, trace_id: str, target: str) -> AgentDecisionTrace:
        if trace_id not in cls._traces:
            cls._traces[trace_id] = AgentDecisionTrace(trace_id, target)
        return cls._traces[trace_id]
