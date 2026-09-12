"""
Autonomous Closed-Loop Epistemic Reasoning Engine
Orchestrates the complete 19-step closed cycle:
Observe -> Model -> Hypothesize -> Plan -> EIG -> Act -> Verify -> Graph Update -> Bayesian Update -> Replan
Includes deadlock detection and strategy adaptation.
"""
import time
import logging
from enum import Enum
from typing import Dict, List, Any, Optional, Tuple

from core.reasoning.belief_state import BeliefState, BeliefSnapshot
from core.reasoning.uncertainty import UncertaintyModel, EntropyRecord
from core.reasoning.action_model import ActionDescriptor, ActionKind
from core.reasoning.decision_policy import EpistemicDecisionPolicy, PolicyMode
from core.reasoning.bayesian_engine import PosteriorUpdater
from core.attack_graph.graph import CausalAttackGraph
from core.attack_graph.nodes import AttackNode, NodeType
from core.attack_graph.edges import AttackEdge, EdgeType

log = logging.getLogger("core.reasoning.reasoning_loop")


class LoopStatus(str, Enum):
    ACTIVE = "ACTIVE"
    GOAL_ACHIEVED = "GOAL_ACHIEVED"
    DEADLOCK_DETECTED = "DEADLOCK_DETECTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    FAILED = "FAILED"


class DeadlockDetector:
    """
    كاشف التعليق والتكرار (Deadlock Detector):
    يرصد تكرار نفس القرار والمعتقدات لعدة دورات متتالية ويتدخل لكسر الحلقة
    """

    def __init__(self, max_stalls: int = 3):
        self.max_stalls = max_stalls
        self._history: List[Tuple[str, str, Dict[str, float]]] = []

    def check(self, target: str, tool_name: str, hypotheses: Dict[str, float]) -> bool:
        """ترجع True إذا تكررت نفس المعطيات بشكل متطابق لـ max_stalls مرات"""
        sig = (target, tool_name, dict(hypotheses))
        self._history.append(sig)
        if len(self._history) < self.max_stalls:
            return False

        # Check last N entries
        recent = self._history[-self.max_stalls:]
        if all(r == recent[0] for r in recent):
            return True
        return False

    def reset(self):
        self._history.clear()


class AutonomousReasoningLoop:
    """
    حلقة الاستدلال المعرفي المغلقة:
    تدير عملية التحقيق الأمني الذاتي من الرصد الأولي وحتى الإثبات الجنائي
    """

    def __init__(
        self,
        target: str = "target.local",
        belief_state: Optional[BeliefState] = None,
        attack_graph: Optional[CausalAttackGraph] = None
    ):
        self.target = target
        self.belief = belief_state or BeliefState()
        self.graph = attack_graph or CausalAttackGraph(target=target)
        self.deadlock = DeadlockDetector(max_stalls=3)
        self.investigation_log: List[Dict[str, Any]] = []

    def step(
        self,
        candidates: List[ActionDescriptor],
        executor_callback,  # async/sync callable: execute(action) -> (observed_outcome: str, evidence_item)
        goal_evaluator=None,
        scope_guard=None,
        forced_mode: Optional[PolicyMode] = None,
        hypotheses_types: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        تنفيذ دورة استدلال ذرية كاملة (Epistemic Cycle Step)
        """
        t0 = time.time()
        prior_h = UncertaintyModel.compute_entropy(self.belief.hypotheses)

        # 1. Select optimal action via Epistemic Decision Policy
        best_action, breakdowns, mode = EpistemicDecisionPolicy.select_action(
            candidates=candidates,
            belief_state=self.belief,
            scope_guard=scope_guard,
            mode=forced_mode,
            hypotheses_types=hypotheses_types
        )

        if not best_action:
            return {
                "status": LoopStatus.DEADLOCK_DETECTED,
                "reason": "No admissible candidate actions available.",
                "breakdowns": [b.to_dict() for b in breakdowns]
            }

        # 2. Deadlock Detection Check
        if self.deadlock.check(best_action.target, best_action.tool_name, self.belief.hypotheses):
            log.warning(f"[ReasoningLoop] Deadlock detected on {best_action.tool_name}. State stalling.")
            return {
                "status": LoopStatus.DEADLOCK_DETECTED,
                "action": best_action.model_dump(),
                "reason": f"State stalled on identical action ({best_action.tool_name}) for 3 consecutive steps."
            }

        # 3. Governed Execution via Callback / Gateway
        observed_outcome, evidence = executor_callback(best_action)

        # 4. Bayesian Posterior Belief Update
        prior_dist = dict(self.belief.hypotheses)
        new_posterior = PosteriorUpdater.update(
            prior_distribution=prior_dist,
            action_kind=best_action.tool_name,
            observed_outcome=observed_outcome,
            hypotheses_types=hypotheses_types
        )

        # 5. Measure Entropy & Information Gain
        entropy_record = UncertaintyModel.record_transition(prior_dist, new_posterior)

        # 6. Commit Versioned State Update
        self.belief.add_observation({
            "action_id": best_action.action_id,
            "tool_name": best_action.tool_name,
            "observed_outcome": observed_outcome,
            "outcome_evidence": evidence.id if evidence else None
        })
        self.belief.set_hypotheses(
            new_posterior,
            justification=f"Executed {best_action.tool_name} yielding outcome: '{observed_outcome}'",
            action_taken=best_action.tool_name
        )
        if evidence:
            self.belief.link_evidence(evidence.id)

        # 7. Update Attack Graph with Observed Fact
        obs_node = AttackNode(
            node_type=NodeType.OBSERVATION,
            label=f"Obs: {best_action.tool_name} -> {observed_outcome}",
            properties={"outcome": observed_outcome, "duration": round(time.time() - t0, 3)}
        )
        self.graph.add_node(obs_node)

        # 8. Goal Satisfaction Evaluation
        goal_satisfied = False
        goal_reason = ""
        if goal_evaluator:
            goal_satisfied, goal_reason = goal_evaluator(self.belief, self.graph)

        step_result = {
            "status": LoopStatus.GOAL_ACHIEVED if goal_satisfied else LoopStatus.ACTIVE,
            "version": self.belief.version,
            "action_taken": best_action.tool_name,
            "action_kind": best_action.action_kind.value,
            "policy_mode": mode.value,
            "observed_outcome": observed_outcome,
            "prior_entropy": entropy_record.prior_entropy,
            "posterior_entropy": entropy_record.posterior_entropy,
            "information_gain_bits": entropy_record.entropy_delta,
            "goal_satisfied": goal_satisfied,
            "goal_reason": goal_reason,
            "duration": round(time.time() - t0, 3)
        }
        self.investigation_log.append(step_result)
        return step_result
