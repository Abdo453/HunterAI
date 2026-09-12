"""
Unit Tests for ActionEvaluator and EpistemicDecisionPolicy
Tests: Hard safety gates, Zero-EIG admissible selection (goal progress / baseline), and PolicyProfile mode shifts.
"""
import pytest

from core.reasoning.action_model import ActionDescriptor, ActionKind
from core.reasoning.action_evaluator import ActionEvaluator
from core.reasoning.decision_policy import EpistemicDecisionPolicy, PolicyMode
from core.reasoning.belief_state import BeliefState
from agents.security_intelligence.scope_guard import ScopeGuard
from agents.security_intelligence.schemas import ScopeRule


class TestActionEvaluatorAndPolicy:
    def test_hard_gate_rejects_destructive_action(self):
        destructive_act = ActionDescriptor(
            action_kind=ActionKind.EXPLOITATION,
            tool_name="sqlmap",
            target="https://target.local",
            is_destructive=True
        )
        admissible, reason = destructive_act.check_admissibility()
        assert admissible is False
        assert "Hard Gate" in reason

    def test_hard_gate_rejects_out_of_scope_target(self):
        rule = ScopeRule(target="api.target.local", allowed_domains=["api.target.local"])
        guard = ScopeGuard(rule)

        out_of_scope_act = ActionDescriptor(
            action_kind=ActionKind.DISCOVERY,
            tool_name="nmap",
            target="https://victim-bank.com"
        )
        admissible, reason = out_of_scope_act.check_admissibility(scope_guard=guard)
        assert admissible is False
        assert "out of scope" in reason.lower()

    def test_zero_eig_action_selected_when_goal_progress_is_high(self):
        """
        Critical architectural requirement from user:
        Actions with EIG = 0.0 (like clean baseline or final verification step)
        MUST be selectable if they offer high Goal Progress or Evidence Value!
        """
        belief = BeliefState()
        belief.set_hypotheses({"BOLA": 0.88, "Public": 0.12})  # Strong belief, near verification

        # Action with EIG = 0.0, but essential for goal verification
        verification_act = ActionDescriptor(
            action_id="act_verify",
            action_kind=ActionKind.VERIFICATION,
            tool_name="generate_proof_report",
            target="https://target.local",
            predicted_outcomes={},  # EIG will be 0.0
            expected_goal_delta=0.95,
            expected_evidence_value=0.90,
            estimated_cost=0.5
        )

        # Action with slight EIG, but low goal progress
        minor_recon_act = ActionDescriptor(
            action_id="act_recon",
            action_kind=ActionKind.DISCOVERY,
            tool_name="cross_tenant_probe",
            target="https://target.local",
            predicted_outcomes={"200_cross_tenant_data": 0.5, "403_forbidden": 0.5},
            expected_goal_delta=0.10,
            expected_evidence_value=0.10,
            estimated_cost=2.0
        )

        best_action, breakdowns, mode = EpistemicDecisionPolicy.select_action(
            candidates=[verification_act, minor_recon_act],
            belief_state=belief,
            mode=PolicyMode.VERIFICATION
        )

        assert best_action is not None
        assert best_action.action_id == "act_verify"
        # Verify the selected action indeed had EIG = 0.0
        v_bd = next(b for b in breakdowns if b.action_id == "act_verify")
        assert v_bd.eig == 0.0
        assert v_bd.goal_progress == 0.95
        assert v_bd.total_utility > 0.0

    def test_disambiguation_mode_prioritizes_high_eig(self):
        belief = BeliefState()
        belief.set_hypotheses({"BOLA": 0.50, "Public": 0.50})  # High uncertainty

        high_eig_act = ActionDescriptor(
            action_id="act_disambiguate",
            action_kind=ActionKind.DISAMBIGUATION,
            tool_name="cross_tenant_probe",
            target="https://target.local",
            predicted_outcomes={"200_cross_tenant_data": 0.50, "403_forbidden": 0.50},
            expected_goal_delta=0.20,
            estimated_cost=1.0
        )

        low_eig_act = ActionDescriptor(
            action_id="act_baseline",
            action_kind=ActionKind.BASELINE,
            tool_name="unauthenticated_baseline",
            target="https://target.local",
            predicted_outcomes={"401_unauthorized": 0.90, "200_ok": 0.10},
            expected_goal_delta=0.20,
            estimated_cost=1.0
        )

        best_action, _, mode = EpistemicDecisionPolicy.select_action(
            candidates=[high_eig_act, low_eig_act],
            belief_state=belief,
            mode=PolicyMode.DISAMBIGUATION
        )

        assert best_action is not None
        assert best_action.action_id == "act_disambiguate"
