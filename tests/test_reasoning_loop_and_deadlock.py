"""
Unit Tests for AutonomousReasoningLoop and DeadlockDetector
Tests: Closed-loop cycle execution, belief & graph updates, and deadlock triggering upon state stalling.
"""
import pytest

from core.reasoning.reasoning_loop import AutonomousReasoningLoop, LoopStatus, DeadlockDetector
from core.reasoning.belief_state import BeliefState
from core.reasoning.action_model import ActionDescriptor, ActionKind
from core.attack_graph.graph import CausalAttackGraph
from agents.security_intelligence.schemas import EvidenceItem, EvidenceType


class TestReasoningLoopAndDeadlock:
    def test_closed_loop_step_execution(self):
        belief = BeliefState()
        belief.set_hypotheses({"BOLA": 0.50, "Public_Resource": 0.50})
        graph = CausalAttackGraph(target="app.local")
        loop = AutonomousReasoningLoop(target="app.local", belief_state=belief, attack_graph=graph)

        candidate = ActionDescriptor(
            action_id="act_1",
            action_kind=ActionKind.DISAMBIGUATION,
            tool_name="cross_tenant_probe",
            target="https://app.local/invoices/100",
            predicted_outcomes={"200_cross_tenant_data": 0.50, "403_forbidden": 0.50}
        )

        def mock_executor(action):
            ev = EvidenceItem(
                type=EvidenceType.BEHAVIOR_DIFF,
                source="test",
                description="Cross-tenant access verified",
                data={"status_code": 200}
            )
            return "200_cross_tenant_data", ev

        step_res = loop.step(candidates=[candidate], executor_callback=mock_executor)

        assert step_res["status"] == LoopStatus.ACTIVE
        assert step_res["action_taken"] == "cross_tenant_probe"
        assert step_res["observed_outcome"] == "200_cross_tenant_data"
        assert step_res["information_gain_bits"] > 0.0
        assert belief.version == 2
        assert len(belief.observations) == 1
        assert len(graph.nodes) >= 1  # Observation node added

    def test_deadlock_detector_triggers_on_stalled_state(self):
        detector = DeadlockDetector(max_stalls=3)
        hyps = {"BOLA": 0.5, "Public": 0.5}

        # Step 1
        assert detector.check("target.com", "nmap", hyps) is False
        # Step 2
        assert detector.check("target.com", "nmap", hyps) is False
        # Step 3 (Same target, tool, and hypotheses repeated 3 times) -> Deadlock!
        assert detector.check("target.com", "nmap", hyps) is True

    def test_reasoning_loop_handles_deadlock_gracefully(self):
        belief = BeliefState()
        belief.set_hypotheses({"BOLA": 0.50, "Public": 0.50})
        loop = AutonomousReasoningLoop(target="app.local", belief_state=belief)

        stalling_action = ActionDescriptor(
            action_id="act_stall",
            action_kind=ActionKind.DISCOVERY,
            tool_name="nmap",
            target="https://app.local",
            predicted_outcomes={}
        )

        def mock_nop(action):
            return "generic_200", None

        # Execute 2 times without deadlock
        r1 = loop.step([stalling_action], mock_nop)
        assert r1["status"] != LoopStatus.DEADLOCK_DETECTED
        r2 = loop.step([stalling_action], mock_nop)
        assert r2["status"] != LoopStatus.DEADLOCK_DETECTED

        # 3rd time triggers deadlock detection
        r3 = loop.step([stalling_action], mock_nop)
        assert r3["status"] == LoopStatus.DEADLOCK_DETECTED
        assert "stalled" in r3["reason"]
