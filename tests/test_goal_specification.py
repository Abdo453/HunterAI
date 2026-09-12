"""
Unit Tests for Goal Specification and Predicate Satisfaction (Cairn-Inspired)
Tests: DATA_ISOLATION_CHECK, UNAUTH_ACCESS_CHECK, INJECTION_CHECK, ATTACK_SURFACE_MAPPING
"""
import pytest
from core.planner.schemas import SecurityGoal, GoalType
from core.state.security_state import SecurityState
from agents.security_intelligence.schemas import (
    FindingStatus,
    IntelligenceFinding,
    SeverityLevel,
    ConfidenceLevel
)


def _make_confirmed_finding(vuln_type="BOLA", endpoint="/api/v1/invoices/100") -> IntelligenceFinding:
    return IntelligenceFinding(
        target="target.local",
        title=f"Confirmed {vuln_type} on {endpoint}",
        vulnerability_type=vuln_type,
        severity=SeverityLevel.HIGH,
        confidence_score=0.90,
        confidence_level=ConfidenceLevel.HIGH,
        status=FindingStatus.CONFIRMED,
        reasoning_chain=[f"Tested {endpoint}"]
    )


class TestGoalSpecifications:
    """Test goal predicate satisfaction under various state conditions"""

    def test_data_isolation_goal_unsatisfied_initially(self):
        state = SecurityState(target="target.local")
        goal = SecurityGoal(
            title="Verify Tenant Isolation",
            goal_type=GoalType.DATA_ISOLATION_CHECK,
            target="target.local"
        )
        satisfied, reason = goal.is_satisfied(state)
        assert satisfied is False
        assert "not yet confirmed" in reason

    def test_data_isolation_goal_satisfied_when_bola_confirmed(self):
        state = SecurityState(target="target.local")
        goal = SecurityGoal(
            title="Verify Tenant Isolation",
            goal_type=GoalType.DATA_ISOLATION_CHECK,
            target="target.local"
        )
        # Add confirmed BOLA finding
        finding = _make_confirmed_finding("BOLA", "/api/v1/invoices/100")
        state.record_finding(finding)

        satisfied, reason = goal.is_satisfied(state)
        assert satisfied is True
        assert "Goal satisfied" in reason
        assert "BOLA" in reason

    def test_unauth_access_goal_satisfied(self):
        state = SecurityState(target="target.local")
        goal = SecurityGoal(
            title="Verify Admin API Authorization",
            goal_type=GoalType.UNAUTH_ACCESS_CHECK,
            target="target.local"
        )
        satisfied, _ = goal.is_satisfied(state)
        assert satisfied is False

        # Add BFLA finding
        finding = _make_confirmed_finding("BFLA", "/admin/users")
        state.record_finding(finding)
        satisfied, reason = goal.is_satisfied(state)
        assert satisfied is True
        assert "BFLA" in reason

    def test_injection_goal_satisfied(self):
        state = SecurityState(target="target.local")
        goal = SecurityGoal(
            title="Verify SQL Injection",
            goal_type=GoalType.INJECTION_CHECK,
            target="target.local"
        )
        satisfied, _ = goal.is_satisfied(state)
        assert satisfied is False

        # Add SQLi finding
        finding = _make_confirmed_finding("SQLi", "/api/search")
        state.record_finding(finding)
        satisfied, reason = goal.is_satisfied(state)
        assert satisfied is True
        assert "SQLi" in reason

    def test_attack_surface_mapping_goal(self):
        state = SecurityState(target="target.local")
        goal = SecurityGoal(
            title="Map Attack Surface",
            goal_type=GoalType.ATTACK_SURFACE_MAPPING,
            target="target.local"
        )
        satisfied, _ = goal.is_satisfied(state)
        assert satisfied is False

        # Add 5 endpoints
        for i in range(5):
            state.add_endpoint(f"/api/ep_{i}", method="GET")

        satisfied, reason = goal.is_satisfied(state)
        assert satisfied is True
        assert "5 endpoints" in reason
