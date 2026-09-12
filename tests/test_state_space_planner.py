"""
Unit Tests for StateSpacePlanner (Cairn-Inspired State-Space Search)
Tests: Heuristic distance, Candidate generation, Optimal selection, Single step, Autonomous mission run
"""
import pytest
from unittest.mock import AsyncMock, MagicMock

from core.planner.schemas import SecurityGoal, GoalType
from core.planner.state_space_planner import StateSpacePlanner
from core.state.security_state import SecurityState
from core.gateway.tool_gateway import GovernedToolGateway
from core.gateway.policy_engine import PolicyEngine
from core.gateway.schemas import GovernedExecutionResult, RiskTier
from agents.security_intelligence.scope_guard import ScopeGuard
from agents.security_intelligence.schemas import ScopeRule, FindingStatus


@pytest.fixture
def mock_planner():
    rule = ScopeRule(target="api.target.local", allowed_domains=["api.target.local"], allow_active_tests=True)
    guard = ScopeGuard(rule)
    policy = PolicyEngine(scope_guard=guard)
    gateway = MagicMock(spec=GovernedToolGateway)
    
    # Mock successful execution result
    gateway.execute_proposal = AsyncMock(return_value=GovernedExecutionResult(
        proposal_id="PROP-001",
        tool_name="smartpoc",
        target="api.target.local",
        success=True,
        blocked=False,
        risk_tier=RiskTier.TIER_2_PROBE
    ))
    gateway.set_security_state = MagicMock()

    state = SecurityState(target="api.target.local")
    planner = StateSpacePlanner(
        security_state=state,
        tool_gateway=gateway
    )
    return planner, state, gateway


class TestStateSpacePlannerSearch:
    """Test heuristic evaluation and dynamic state transitions"""

    def test_heuristic_distance_decreases_as_state_evolves(self, mock_planner):
        planner, state, _ = mock_planner
        goal = SecurityGoal(
            title="Verify BOLA Isolation",
            goal_type=GoalType.DATA_ISOLATION_CHECK,
            target="api.target.local"
        )

        # Initial distance should be high
        h0 = planner.heuristic_distance(state, goal)
        assert h0 >= 0.70

        # Discover endpoints -> distance drops
        state.add_endpoint("/api/v1/invoices/100", method="GET", auth_required=True)
        state.add_endpoint("/api/v1/invoices/101", method="GET", auth_required=True)
        state.add_endpoint("/api/v1/users", method="GET")
        h1 = planner.heuristic_distance(state, goal)
        assert h1 < h0

        # Acquire identities -> distance drops further
        state.add_identity("user_a", role="user", token="tok_a")
        state.add_identity("user_b", role="user", token="tok_b")
        h2 = planner.heuristic_distance(state, goal)
        assert h2 < h1

    def test_candidate_action_generation(self, mock_planner):
        planner, state, _ = mock_planner
        goal = SecurityGoal(
            title="Verify BOLA Isolation",
            goal_type=GoalType.DATA_ISOLATION_CHECK,
            target="api.target.local"
        )

        # State without endpoints should generate crawl proposal
        candidates = planner.generate_candidate_actions(state, goal)
        assert len(candidates) > 0
        assert any(c.action_type == "CRAWL" for c in candidates)

        # Populate endpoints & identities -> should generate probe proposal
        state.add_endpoint("/api/v1/invoices/100", method="GET")
        state.add_identity("user_a", token="tok_a")
        candidates2 = planner.generate_candidate_actions(state, goal)
        assert any(c.action_type == "SMART_POC" for c in candidates2)

    def test_select_optimal_action(self, mock_planner):
        planner, state, _ = mock_planner
        goal = SecurityGoal(
            title="Verify BOLA Isolation",
            goal_type=GoalType.DATA_ISOLATION_CHECK,
            target="api.target.local"
        )
        state.add_endpoint("/api/v1/invoices/100")
        state.add_identity("user_a")

        optimal = planner.select_optimal_action(state, goal)
        assert optimal is not None
        assert optimal.action_type == "SMART_POC"

    @pytest.mark.asyncio
    async def test_step_execution(self, mock_planner):
        planner, state, gateway = mock_planner
        goal = SecurityGoal(
            title="Verify BOLA Isolation",
            goal_type=GoalType.DATA_ISOLATION_CHECK,
            target="api.target.local"
        )

        step_res = await planner.step(goal)
        assert step_res["step_executed"] is True
        assert gateway.execute_proposal.called

    @pytest.mark.asyncio
    async def test_full_autonomous_mission_run(self, mock_planner):
        planner, state, gateway = mock_planner
        goal = SecurityGoal(
            title="Verify BOLA Isolation",
            goal_type=GoalType.DATA_ISOLATION_CHECK,
            target="api.target.local",
            max_search_depth=5
        )

        report = await planner.run_mission(goal, max_steps=5)
        assert report.target == "api.target.local"
        assert report.steps_taken > 0
        assert report.achieved is True
        assert len(report.findings_confirmed) >= 1
        assert "Goal satisfied" in report.conclusion
