"""
Unit Tests for PolicyEngine (Governed Safety Arbitration)
Tests: Destructive blocking, Scope enforcement, Active testing gating, Rate limiting, and Input sanitization
"""
import pytest
from core.gateway.schemas import RiskTier, ActionProposal
from core.gateway.policy_engine import PolicyEngine
from agents.security_intelligence.scope_guard import ScopeGuard
from agents.security_intelligence.schemas import ScopeRule


class TestPolicyEngine:
    """Test policy arbitration rules"""

    def setup_method(self):
        rule = ScopeRule(
            target="api.target.local",
            allowed_domains=["api.target.local"],
            allow_active_tests=True
        )
        self.guard = ScopeGuard(rule)
        self.policy = PolicyEngine(scope_guard=self.guard, max_repeated_actions=3)

    def test_instantly_blocks_destructive_commands(self):
        prop = ActionProposal(
            target="https://api.target.local/v1",
            tool_name="sqlmap",
            command_args="--sql-query 'DROP TABLE users;'"
        )
        verdict = self.policy.evaluate_proposal(prop)
        assert verdict.allowed is False
        assert verdict.status == "BLOCKED_DESTRUCTIVE"
        assert verdict.risk_tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE

    def test_blocks_out_of_scope_target(self):
        prop = ActionProposal(
            target="https://unauthorized-victim.com/test",
            tool_name="nmap",
            command_args="-sV"
        )
        verdict = self.policy.evaluate_proposal(prop)
        assert verdict.allowed is False
        assert verdict.status == "BLOCKED_SCOPE"

    def test_blocks_active_when_disallowed(self):
        # Disallow active tests
        self.guard.set_scope(ScopeRule(
            target="api.target.local",
            allowed_domains=["api.target.local"],
            allow_active_tests=False
        ))
        prop = ActionProposal(
            target="https://api.target.local/search",
            tool_name="ffuf",
            command_args="-w wordlist.txt -u https://api.target.local/FUZZ"
        )
        verdict = self.policy.evaluate_proposal(prop)
        assert verdict.allowed is False
        assert verdict.status == "BLOCKED_ACTIVE_DISALLOWED"

    def test_approves_in_scope_active_probe(self):
        prop = ActionProposal(
            target="https://api.target.local/search",
            tool_name="ffuf",
            command_args="-w wordlist.txt -u https://api.target.local/FUZZ"
        )
        verdict = self.policy.evaluate_proposal(prop)
        assert verdict.allowed is True
        assert verdict.status == "APPROVED"
        assert verdict.risk_tier == RiskTier.TIER_2_PROBE

    def test_enforces_rate_limiting_loop_protection(self):
        prop = ActionProposal(
            target="https://api.target.local/items",
            tool_name="ffuf",
            command_args="FUZZ"
        )
        # Max repeats is 3
        v1 = self.policy.evaluate_proposal(prop)
        assert v1.allowed is True
        v2 = self.policy.evaluate_proposal(prop)
        assert v2.allowed is True
        v3 = self.policy.evaluate_proposal(prop)
        assert v3.allowed is True

        # 4th should be blocked by loop protection
        v4 = self.policy.evaluate_proposal(prop)
        assert v4.allowed is False
        assert verdict_status_blocked(v4.status)

    def test_sanitizes_command_arguments(self):
        prop = ActionProposal(
            target="https://api.target.local/test",
            tool_name="nmap",
            command_args="-sV\r\n-p 80   443\n"
        )
        verdict = self.policy.evaluate_proposal(prop)
        assert "\r" not in verdict.sanitized_args
        assert "\n" not in verdict.sanitized_args
        assert "  " not in verdict.sanitized_args


def verdict_status_blocked(status: str) -> bool:
    return "BLOCKED" in status
