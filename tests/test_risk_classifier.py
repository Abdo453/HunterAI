"""
Unit Tests for RiskClassifier (CyberStrikeAI-Inspired)
Tests classification into Risk Tiers (0 to 4) and detection of destructive commands
"""
import pytest
from core.gateway.schemas import RiskTier, ActionProposal
from core.gateway.risk_classifier import RiskClassifier


class TestRiskClassifier:
    """Test classification of various actions into risk tiers"""

    def setup_method(self):
        self.classifier = RiskClassifier()

    def test_passive_tool_classification(self):
        prop = ActionProposal(
            target="target.local",
            tool_name="whois",
            action_type="PASSIVE_ANALYSIS"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_0_PASSIVE

    def test_active_recon_classification(self):
        prop = ActionProposal(
            target="target.local",
            tool_name="nmap",
            command_args="-sV -p 80,443",
            action_type="PORT_SCAN"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_1_RECON_ACTIVE

    def test_probe_tool_classification(self):
        prop = ActionProposal(
            target="https://target.local/api/search",
            tool_name="ffuf",
            command_args="-w /wordlist.txt -u https://target.local/FUZZ",
            action_type="FUZZ"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_2_PROBE

    def test_exploit_classification(self):
        prop = ActionProposal(
            target="https://target.local/login",
            tool_name="sqlmap",
            command_args="-u https://target.local/login --os-shell",
            action_type="EXPLOIT"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_3_EXPLOIT_POC

    # ── Destructive Detection (TIER 4) ──────────────────────────────────────

    def test_destructive_sql_drop_table(self):
        prop = ActionProposal(
            target="https://target.local/api",
            tool_name="sqlmap",
            command_args="--sql-query 'DROP TABLE users;'"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE
        assert "DROP" in reason

    def test_destructive_sql_truncate(self):
        prop = ActionProposal(
            target="https://target.local/api",
            tool_name="sqlmap",
            command_args="--sql-query 'TRUNCATE TABLE orders;'"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE

    def test_destructive_os_rm_rf(self):
        prop = ActionProposal(
            target="https://target.local/exec",
            tool_name="custom_exec",
            command_args="rm -rf / --no-preserve-root"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE
        assert "destructive" in reason.lower()

    def test_destructive_os_fork_bomb(self):
        prop = ActionProposal(
            target="https://target.local/exec",
            tool_name="bash",
            command_args=":(){ :|:& };:"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE

    def test_destructive_dos_flood(self):
        prop = ActionProposal(
            target="https://target.local/api",
            tool_name="custom_probe",
            command_args="--dos --flood"
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE

    def test_destructive_explicit_flag(self):
        prop = ActionProposal(
            target="https://target.local/api",
            tool_name="any_tool",
            is_destructive=True
        )
        tier, reason = self.classifier.classify_proposal(prop)
        assert tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE
