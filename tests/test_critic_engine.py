"""
Unit Tests for CriticEngine — Anti-Hallucination & False-Positive Filter
Tests: FP memory match, missing evidence penalty, behavioral diff bonus, BOLA/SQLi-specific logic
"""
import pytest
from agents.security_intelligence.critic import CriticEngine
from agents.security_intelligence.false_positive_memory import FalsePositiveMemory
from agents.security_intelligence.schemas import (
    SecurityHypothesis, EvidenceItem, EvidenceType, HypothesisStatus
)


def _clean_critic():
    """Create CriticEngine with clean in-memory FP memory (no disk contamination)"""
    return CriticEngine(fp_memory=FalsePositiveMemory(storage_file=None))


def _make_hypothesis(vuln_type="BOLA", endpoint="/api/users/123", params=None):
    return SecurityHypothesis(
        title=f"Test {vuln_type} on {endpoint}",
        vulnerability_type=vuln_type,
        target_endpoint=endpoint,
        parameters=params or ["user_id"],
        confidence=0.65
    )


def _make_evidence(ev_type=EvidenceType.BEHAVIOR_DIFF, desc="Cross-user diff"):
    return EvidenceItem(
        type=ev_type,
        source="test",
        description=desc,
        data={"detail": "test evidence"}
    )


class TestCriticEngineNoEvidence:
    """Missing evidence should penalize confidence"""

    def test_no_evidence_penalizes(self):
        critic = _clean_critic()
        hyp = _make_hypothesis()
        result = critic.review_hypothesis(hyp, [])
        assert result["adjustment"] < 0, "Empty evidence should cause negative adjustment"
        assert "No direct evidence" in result["critic_notes"]

    def test_no_evidence_still_valid_if_no_fp(self):
        critic = _clean_critic()
        hyp = _make_hypothesis()
        result = critic.review_hypothesis(hyp, [])
        assert result["is_valid"] is True, "Missing evidence penalizes but doesn't reject"


class TestCriticEngineFalsePositiveMatch:
    """Historical false positive matches should reject hypothesis"""

    def test_known_fp_rejects_hypothesis(self):
        fp_mem = FalsePositiveMemory(storage_file=None)
        fp_mem.record_false_positive(
            pattern="/api/users/123 user_id",
            vuln_type="BOLA",
            endpoint="/api/users/123",
            reason="Public endpoint confirmed"
        )
        critic = CriticEngine(fp_memory=fp_mem)
        hyp = _make_hypothesis()
        result = critic.review_hypothesis(hyp, [])
        assert result["is_valid"] is False
        assert "False Positive" in result["rejection_reason"]
        assert result["adjustment"] <= -0.40


class TestCriticEngineBehavioralDiff:
    """Behavioral diff evidence should boost confidence"""

    def test_behavioral_diff_boosts(self):
        critic = _clean_critic()
        hyp = _make_hypothesis()
        evidence = [_make_evidence(EvidenceType.BEHAVIOR_DIFF, "Cross-user object access")]
        result = critic.review_hypothesis(hyp, evidence)
        # +0.20 bonus for BEHAVIOR_DIFF, no BOLA penalty (has "cross"/"user" in desc)
        assert "behavioral" in result["critic_notes"].lower()
        assert result["adjustment"] > 0, "Behavioral diff with cross-user desc should be positive"

    def test_non_behavioral_evidence_gets_bola_penalty(self):
        critic = _clean_critic()
        hyp = _make_hypothesis()
        evidence = [_make_evidence(EvidenceType.STATUS_CODE, "Got 200 OK")]
        result = critic.review_hypothesis(hyp, evidence)
        # STATUS_CODE: no diff bonus, missing cross-user for BOLA (-0.15) → net negative
        assert result["adjustment"] < 0, "Status code alone on BOLA should penalize"


class TestCriticEngineBOLA:
    """BOLA-specific: missing cross-user evidence should penalize"""

    def test_bola_without_cross_user_penalizes(self):
        critic = _clean_critic()
        hyp = _make_hypothesis("BOLA")
        evidence = [_make_evidence(EvidenceType.STATUS_CODE, "Returned invoice data")]
        result = critic.review_hypothesis(hyp, evidence)
        assert result["adjustment"] < 0, "BOLA without cross-user evidence should penalize"
        assert "cross-user" in result["critic_notes"].lower()

    def test_bola_with_explicit_cross_user_diff(self):
        critic = _clean_critic()
        hyp = _make_hypothesis("BOLA")
        evidence = [_make_evidence(EvidenceType.BEHAVIOR_DIFF, "Cross-user access to object 456 confirmed")]
        result = critic.review_hypothesis(hyp, evidence)
        # +0.20 for behavioral diff, no -0.15 BOLA penalty (has cross/user in desc)
        assert result["adjustment"] > 0, "Cross-user behavioral diff should net positive"


class TestCriticEngineSQLi:
    """SQLi-specific: missing DB error/timing should penalize"""

    def test_sqli_without_db_error_penalizes(self):
        critic = _clean_critic()
        hyp = _make_hypothesis("SQLi", "/api/search?q=test", ["q"])
        evidence = [_make_evidence(EvidenceType.STATUS_CODE, "Got different length")]
        result = critic.review_hypothesis(hyp, evidence)
        assert result["adjustment"] < 0, "SQLi without DB error/timing should penalize"
        assert "database error" in result["critic_notes"].lower() or "time-delay" in result["critic_notes"].lower()

    def test_sqli_with_timing_leak_no_extra_penalty(self):
        critic = _clean_critic()
        hyp = _make_hypothesis("SQLi", "/api/search?q=test", ["q"])
        evidence = [_make_evidence(EvidenceType.TIMING_LEAK, "5 second delay on sleep(5)")]
        result = critic.review_hypothesis(hyp, evidence)
        # Should not have the -0.20 SQLi penalty
        assert "database error" not in result["critic_notes"].lower()
