"""
Unit Tests for FindingValidator & 5-Stage Vulnerability Lifecycle (Shannon & Dark-Moon Inspired)
Tests: OBSERVED -> SUSPECTED -> CONFIRMED -> EXPLOITED -> IMPACT_VERIFIED
"""
import pytest
from agents.security_intelligence.schemas import (
    IntelligenceFinding,
    FindingStatus,
    EvidenceItem,
    EvidenceType,
    ConfidenceLevel,
    SeverityLevel
)
from agents.security_intelligence.finding_validator import FindingValidator
from agents.security_intelligence.brain import SecurityIntelligence


def _make_finding(
    status=FindingStatus.OBSERVED,
    confidence=0.50,
    evidence=None,
    hypotheses=None,
    poc_steps=None,
    reproduction_curl=None,
    impact_desc=None
) -> IntelligenceFinding:
    return IntelligenceFinding(
        target="api.target.local",
        title="Potential BOLA on /api/v1/invoices/101",
        vulnerability_type="BOLA",
        severity=SeverityLevel.HIGH,
        confidence_score=confidence,
        confidence_level=ConfidenceLevel.POSSIBLE,
        status=status,
        hypotheses_validated=hypotheses or [],
        evidence=evidence or [],
        poc_steps=poc_steps or [],
        reproduction_curl=reproduction_curl,
        impact_description=impact_desc
    )


def _make_evidence(ev_type=EvidenceType.BEHAVIOR_DIFF, desc="Differential behavior"):
    return EvidenceItem(
        type=ev_type,
        source="test_runner",
        description=desc,
        data={"detail": "verified differential"}
    )


class TestFindingValidatorLifecycle:
    """Test transitions across the 5 lifecycle states"""

    def test_initial_status_is_observed(self):
        f = _make_finding()
        assert f.status == FindingStatus.OBSERVED

    def test_transition_to_suspected_requires_hypothesis(self):
        validator = FindingValidator()
        f_no_hyp = _make_finding(status=FindingStatus.OBSERVED)
        can_trans, reason = validator.can_transition(f_no_hyp, FindingStatus.SUSPECTED)
        assert can_trans is False, "Should reject transition without hypothesis"

        f_with_hyp = _make_finding(status=FindingStatus.OBSERVED, hypotheses=["HYP-001"])
        can_trans, reason = validator.can_transition(f_with_hyp, FindingStatus.SUSPECTED)
        assert can_trans is True

    def test_promotion_to_confirmed_without_evidence_rejected(self):
        """Shannon principle: Zero tolerance for unverified findings"""
        validator = FindingValidator()
        f = _make_finding(status=FindingStatus.SUSPECTED, confidence=0.85, hypotheses=["HYP-001"])
        can_trans, reason = validator.can_transition(f, FindingStatus.CONFIRMED)
        assert can_trans is False
        assert "Missing differential behavior" in reason

    def test_promotion_to_confirmed_with_behavioral_diff_succeeds(self):
        validator = FindingValidator()
        ev = _make_evidence(EvidenceType.BEHAVIOR_DIFF, "User B accessed User A resource with 200 OK")
        f = _make_finding(status=FindingStatus.SUSPECTED, confidence=0.75, evidence=[ev], hypotheses=["HYP-001"])
        can_trans, reason = validator.can_transition(f, FindingStatus.CONFIRMED)
        assert can_trans is True

        success, reason, updated = validator.transition_finding(f, FindingStatus.CONFIRMED, rationale="Differential proof verified")
        assert success is True
        assert updated.status == FindingStatus.CONFIRMED
        assert len(updated.lifecycle_history) == 1
        assert updated.lifecycle_history[0]["from_status"] == "SUSPECTED"
        assert updated.lifecycle_history[0]["to_status"] == "CONFIRMED"

    def test_promotion_to_exploited_requires_poc(self):
        validator = FindingValidator()
        ev = _make_evidence(EvidenceType.BEHAVIOR_DIFF)
        f = _make_finding(status=FindingStatus.CONFIRMED, confidence=0.85, evidence=[ev])
        
        # No PoC
        can_trans, reason = validator.can_transition(f, FindingStatus.EXPLOITED)
        assert can_trans is False
        assert "Requires concrete non-destructive PoC" in reason

        # With PoC steps
        can_trans, reason = validator.can_transition(
            f, FindingStatus.EXPLOITED,
            poc_steps=["1. Obtain JWT for user Alice", "2. Send GET /api/v1/invoices/202 with Bob ID", "3. Verify 200 OK"]
        )
        assert can_trans is True

    def test_promotion_to_impact_verified_requires_impact_and_poc(self):
        validator = FindingValidator()
        ev = _make_evidence(EvidenceType.BEHAVIOR_DIFF)
        f = _make_finding(
            status=FindingStatus.EXPLOITED,
            confidence=0.90,
            evidence=[ev],
            poc_steps=["Step 1", "Step 2"],
            reproduction_curl="curl -H 'Authorization: Bearer test' https://api.target.local/invoices/2"
        )

        # Without impact description
        can_trans, reason = validator.can_transition(f, FindingStatus.IMPACT_VERIFIED)
        assert can_trans is False
        assert "Requires documented business/security impact" in reason

        # With impact description
        can_trans, reason = validator.can_transition(
            f, FindingStatus.IMPACT_VERIFIED,
            impact_description="Allows horizontal unauthorized exfiltration of financial invoice records across all tenants."
        )
        assert can_trans is True

        success, reason, updated = validator.transition_finding(
            f, FindingStatus.IMPACT_VERIFIED,
            impact_description="Allows horizontal unauthorized exfiltration of financial invoice records across all tenants."
        )
        assert success is True
        assert updated.status == FindingStatus.IMPACT_VERIFIED
        assert updated.impact_description is not None

    def test_illegal_jump_rejected(self):
        """Cannot jump directly from OBSERVED to IMPACT_VERIFIED"""
        validator = FindingValidator()
        f = _make_finding(status=FindingStatus.OBSERVED)
        can_trans, reason = validator.can_transition(f, FindingStatus.IMPACT_VERIFIED)
        assert can_trans is False
        assert "Invalid transition" in reason

    def test_evaluate_max_eligible_status(self):
        validator = FindingValidator()
        f_obs = _make_finding(status=FindingStatus.OBSERVED)
        assert validator.evaluate_max_eligible_status(f_obs) == FindingStatus.OBSERVED

        f_susp = _make_finding(hypotheses=["H1"])
        assert validator.evaluate_max_eligible_status(f_susp) == FindingStatus.SUSPECTED

        f_conf = _make_finding(
            confidence=0.75,
            evidence=[_make_evidence(EvidenceType.BEHAVIOR_DIFF)]
        )
        assert validator.evaluate_max_eligible_status(f_conf) == FindingStatus.CONFIRMED

        f_expl = _make_finding(
            confidence=0.85,
            evidence=[_make_evidence(EvidenceType.BEHAVIOR_DIFF)],
            poc_steps=["Curl test"]
        )
        assert validator.evaluate_max_eligible_status(f_expl) == FindingStatus.EXPLOITED

        f_impact = _make_finding(
            confidence=0.90,
            evidence=[_make_evidence(EvidenceType.BEHAVIOR_DIFF)],
            poc_steps=["Curl test"],
            impact_desc="Full tenant leak"
        )
        assert validator.evaluate_max_eligible_status(f_impact) == FindingStatus.IMPACT_VERIFIED


class TestSecurityIntelligenceFacadeValidatorIntegration:
    """Test facade delegation to FindingValidator"""

    def test_facade_exposes_validator_methods(self):
        si = SecurityIntelligence()
        assert si.finding_validator is not None

        f = _make_finding(status=FindingStatus.OBSERVED, hypotheses=["HYP-001"])
        can_trans, reason = si.validate_finding_transition(f, FindingStatus.SUSPECTED)
        assert can_trans is True

        success, reason, updated = si.transition_finding(f, FindingStatus.SUSPECTED)
        assert success is True
        assert updated.status == FindingStatus.SUSPECTED
