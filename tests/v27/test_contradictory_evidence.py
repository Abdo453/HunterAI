"""
Tests for Contradictory Evidence Adjudication in Evidence Court
"""
import pytest
from core.evidence_court import (
    CausalEvidence,
    CourtVerdict,
    EvidenceCourt,
)


def test_evidence_court_holds_contradictory_evidence_in_unverified():
    causal_ev = CausalEvidence(
        metamorphic_passed=False,
        contradiction_detected=True,
        rationale="E1 succeeded but metamorphic variation E2 returned 500 internal error",
    )

    judgment = EvidenceCourt.adjudicate(
        target_url="https://app.target.local/api/test",
        parameter="input",
        vuln_class="command_injection",
        finder_claim={"claim": "Uncertain RCE probe"},
        verifier_result={"reproduced": False},
        causal_evidence=causal_ev,
        is_in_scope=True,
    )

    assert judgment.verdict == CourtVerdict.UNVERIFIED
    assert judgment.epistemic_state == "PARTIALLY_VERIFIED"
    assert judgment.contradiction_detected is True
    assert judgment.reportable is False
    assert "Metamorphic Contradiction" in judgment.adjudication_rationale
