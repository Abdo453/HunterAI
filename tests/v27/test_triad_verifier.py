"""
Tests for Metamorphic Triad Verifier (B x C x E1 x E2)
"""
import pytest
from core.reasoning.triad_verifier import (
    TransactionSnapshot,
    TriadBundle,
    TriadVerifier,
)


def test_triad_verifier_passes_on_concordant_probes():
    b = TransactionSnapshot(status_code=200, body="Normal Response")
    c = TransactionSnapshot(status_code=200, body="Normal Response with benign param")
    e1 = TransactionSnapshot(status_code=200, body="Differential output token: 72")
    e2 = TransactionSnapshot(status_code=200, body="Differential output token: 72")

    bundle = TriadBundle(
        hypothesis_id="hyp_001",
        target_endpoint="/api/calc",
        baseline=b,
        control=c,
        experiment_1=e1,
        experiment_2=e2,
    )

    result = TriadVerifier.verify_triad(bundle)
    assert result.is_causally_differentiated is True
    assert result.metamorphic_consistency is True
    assert result.contradiction_detected is False
    assert result.epistemic_verdict == "CONFIRMED"


def test_triad_verifier_detects_contradiction():
    b = TransactionSnapshot(status_code=200, body="Normal Response")
    c = TransactionSnapshot(status_code=200, body="Control Response")
    e1 = TransactionSnapshot(status_code=200, body="Token: 72")
    e2 = TransactionSnapshot(status_code=500, body="Internal Server Error")

    bundle = TriadBundle(
        hypothesis_id="hyp_contra",
        target_endpoint="/api/calc",
        baseline=b,
        control=c,
        experiment_1=e1,
        experiment_2=e2,
    )

    result = TriadVerifier.verify_triad(bundle)
    assert result.contradiction_detected is True
    assert result.metamorphic_consistency is False
    assert result.epistemic_verdict == "PARTIALLY_VERIFIED"
    assert "Metamorphic Contradiction" in result.rationale


def test_triad_verifier_rejects_control_equivalence():
    b = TransactionSnapshot(status_code=200, body="Normal")
    c = TransactionSnapshot(status_code=400, body="Invalid input format")
    e1 = TransactionSnapshot(status_code=400, body="Invalid input format")
    e2 = TransactionSnapshot(status_code=400, body="Invalid input format")

    bundle = TriadBundle(
        hypothesis_id="hyp_equiv",
        target_endpoint="/api/calc",
        baseline=b,
        control=c,
        experiment_1=e1,
        experiment_2=e2,
    )

    result = TriadVerifier.verify_triad(bundle)
    assert result.is_causally_differentiated is False
    assert result.epistemic_verdict == "REJECTED"
    assert "Control mutation (C) produced identical response" in result.rationale
