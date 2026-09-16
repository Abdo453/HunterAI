"""
Tests for EvidenceCourt Causality Gate & Causal Triad (V27.0)
"""
import pytest
from core.evidence_court import CausalTriad, CourtVerdict, EvidenceCourt


def test_causality_gate_rejects_length_delta_alone():
    judgment = EvidenceCourt.adjudicate(
        target_url="https://app.target.local/search",
        parameter="q",
        vuln_class="command_injection",
        finder_claim={"is_real_vuln": True},
        verifier_result={
            "reproduced": True,
            "length_delta_only": True,
            "status_code": 200,
        },
        is_in_scope=True,
    )
    assert judgment.verdict == CourtVerdict.FALSE_POSITIVE
    assert judgment.reportable is False
    assert "Causality Gate Violation" in judgment.adjudication_rationale


def test_causality_gate_evaluates_triad_with_control_equivalence():
    triad = CausalTriad(
        baseline_status=200,
        baseline_length=1000,
        control_status=200,
        control_length=1200,
        experiment_status=200,
        experiment_length=1202,
        deterministic_execution_token=None,
    )

    judgment = EvidenceCourt.adjudicate(
        target_url="https://app.target.local/profile",
        parameter="bio",
        vuln_class="xss",
        finder_claim={"is_real_vuln": True},
        verifier_result={"reproduced": True, "status_code": 200},
        causal_triad=triad,
        is_in_scope=True,
    )
    assert judgment.verdict == CourtVerdict.FALSE_POSITIVE
    assert "Control mutation produced identical shift" in judgment.adjudication_rationale


def test_causality_gate_negative_observables_triggers_disproved():
    judgment = EvidenceCourt.adjudicate(
        target_url="https://app.target.local/api/users/42",
        parameter="user_id",
        vuln_class="idor",
        finder_claim={"is_real_vuln": True},
        verifier_result={
            "reproduced": False,
            "status_code": 403,
            "response_body": "{'error': 'Unauthorized: access denied'}",
        },
        negative_observables={
            "status_codes": [401, 403, 404],
            "response_patterns": ["access denied", "forbidden"],
        },
        is_in_scope=True,
    )
    assert judgment.verdict == CourtVerdict.DISPROVED
    assert judgment.reportable is False
    assert "Negative observable triggered" in judgment.adjudication_rationale


def test_causality_gate_confirms_with_true_causal_proof():
    triad = CausalTriad(
        baseline_status=200,
        baseline_length=1000,
        control_status=200,
        control_length=1000,
        experiment_status=200,
        experiment_length=1050,
        deterministic_execution_token="72",
    )

    judgment = EvidenceCourt.adjudicate(
        target_url="https://app.target.local/calc",
        parameter="input",
        vuln_class="command_injection",
        finder_claim={"is_real_vuln": True},
        verifier_result={
            "reproduced": True,
            "arithmetic_proof_confirmed": True,
            "status_code": 200,
            "confidence": 0.99,
        },
        causal_triad=triad,
        is_in_scope=True,
    )
    assert judgment.verdict == CourtVerdict.CONFIRMED
    assert judgment.reportable is True
    assert judgment.calibrated_severity == "Critical"
