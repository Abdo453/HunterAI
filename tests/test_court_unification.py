"""LEDGER-014 (M1b): the two evidence courts must agree.

``EvidenceCourtV2`` (the adversarial tribunal) used to accept the caller's
booleans as proof, so it could CONFIRM a case that the authoritative
``EvidenceCourt`` (v1) refuted. V2 now delegates the proof decision to v1, so the
same input always yields the same epistemic outcome.

These tests pin that contract.
"""
from __future__ import annotations

from core.court.evidence_court_v2 import EvidenceCourtV2
from core.evidence_court import CourtVerdict, EvidenceCourt, ProofPayload

_ENDPOINT = "https://target.local/api/orders"


def _token_proof() -> ProofPayload:
    return ProofPayload(
        artifact_type="token",
        expected_token="PROOF-TOKEN-42",
        response_text="owned :: PROOF-TOKEN-42 :: end",
        baseline_text="denied",
    )


def test_v2_never_confirms_from_caller_flag_alone():
    ruling = EvidenceCourtV2.adjudicate_case(
        case_id="C-1",
        endpoint=_ENDPOINT,
        proof_nonce_proven=True,
        reproductions_count=3,
        causal_chain_verified=True,
        baseline_stable=True,
        waf_clean=True,
    )
    assert ruling.final_verdict != "CONFIRMED"
    # The caller assertion is recorded as DECLARED, never DERIVED.
    assert ruling.proof_strength == "DECLARED"


def test_v1_and_v2_agree_with_and_without_proof():
    # With a re-evaluable proof, both courts CONFIRM.
    v2_ok = EvidenceCourtV2.adjudicate_case(
        case_id="C-2",
        endpoint=_ENDPOINT,
        proof_nonce_proven=True,
        reproductions_count=2,
        causal_chain_verified=True,
        baseline_stable=True,
        waf_clean=True,
        proof_payload=_token_proof(),
    )
    v1_ok = EvidenceCourt.adjudicate(
        target_url=_ENDPOINT,
        parameter="id",
        vuln_class="idor",
        verifier_result={"reproduced": True, "deterministic_proof": True},
        proof_payload=_token_proof(),
    )
    assert v1_ok.verdict is CourtVerdict.CONFIRMED
    assert v2_ok.final_verdict == "CONFIRMED"

    # Without a proof payload, neither court confirms a bare flag.
    v2_bad = EvidenceCourtV2.adjudicate_case(
        case_id="C-3",
        endpoint=_ENDPOINT,
        proof_nonce_proven=True,
        reproductions_count=2,
        causal_chain_verified=True,
        baseline_stable=True,
        waf_clean=True,
    )
    v1_bad = EvidenceCourt.adjudicate(
        target_url=_ENDPOINT,
        parameter="id",
        vuln_class="idor",
        verifier_result={"reproduced": True, "deterministic_proof": True},
    )
    assert v1_bad.verdict is not CourtVerdict.CONFIRMED
    assert v2_bad.final_verdict != "CONFIRMED"


def test_v2_waf_dissent_refutes():
    ruling = EvidenceCourtV2.adjudicate_case(
        case_id="C-4",
        endpoint=_ENDPOINT,
        proof_nonce_proven=True,
        reproductions_count=3,
        causal_chain_verified=True,
        baseline_stable=True,
        waf_clean=False,
    )
    assert ruling.final_verdict == "REFUTED"
    skeptic = [o for o in ruling.opinions if o.role.value == "SKEPTIC"]
    assert skeptic and skeptic[0].disposition == "VOTE_REJECT"
