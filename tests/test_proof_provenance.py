"""Regression tests: deterministic proof must be DERIVED, not DECLARED.

Defect (proved by live experiment before the fix):
    ``EvidenceCourt.adjudicate`` accepted any caller-supplied truthy boolean as
    "deterministic proof":

        verifier_result={"reproduced": True, "canary_confirmed": True}
        raw_evidence="", source_tool="llm_hallucination"
        => verdict CONFIRMED, reportable True, "complete Evidence Chain"

    Meanwhile the pipeline's own scanner call sites could never confirm
    anything, because they only ever passed ``{"reproduced": True}``.

Fixed contract:
    * Proof must be re-evaluable from raw observed data (``ProofPayload``).
    * Declared-only booleans -> UNVERIFIED (unless explicitly opted in).
    * A payload the engine refutes -> FALSE_POSITIVE, not "unverified".
"""
from __future__ import annotations

import pytest

from core.evidence_court import (
    CausalEvidence,
    CourtVerdict,
    EvidenceCourt,
    ProofPayload,
    ProofStrength,
    _ProofResolver,
)
from core.poe_engine import ProofOfExecutionEngine


def adjudicate(**kwargs):
    base = dict(
        target_url="https://target.example/api/item",
        parameter="id",
        vuln_class="cmd_injection",
        is_in_scope=True,
    )
    base.update(kwargs)
    return EvidenceCourt.adjudicate(**base)


class TestFabricationIsRejected:
    def test_declared_flag_alone_does_not_confirm(self):
        j = adjudicate(
            verifier_result={"reproduced": True, "canary_confirmed": True},
            finder_claim={"source_tool": "llm_hallucination", "raw_evidence": ""},
        )
        assert j.verdict is CourtVerdict.UNVERIFIED
        assert j.reportable is False
        assert j.proof_strength == ProofStrength.DECLARED.value

    @pytest.mark.parametrize(
        "flag",
        [
            "arithmetic_proof_confirmed",
            "extracted_data",
            "auth_bypass_confirmed",
            "file_content_confirmed",
            "boolean_branch_confirmed",
            "canary_confirmed",
            "template_eval_confirmed",
            "dom_breakout_confirmed",
            "token_bypass_confirmed",
            "deterministic_proof",
        ],
    )
    def test_every_legacy_flag_is_downgraded_without_evidence(self, flag):
        j = adjudicate(verifier_result={"reproduced": True, flag: True})
        assert j.verdict is CourtVerdict.UNVERIFIED, f"{flag} must not confirm on its own"

    def test_explicit_opt_in_preserves_legacy_behaviour_but_labels_it(self):
        j = adjudicate(
            verifier_result={"reproduced": True, "canary_confirmed": True},
            allow_declared_proof=True,
        )
        assert j.verdict is CourtVerdict.CONFIRMED
        assert j.proof_strength == ProofStrength.DECLARED.value
        assert j.epistemic_state == "CONFIRMED_ON_DECLARED_PROOF"


class TestDerivedProofConfirms:
    def test_command_injection_arithmetic(self):
        j = adjudicate(
            verifier_result={"reproduced": True, "arithmetic_proof_confirmed": True},
            proof_payload={
                "artifact_type": "command_injection",
                "response_text": "uid=0(root)\n72\n",
                "expected_result": "72",
                "probed_expression": "53+19",
            },
        )
        assert j.verdict is CourtVerdict.CONFIRMED
        assert j.proof_strength == ProofStrength.DERIVED.value
        assert j.proof_kind == "command_injection"

    def test_sqli_banner_extraction(self):
        j = adjudicate(
            vuln_class="sqli",
            verifier_result={"reproduced": True, "extracted_data": "x"},
            proof_payload={
                "artifact_type": "sqli",
                "response_text": "ERROR: PostgreSQL 14.5 on x86_64-pc-linux-gnu",
            },
        )
        assert j.verdict is CourtVerdict.CONFIRMED
        assert j.proof_strength == ProofStrength.DERIVED.value

    def test_lfi_passwd_signature(self):
        j = adjudicate(
            vuln_class="lfi",
            verifier_result={"reproduced": True, "file_content_confirmed": True},
            proof_payload={
                "artifact_type": "lfi",
                "response_text": "root:x:0:0:root:/root:/bin/bash",
            },
        )
        assert j.verdict is CourtVerdict.CONFIRMED

    def test_new_nonce_absent_from_baseline(self):
        j = adjudicate(
            vuln_class="idor",
            verifier_result={"reproduced": True, "auth_bypass_confirmed": True},
            proof_payload={
                "artifact_type": "auth_bypass",
                "response_text": '{"owner": "victim_alice", "token": "NONCE-9F31"}',
                "baseline_text": '{"owner": "attacker_bob"}',
                "expected_token": "NONCE-9F31",
            },
        )
        assert j.verdict is CourtVerdict.CONFIRMED
        assert j.proof_strength == ProofStrength.DERIVED.value

    def test_trusted_causal_evidence_confirms(self):
        # Independent verification must have executed (verifier_result present);
        # the causal engine's invariant verdict then supplies the proof.
        j = adjudicate(
            verifier_result={"reproduced": True},
            causal_evidence=CausalEvidence(
                metamorphic_passed=True,
                invariant_passed=True,
                causal_strength=1.0,
                extracted_observables={"E1": "72", "E2": "72"},
            ),
        )
        assert j.verdict is CourtVerdict.CONFIRMED
        assert j.proof_strength == ProofStrength.DERIVED.value
        assert j.proof_kind == "causal_invariant"

    def test_causal_evidence_without_verifier_result_is_inconclusive(self):
        """No independent verification ran -> inconclusive, never confirmed."""
        j = adjudicate(
            causal_evidence=CausalEvidence(
                metamorphic_passed=True, invariant_passed=True, causal_strength=1.0
            ),
        )
        assert j.verdict is CourtVerdict.INCONCLUSIVE
        assert j.reportable is False


class TestRefutedProofIsDisproof:
    def test_arithmetic_syntax_echo_is_refuted(self):
        j = adjudicate(
            verifier_result={"reproduced": True, "arithmetic_proof_confirmed": True},
            proof_payload={
                "artifact_type": "command_injection",
                "response_text": "<html>error: $((53+19)) rejected</html>",
                "expected_result": "72",
                "probed_expression": "53+19",
            },
        )
        assert j.verdict is CourtVerdict.FALSE_POSITIVE
        assert j.proof_strength == ProofStrength.REFUTED.value
        assert j.reportable is False

    def test_missing_arithmetic_result_is_refuted(self):
        j = adjudicate(
            verifier_result={"reproduced": True, "arithmetic_proof_confirmed": True},
            proof_payload={
                "artifact_type": "command_injection",
                "response_text": "command executed but no numeric output",
                "expected_result": "72",
                "probed_expression": "53+19",
            },
        )
        assert j.verdict is CourtVerdict.FALSE_POSITIVE

    def test_nonce_already_in_baseline_is_refuted(self):
        """A token that exists before the probe proves nothing."""
        j = adjudicate(
            verifier_result={"reproduced": True, "canary_confirmed": True},
            proof_payload={
                "artifact_type": "canary",
                "response_text": "session NONCE-9F31 active",
                "baseline_text": "session NONCE-9F31 active",
                "expected_token": "NONCE-9F31",
            },
        )
        assert j.verdict is CourtVerdict.FALSE_POSITIVE
        assert j.proof_strength == ProofStrength.REFUTED.value

    def test_nonce_absent_from_response_is_refuted(self):
        j = adjudicate(
            verifier_result={"reproduced": True, "canary_confirmed": True},
            proof_payload={
                "artifact_type": "canary",
                "response_text": "nothing useful here",
                "baseline_text": "",
                "expected_token": "NONCE-9F31",
            },
        )
        assert j.verdict is CourtVerdict.FALSE_POSITIVE

    def test_no_sqli_banner_is_refuted(self):
        j = adjudicate(
            vuln_class="sqli",
            verifier_result={"reproduced": True, "extracted_data": "x"},
            proof_payload={"artifact_type": "sqli", "response_text": "Premium Gadget"},
        )
        assert j.verdict is CourtVerdict.FALSE_POSITIVE


class TestPoEReflectionSemantics:
    """The reflection heuristic must not reject genuine execution.

    Defect found via the 12-lab arena: real diagnostic tools echo the command
    they ran, so a response legitimately contains both the syntax and the
    computed result. Rejecting on echoed syntax alone was a false negative.
    """

    def test_echoed_syntax_without_result_is_reflection(self):
        ok, reason = ProofOfExecutionEngine.verify_command_injection(
            "<html>PING ; echo $((53+19)); (127.0.0.1)</html>", "72", "53+19"
        )
        assert ok is False
        assert "Reflection" in reason or "syntax echo" in reason

    def test_echoed_syntax_with_result_is_execution(self):
        ok, reason = ProofOfExecutionEngine.verify_command_injection(
            "PING ; echo $((53+19)); (127.0.0.1): 56 data bytes\n72\n", "72", "53+19"
        )
        assert ok is True, reason

    def test_result_present_in_baseline_is_rejected(self):
        ok, reason = ProofOfExecutionEngine.verify_command_injection(
            "PING host: 56 data bytes\n72\n", "72", "53+19", baseline_text="PING host: 56 data bytes\n72\n"
        )
        assert ok is False
        assert "baseline" in reason.lower()

    def test_result_absent_and_no_echo(self):
        ok, _ = ProofOfExecutionEngine.verify_command_injection("nothing numeric here", "72", "53+19")
        assert ok is False

    def test_clean_execution_still_confirms(self):
        ok, _ = ProofOfExecutionEngine.verify_command_injection("uid=0(root)\n72\n", "72", "53+19")
        assert ok is True

    def test_json_reflection_is_rejected(self):
        ok, reason = ProofOfExecutionEngine.verify_command_injection(
            '<script>var x = {"host": "53+19"};</script>', "72", "53+19"
        )
        assert ok is False


class TestResolverContract:
    def test_no_proof_offered(self):
        strength, kind, detail = _ProofResolver.resolve({"reproduced": True}, None, None)
        assert strength is ProofStrength.NONE
        assert kind == ""

    def test_payload_wins_over_declared_flag(self):
        """Even with a declared flag set, a refuting payload must win."""
        strength, _, _ = _ProofResolver.resolve(
            {"reproduced": True, "deterministic_proof": "anything"},
            None,
            ProofPayload(artifact_type="command_injection", response_text="no numbers"),
        )
        assert strength is ProofStrength.REFUTED

    def test_payload_passed_inside_verifier_result_is_accepted(self):
        j = adjudicate(
            verifier_result={
                "reproduced": True,
                "arithmetic_proof_confirmed": True,
                "proof_payload": {
                    "artifact_type": "command_injection",
                    "response_text": "www-data 72",
                    "expected_result": "72",
                },
            },
        )
        assert j.verdict is CourtVerdict.CONFIRMED
        assert j.proof_strength == ProofStrength.DERIVED.value

    def test_empty_payload_mapping_is_ignored(self):
        assert ProofPayload.from_mapping(None) is None
        assert ProofPayload.from_mapping({}) is None
        assert ProofPayload.from_mapping({"unrelated": 1}) is None

    def test_judgment_serialises_proof_fields(self):
        j = adjudicate(verifier_result={"reproduced": True, "canary_confirmed": True})
        d = j.to_dict()
        assert d["proof_strength"] == ProofStrength.DECLARED.value
        assert "proof_detail" in d
