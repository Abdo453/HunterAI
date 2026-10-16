"""LEDGER-016 (M1d): PoE is wired into the pipeline gate; signals become
hypotheses, not confirmations.

Acceptance: a candidate yields a CONFIRMED finding ONLY when a re-evaluable
ProofPayload proves execution. Without such proof the candidate is rejected
(and, in the pipeline, deferred as a hypothesis) — i.e. findings_count == 0.
"""
from __future__ import annotations

from core.causal.causal_graph import CausalSecurityGraph
from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
from hunter_ai.pipeline.qualification_gate import FindingQualificationGate
from hunter_ai.pipeline.schemas import FindingStatus

_ENDPOINT = "https://target.local/download"
_LFI_BODY = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"


def test_gate_rejects_scanner_signal_without_proof():
    is_q, finding, rationale = FindingQualificationGate.evaluate_candidate(
        title="Nuclei: possible SQL injection",
        asset="target.local",
        endpoint=_ENDPOINT,
        vuln_type="SQLi",
        raw_evidence="[sqli] possible injection at param id",
        source_tool="nuclei",
        verifier_result={"reproduced": True, "is_reflection": False},
        proof_payload=None,
    )
    assert is_q is False
    assert finding is None
    assert "Evidence Court" in rationale


def test_gate_confirms_with_valid_poe_payload():
    is_q, finding, rationale = FindingQualificationGate.evaluate_candidate(
        title="Path Traversal: /etc/passwd disclosure",
        asset="target.local",
        endpoint=_ENDPOINT,
        vuln_type="PathTraversal",
        raw_evidence=_LFI_BODY,
        source_tool="SpecialFileHunter",
        verifier_result={"reproduced": True, "is_reflection": False},
        proof_payload={"artifact_type": "lfi", "response_text": _LFI_BODY},
    )
    assert is_q is True
    assert finding is not None
    assert finding.status == FindingStatus.CONFIRMED


def test_court_verifier_result_is_truthful():
    # No proof payload -> reproduction is NOT claimed, even when observed.
    assert HunterPipelineOrchestrator._court_verifier_result(None, directly_observed=True)["reproduced"] is False

    # A re-evaluable payload from a first-hand observation -> reproduction claimed.
    payload = {"artifact_type": "lfi", "response_text": _LFI_BODY}
    assert HunterPipelineOrchestrator._court_verifier_result(payload, directly_observed=True)["reproduced"] is True

    # A scanner line is not observed first-hand -> never reproduction.
    assert HunterPipelineOrchestrator._court_verifier_result(payload, directly_observed=False)["reproduced"] is False


def test_causal_chain_requires_observed_differential():
    unproven = CausalSecurityGraph("api.test.local").build_standard_injection_chain(
        finding_id="F-TEST-A", param="q", sink_name="SQL_QUERY",
        differential_detail="claimed but unobserved",
    )
    assert unproven.is_causally_proven is False

    proven = CausalSecurityGraph("api.test.local").build_standard_injection_chain(
        finding_id="F-TEST-B", param="q", sink_name="SQL_QUERY",
        differential_detail="observed differential", observed_differential=True,
    )
    assert proven.is_causally_proven is True
