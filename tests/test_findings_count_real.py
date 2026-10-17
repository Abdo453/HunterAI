"""
LEDGER-027 (M5) — Real findings: findings_count.

Proves the pipeline only emits CONFIRMED findings when backed by re-evaluable
PoE, and never on a scanner line / reflected payload alone:
  - clean target (no proof)       -> 0 confirmed findings
  - sqli / lfi / cmdi with PoE    -> confirmed finding
  - out-of-scope                  -> rejected
  - xss / secret (no PoE family)  -> left UNVERIFIED (deferred hypothesis)
"""
from __future__ import annotations

from core.evidence_court import CourtVerdict, ProofPayload
from hunter_ai.pipeline.qualification_gate import FindingQualificationGate


def _gate() -> FindingQualificationGate:
    return FindingQualificationGate()


def test_clean_target_zero_confirmed_findings():
    """No proof payload => court returns UNVERIFIED => no confirmed finding."""
    gate = _gate()
    qualified, finding, rationale = gate.evaluate_candidate(
        title="Reflected input",
        asset="https://example.com",
        endpoint="https://example.com/page?q=test",
        vuln_type="XSS",
        raw_evidence="<script>alert(1)</script> echoed in response",
        source_tool="dalfox",
        verifier_result={"reproduced": True, "is_reflection": False},
        is_in_scope=True,
        proof_payload=None,
    )
    assert qualified is False
    assert finding is None
    assert "UNVERIFIED" in rationale or "No deterministic proof" in rationale


def test_out_of_scope_rejected_even_with_proof():
    gate = _gate()
    payload = ProofPayload.from_vuln_evidence("SQLi", "PostgreSQL 15.2 (deb x86-64)")
    assert payload is not None
    qualified, finding, rationale = gate.evaluate_candidate(
        title="SQLi",
        asset="https://evil.example.net",
        endpoint="https://evil.example.net/search?q=1",
        vuln_type="SQLi",
        raw_evidence="PostgreSQL 15.2 (deb x86-64)",
        source_tool="sqlmap",
        verifier_result={"reproduced": True, "is_reflection": False},
        is_in_scope=False,
        proof_payload=payload.to_dict(),
    )
    assert qualified is False
    assert finding is None


def test_sqli_with_poe_confirmed():
    gate = _gate()
    payload = ProofPayload.from_vuln_evidence("SQLi", "PostgreSQL 15.2 (deb x86-64)")
    assert payload is not None
    qualified, finding, rationale = gate.evaluate_candidate(
        title="SQLi banner extraction",
        asset="https://example.com",
        endpoint="https://example.com/search?q=1",
        vuln_type="SQLi",
        raw_evidence="PostgreSQL 15.2 (deb x86-64)",
        source_tool="sqlmap",
        verifier_result={"reproduced": True, "is_reflection": False},
        is_in_scope=True,
        proof_payload=payload.to_dict(),
    )
    assert qualified is True
    assert finding is not None
    assert finding.status.value == "CONFIRMED"
    assert "CONFIRMED by Evidence Court" in rationale


def test_lfi_with_poe_confirmed():
    gate = _gate()
    payload = ProofPayload.from_vuln_evidence("LFI", "root:x:0:0:root:/root:/bin/bash")
    assert payload is not None
    qualified, finding, _ = gate.evaluate_candidate(
        title="LFI /etc/passwd",
        asset="https://example.com",
        endpoint="https://example.com/file?path=../../../etc/passwd",
        vuln_type="LFI",
        raw_evidence="root:x:0:0:root:/root:/bin/bash",
        source_tool=" nuclei",
        verifier_result={"reproduced": True, "is_reflection": False},
        is_in_scope=True,
        proof_payload=payload.to_dict(),
    )
    assert qualified is True
    assert finding is not None
    assert finding.status.value == "CONFIRMED"


def test_cmdi_with_poe_confirmed():
    gate = _gate()
    payload = ProofPayload.from_vuln_evidence("cmd_injection", "command injection output: 72")
    assert payload is not None
    qualified, finding, _ = gate.evaluate_candidate(
        title="Command injection arithmetic",
        asset="https://example.com",
        endpoint="https://example.com/ping?host=1.1.1.1",
        vuln_type="CommandInjection",
        raw_evidence="command injection output: 72",
        source_tool="dalfox",
        verifier_result={"reproduced": True, "is_reflection": False},
        is_in_scope=True,
        proof_payload=payload.to_dict(),
    )
    assert qualified is True
    assert finding is not None
    assert finding.status.value == "CONFIRMED"


def test_no_poe_families_left_unverified():
    """Types without a PoE signature (XSS, Secret, NucleiExposure, ...) are
    honestly UNVERIFIED, never confirmed on a scanner line."""
    gate = _gate()
    for vuln_type, evidence in [
        ("XSS", "<svg onload=alert(1)>"),
        ("SecretLeak", "AKIAIOSFODNN7EXAMPLE"),
        ("NucleiExposure", "misconfig exposed"),
        ("SubdomainTakeover", "CNAME points to deleted bucket"),
    ]:
        qualified, finding, rationale = gate.evaluate_candidate(
            title=vuln_type,
            asset="https://example.com",
            endpoint="https://example.com/test",
            vuln_type=vuln_type,
            raw_evidence=evidence,
            source_tool="nuclei",
            verifier_result={"reproduced": True, "is_reflection": False},
            is_in_scope=True,
            proof_payload=None,
        )
        assert qualified is False, f"{vuln_type} must not be confirmed without PoE"
        assert finding is None
