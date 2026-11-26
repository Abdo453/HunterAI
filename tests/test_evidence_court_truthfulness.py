"""
Phase 3 Authoritative Evidence Court, 7-State Truthfulness, Anti-Stub & Real Replay Tests
=========================================================================================
Comprehensive hermetic + local loopback HTTP verification covering:
1. All 7 canonical CourtVerdict states + backward-compatible legacy aliases
2. Closed bare-diff loophole (response_text != baseline_text NEVER returns DERIVED)
3. Per-vulnerability-category ProofContract registry (all 13 categories)
4. UNAVAILABLE (timeout/missing binary) and ERROR (runtime exception) separation
5. Raised E3 minimum confirmed evidence level (E2 rejected, E3 accepted)
6. Hardened causal invariants (CommandExecution B+C word boundaries, BooleanDifferential
   volatile-noise stripping, DOMExecution runtime telemetry requirement, default registry)
7. EvidenceCourtV2 + AdversarialEvidenceProsecutor wiring
8. FinalEvidenceCourt rejecting LIKELY/CANDIDATE and defaulting missing verified to False
9. Legacy court shims (tribunal.py + hunter_ai/evidence/evidence_court.py) delegating truthfully
10. ValidationGate + SevenQuestionGate requiring canonical CONFIRMED/DERIVED, fail-closed Q7, zero Q6 freebie
11. Anti-stub cleanup: ZERO verified=True / synthetic data on missing tools or errors across
    all cleaned factories, adapters, orchestrators, controllers, and skills
12. OmniHunterEngine & live_scanner routing through FindingQualificationGate + EvidenceCourt
13. Real differential HTTP replay against a live local loopback vulnerable/safe HTTP server
    (ReplayLab, ReplayBundleFactory, and hunter_ai.tools.verifier)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from core.evidence.evidence_level import EvidenceLevel, EvidenceLevelEvaluator
from core.evidence_court import (
    CANONICAL_COURT_VERDICTS,
    CANONICAL_PROOF_CATEGORIES,
    PROOF_CONTRACT_REGISTRY,
    CausalEvidence,
    CourtJudgment,
    CourtVerdict,
    EvidenceCourt,
    ProofPayload,
    ProofStrength,
    canonical_verdict,
)
from core.reasoning.causal_invariants import (
    BooleanDifferentialInvariant,
    CausalInvariantRegistry,
    CommandExecutionInvariant,
    DOMExecutionInvariant,
)
from core.reasoning.triad_verifier import TransactionSnapshot, TriadBundle


# ── Local Loopback Vulnerable / Safe HTTP Fixture ─────────────────────────────

class _LoopbackReplayHandler(BaseHTTPRequestHandler):
    """Real loopback HTTP server with vulnerable and patched/safe endpoints."""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, code: int, body: str, content_type: str = "text/plain", headers: Dict[str, str] | None = None) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/vuln/sqli":
            q = (qs.get("id") or ["1"])[0]
            if "'" in q or "union" in q.lower():
                self._send(500, "ERROR: PostgreSQL 15.4 on x86_64-pc-linux-gnu near syntax")
            else:
                self._send(200, "Item #1: Standard Product Page")
            return

        if parsed.path == "/safe/sqli":
            self._send(200, "Item #1: Standard Product Page (parameterized safe)")
            return

        if parsed.path == "/vuln/cmd":
            expr = (qs.get("expr") or ["baseline"])[0]
            if "53+19" in expr:
                self._send(200, "calc output: 72")
            else:
                self._send(200, "calc output: ok")
            return

        if parsed.path == "/safe/cmd":
            expr = (qs.get("expr") or ["baseline"])[0]
            # Literal reflection only — never evaluates arithmetic
            self._send(200, f"echoed literal input: {expr}")
            return

        if parsed.path == "/vuln/idor":
            uid = (qs.get("id") or ["1"])[0]
            if uid == "2":
                self._send(200, json.dumps({"user": "victim", "secret": "VICTIM_CANARY_9944"}), "application/json")
            else:
                self._send(200, json.dumps({"user": "self", "secret": "OWN_DATA_11"}), "application/json")
            return

        if parsed.path == "/live_scan_root":
            # Serves link with query param + vulnerable CORS/env + safe reflected XSS
            self._send(
                200,
                "<html><head><title>Lab</title></head><body><a href='/live_search?q=hello'>Search</a></body></html>",
                "text/html",
                headers={
                    "Access-Control-Allow-Origin": self.headers.get("Origin", ""),
                    "Access-Control-Allow-Credentials": "true",
                } if self.headers.get("Origin") else None,
            )
            return

        if parsed.path == "/live_search":
            q = (qs.get("q") or [""])[0]
            self._send(200, f"<html><body>Query: {q}</body></html>", "text/html")
            return

        if parsed.path == "/.env":
            self._send(200, "APP_KEY=base64:real_non_placeholder_secret_key_9911\nDB_PASSWORD=realdbpass\n", "text/plain")
            return

        self._send(404, "Not Found")


@pytest.fixture(scope="module")
def loopback_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackReplayHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=3.0)


# ── 1. Canonical 7-State Evidence Court & Legacy Compatibility ───────────────

class TestCanonicalSevenStateCourt:
    def test_all_seven_canonical_states_and_legacy_mapping(self):
        expected_7 = {
            CourtVerdict.UNVERIFIED,
            CourtVerdict.CANDIDATE,
            CourtVerdict.CONFIRMED,
            CourtVerdict.REJECTED,
            CourtVerdict.INCONCLUSIVE,
            CourtVerdict.UNAVAILABLE,
            CourtVerdict.ERROR,
        }
        assert CANONICAL_COURT_VERDICTS == expected_7
        for v in expected_7:
            assert v.canonical_verdict() is v
            assert v.is_canonical is True

        # Backward-compatible legacy alias members map to REJECTED
        for legacy in (
            CourtVerdict.FALSE_POSITIVE,
            CourtVerdict.DISPROVED,
            CourtVerdict.OUT_OF_SCOPE,
            CourtVerdict.BLOCKED,
            CourtVerdict.DUPLICATE,
        ):
            assert legacy.canonical_verdict() is CourtVerdict.REJECTED
            assert canonical_verdict(legacy.value) is CourtVerdict.REJECTED

    def test_closed_bare_diff_loophole_never_returns_derived(self):
        """Regression for L268-273: bare response_text != baseline_text MUST NEVER confirm."""
        judgment = EvidenceCourt.adjudicate(
            target_url="https://target.example/page",
            parameter="q",
            vuln_class="generic_probe",
            verifier_result={"reproduced": True, "status_code": 200},
            proof_payload=ProofPayload(
                response_text="<html><body>Welcome user! Timestamp 12:01</body></html>",
                baseline_text="<html><body>Welcome user! Timestamp 12:00</body></html>",
                artifact_type="",
                expected_token="",
            ),
            is_in_scope=True,
        )
        assert judgment.verdict is not CourtVerdict.CONFIRMED
        assert judgment.verdict in (CourtVerdict.CANDIDATE, CourtVerdict.INCONCLUSIVE)
        assert judgment.proof_strength == ProofStrength.NONE.value
        assert judgment.reportable is False

    def test_distinguishes_unavailable_and_error_from_inconclusive(self):
        # 1. Missing verifier -> INCONCLUSIVE
        j_inc = EvidenceCourt.adjudicate(
            target_url="https://target.example/a",
            parameter="id",
            vuln_class="sqli",
            verifier_result=None,
        )
        assert j_inc.verdict is CourtVerdict.INCONCLUSIVE
        assert j_inc.canonical_verdict is CourtVerdict.INCONCLUSIVE
        assert j_inc.reportable is False

        # 2. Verifier timeout -> UNAVAILABLE
        j_to = EvidenceCourt.adjudicate(
            target_url="https://target.example/a",
            parameter="id",
            vuln_class="sqli",
            verifier_result={"timeout": True, "reason": "probe timed out after 10s"},
        )
        assert j_to.verdict is CourtVerdict.UNAVAILABLE
        assert j_to.canonical_verdict is CourtVerdict.UNAVAILABLE
        assert j_to.reportable is False

        # 3. Missing binary (exit_code=127 / missing_binary) -> UNAVAILABLE
        j_bin = EvidenceCourt.adjudicate(
            target_url="https://target.example/a",
            parameter="id",
            vuln_class="sqli",
            verifier_result={"missing_binary": True, "exit_code": 127},
        )
        assert j_bin.verdict is CourtVerdict.UNAVAILABLE
        assert j_bin.reportable is False

        # 4. Runtime exception -> ERROR
        j_err = EvidenceCourt.adjudicate(
            target_url="https://target.example/a",
            parameter="id",
            vuln_class="sqli",
            verifier_result={"error": "ZeroDivisionError in parser"},
        )
        assert j_err.verdict is CourtVerdict.ERROR
        assert j_err.canonical_verdict is CourtVerdict.ERROR
        assert j_err.reportable is False

        # 5. Candidate status -> CANDIDATE
        j_cand = EvidenceCourt.adjudicate(
            target_url="https://target.example/a",
            parameter="id",
            vuln_class="sqli",
            verifier_result={"reproduced": False, "status": "CANDIDATE"},
        )
        assert j_cand.verdict is CourtVerdict.CANDIDATE
        assert j_cand.reportable is False

        # 6. Out of scope -> OUT_OF_SCOPE (canonical REJECTED)
        j_oos = EvidenceCourt.adjudicate(
            target_url="https://evil.example/a",
            parameter="id",
            vuln_class="sqli",
            verifier_result={"reproduced": True},
            is_in_scope=False,
        )
        assert j_oos.verdict is CourtVerdict.OUT_OF_SCOPE
        assert j_oos.canonical_verdict is CourtVerdict.REJECTED


# ── 2. Per-Category ProofContract Registry (13 Categories) ───────────────────

class TestProofContractRegistry:
    def test_all_13_categories_registered(self):
        registered = set(PROOF_CONTRACT_REGISTRY.list_categories())
        assert set(CANONICAL_PROOF_CATEGORIES) == registered
        assert len(registered) == 13

    def test_each_category_derives_real_proof_and_rejects_bare_diff(self):
        # Build a genuine weak-secret JWT to verify cryptographic HMAC verification
        hdr = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        pld = base64.urlsafe_b64encode(b'{"sub":"1","role":"user"}').decode().rstrip("=")
        sig = base64.urlsafe_b64encode(hmac.new(b"secret", f"{hdr}.{pld}".encode(), hashlib.sha256).digest()).decode().rstrip("=")
        real_weak_jwt = f"{hdr}.{pld}.{sig}"

        valid_cases = {
            "sqli": ProofPayload(artifact_type="sqli", response_text="PostgreSQL 15.3 on linux", baseline_text="normal page"),
            "xss": ProofPayload(artifact_type="xss", response_text="<body>hi</body>", baseline_text="<body>hi</body>", expected_token="canary_dom_1", metadata={"dom_executed": True}),
            "cmdi": ProofPayload(artifact_type="cmdi", response_text="out: 72", baseline_text="out: ok", probed_expression="53+19", expected_result="72"),
            "ssrf": ProofPayload(artifact_type="ssrf", response_text="ami-0123456789abcdef0", baseline_text="normal"),
            "idor": ProofPayload(artifact_type="idor", response_text='{"token":"VICTIM_TOK_88"}', baseline_text='{"token":"SELF_TOK_11"}', expected_token="VICTIM_TOK_88", metadata={"actor_id": "u1", "owner_id": "u2", "status_code": 200}),
            "lfi": ProofPayload(artifact_type="lfi", response_text="root:x:0:0:root:/root:/bin/bash", baseline_text="normal"),
            "ssti": ProofPayload(artifact_type="ssti", response_text="Hello 49 world", baseline_text="Hello guest world", probed_expression="7*7", expected_result="49"),
            "auth": ProofPayload(artifact_type="auth", response_text="ADMIN_SECRET_PANEL", baseline_text="Login required", expected_token="ADMIN_SECRET_PANEL", metadata={"baseline_status": 401, "probe_status": 200}),
            "jwt": ProofPayload(artifact_type="jwt", response_text="ok", metadata={"raw_jwt": real_weak_jwt, "cracked_secret": "secret"}),
            "deser": ProofPayload(artifact_type="deser", response_text="ok", expected_token="oob_deser_99", metadata={"oob_callbacks": ["dns:oob_deser_99.oob.local"]}),
            "race": ProofPayload(artifact_type="race", response_text="ok", metadata={"concurrent_success_count": 5, "expected_max_success": 1, "state_delta_verified": True}),
            "secret": ProofPayload(artifact_type="secret", response_text="const k = 'AKIA9876543210ABCDEF';"),
            "misconfig": ProofPayload(artifact_type="misconfig", response_text="ref: refs/heads/main\n", baseline_text="404 Not Found"),
        }

        for cat, payload in valid_cases.items():
            j = EvidenceCourt.adjudicate(
                target_url=f"https://target.example/{cat}",
                parameter="p",
                vuln_class=cat,
                verifier_result={"reproduced": True, "status_code": 200},
                proof_payload=payload,
            )
            assert j.verdict is CourtVerdict.CONFIRMED, (cat, j.adjudication_rationale)
            assert j.proof_strength == ProofStrength.DERIVED.value

            # Bare response diff without proof for the same category MUST NEVER confirm
            j_bare = EvidenceCourt.adjudicate(
                target_url=f"https://target.example/{cat}",
                parameter="p",
                vuln_class=cat,
                verifier_result={"reproduced": True, "status_code": 200},
                proof_payload=ProofPayload(
                    artifact_type=cat,
                    response_text="slightly different benign text B",
                    baseline_text="slightly different benign text A",
                ),
            )
            assert j_bare.verdict is not CourtVerdict.CONFIRMED, f"{cat} confirmed on bare diff!"
            assert j_bare.proof_strength != ProofStrength.DERIVED.value


# ── 3. Raised E3 Minimum Evidence Level & Hardened Causal Invariants ─────────

class TestEvidenceLevelAndCausalInvariants:
    def test_minimum_confirmed_level_is_e3(self):
        assert EvidenceLevelEvaluator.MINIMUM_CONFIRMED_LEVEL == EvidenceLevel.E3_INVARIANT_VIOLATION

        r_e2 = EvidenceLevelEvaluator.evaluate(
            finding_data={"proof": "status diverged"},
            evidence_items=[{"diff": "status_diverged"}],
            reproduction_count=3,
        )
        assert r_e2.level == EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR
        assert r_e2.is_confirmed_eligible is False

        r_e3 = EvidenceLevelEvaluator.evaluate(
            finding_data={"proof": "cross-tenant data leaked", "contract_satisfied": True},
            evidence_items=[{"diff": "cross-tenant"}],
            reproduction_count=2,
        )
        assert r_e3.level == EvidenceLevel.E3_INVARIANT_VIOLATION
        assert r_e3.is_confirmed_eligible is True

    def test_command_execution_invariant_checks_baseline_and_word_boundaries(self):
        inv = CommandExecutionInvariant(expected_token="72", e1_expr="53+19", e2_expr="41+31")

        # Token 72 already in Baseline B -> MUST fail (invalidated)
        b_has_72 = TriadBundle(
            hypothesis_id="h1",
            target_endpoint="/calc",
            baseline=TransactionSnapshot(status_code=200, body="Count: 72 items"),
            control=TransactionSnapshot(status_code=200, body="Count: 53 items"),
            experiment_1=TransactionSnapshot(status_code=200, body="Count: 72 items"),
            experiment_2=TransactionSnapshot(status_code=200, body="Count: 72 items"),
        )
        res_b = inv.evaluate(b_has_72)
        assert res_b.passed is False
        assert res_b.invalidation_detail == "baseline_contains_token"

        # Substring '72' inside 'nonce_127234' in B/C must NOT falsely trigger boundary collision,
        # while standalone '72' in E1/E2 passes
        b_nonce = TriadBundle(
            hypothesis_id="h2",
            target_endpoint="/calc",
            baseline=TransactionSnapshot(status_code=200, body="id=nonce_127234"),
            control=TransactionSnapshot(status_code=200, body="id=nonce_997211 out=53"),
            experiment_1=TransactionSnapshot(status_code=200, body="id=nonce_000001 out=72"),
            experiment_2=TransactionSnapshot(status_code=200, body="id=nonce_000002 out=72"),
        )
        res_ok = inv.evaluate(b_nonce)
        assert res_ok.passed is True

        # Non-boundary '1720' in E1/E2 must NOT falsely confirm '72'
        b_sub = TriadBundle(
            hypothesis_id="h3",
            target_endpoint="/calc",
            baseline=TransactionSnapshot(status_code=200, body="ok"),
            control=TransactionSnapshot(status_code=200, body="ok"),
            experiment_1=TransactionSnapshot(status_code=200, body="code=1720"),
            experiment_2=TransactionSnapshot(status_code=200, body="code=1720"),
        )
        assert inv.evaluate(b_sub).passed is False

    def test_boolean_differential_strips_volatile_noise(self):
        inv = BooleanDifferentialInvariant()

        # Volatile jitter comment + timestamp length delta > 100 bytes MUST NOT pass!
        noisy_same = TriadBundle(
            hypothesis_id="hb1",
            target_endpoint="/items",
            baseline=TransactionSnapshot(status_code=200, body="<div>Item A</div><!-- " + "X" * 10 + " --> 2026-11-26 10:00:01"),
            control=TransactionSnapshot(status_code=200, body="<div>Item A</div><!-- " + "Y" * 200 + " --> 2026-11-26 10:00:02"),
            experiment_1=TransactionSnapshot(status_code=200, body="<div>Item A</div><!-- " + "Z" * 15 + " --> 2026-11-26 10:00:03"),
            experiment_2=TransactionSnapshot(status_code=200, body="<div>Item A</div><!-- " + "W" * 12 + " --> 2026-11-26 10:00:04"),
        )
        res_noise = inv.evaluate(noisy_same)
        assert res_noise.passed is False
        assert res_noise.invalidation_detail == "volatile_jitter_only"

        # Genuine structural boolean bifurcation (True returns records, False returns empty) passes
        real_split = TriadBundle(
            hypothesis_id="hb2",
            target_endpoint="/items",
            baseline=TransactionSnapshot(status_code=200, body="<ul><li>Alpha Product</li><li>Beta Product</li><li>Gamma Widget</li></ul><!-- nonce_111111 -->"),
            control=TransactionSnapshot(status_code=200, body="<p>No matching records found</p><!-- nonce_222222 -->"),
            experiment_1=TransactionSnapshot(status_code=200, body="<ul><li>Alpha Product</li><li>Beta Product</li><li>Gamma Widget</li></ul><!-- nonce_333333 -->"),
            experiment_2=TransactionSnapshot(status_code=200, body="<ul><li>Alpha Product</li><li>Beta Product</li><li>Gamma Widget</li></ul><!-- nonce_444444 -->"),
        )
        assert inv.evaluate(real_split).passed is True

    def test_dom_execution_invariant_rejects_inert_html_and_registry_populated(self):
        # Default registry MUST have built-in invariants registered
        invs = CausalInvariantRegistry.list_invariants()
        ids = {i["id"] for i in invs}
        assert "INV-CMD-EXEC-01" in ids
        assert "INV-BOOLEAN-DIFF-01" in ids
        assert "INV-DOM-EXECUTION-01" in ids
        assert "INV-OOB-CORRELATION-01" in ids

        dom_inv = DOMExecutionInvariant(canary="CANARY_XSS_77")
        # Inert HTML attribute match without browser DOM execution telemetry -> MUST FAIL
        inert_bundle = TriadBundle(
            hypothesis_id="hd1",
            target_endpoint="/search",
            baseline=TransactionSnapshot(status_code=200, body="<div>hello</div>"),
            control=TransactionSnapshot(status_code=200, body="<div>safe</div>"),
            experiment_1=TransactionSnapshot(status_code=200, body='<div data-x="CANARY_XSS_77">ok</div>'),
            experiment_2=TransactionSnapshot(status_code=200, body='<div data-x="CANARY_XSS_77">ok</div>'),
        )
        r_inert = dom_inv.evaluate(inert_bundle)
        assert r_inert.passed is False
        assert r_inert.invalidation_detail == "inert_html_reflection_only"

        # Actual runtime DOM execution telemetry -> PASSES
        exec_bundle = TriadBundle(
            hypothesis_id="hd2",
            target_endpoint="/search",
            baseline=TransactionSnapshot(status_code=200, body="<div>hello</div>"),
            control=TransactionSnapshot(status_code=200, body="<div>safe</div>"),
            experiment_1=TransactionSnapshot(status_code=200, body="<div>ok</div>", extracted_tokens=["CANARY_XSS_77"]),
            experiment_2=TransactionSnapshot(status_code=200, body="<div>ok</div>", extracted_tokens=["CANARY_XSS_77"]),
            metadata={"dom_execution_observed": True, "console_logs": ["DOM_FIRED:CANARY_XSS_77"]},
        )
        assert dom_inv.evaluate(exec_bundle).passed is True


# ── 4. Legacy Court Adapters, FinalEvidenceCourt & 7-Question Gates ──────────

class TestLegacyAdaptersAndGates:
    def test_evidence_court_v2_wires_prosecutor_and_canonical_states(self):
        from core.court.evidence_court_v2 import EvidenceCourtV2

        # Auth finding with DERIVED token proof BUT prosecutor challenge sensitive_data_leaked=False -> NOT confirmed
        ruling = EvidenceCourtV2.adjudicate_case(
            case_id="P-1",
            endpoint="https://target.example/api/profile",
            proof_nonce_proven=True,
            reproductions_count=2,
            causal_chain_verified=True,
            baseline_stable=True,
            waf_clean=True,
            vuln_family="AUTH_BYPASS",
            verifier_result={"reproduced": True, "sensitive_data_leaked": False},
            proof_payload=ProofPayload(
                artifact_type="token",
                expected_token="OK_TOKEN",
                response_text="OK_TOKEN",
                baseline_text="none",
            ),
        )
        assert ruling.final_verdict != "CONFIRMED"
        assert ruling.canonical_verdict == "REJECTED"
        assert ruling.prosecutor_ruling is not None
        assert ruling.prosecutor_ruling["prosecutor_disposition"] == "OBJECTION_SUSTAINED"

        # Unavailable verifier propagates UNAVAILABLE cleanly
        ruling_unavail = EvidenceCourtV2.adjudicate_case(
            case_id="P-2",
            endpoint="https://target.example/api/profile",
            proof_nonce_proven=False,
            reproductions_count=0,
            causal_chain_verified=True,
            baseline_stable=True,
            waf_clean=True,
            verifier_result={"timeout": True},
        )
        assert ruling_unavail.canonical_verdict == "UNAVAILABLE"

    def test_final_court_rejects_likely_candidate_and_missing_verified(self):
        from hunter_ai.pipeline.final_court import FinalEvidenceCourt
        from hunter_ai.pipeline.schemas import FindingStatus

        base = {
            "id": "f1",
            "finding": "SQLi in /search",
            "asset": "example.test",
            "endpoint": "https://example.test/search",
            "vuln_type": "sqli",
            "evidence": [{"description": "proof", "proof_snippet": "PostgreSQL 15", "verified": True}],
            "reproduction": {"curl_command": "curl https://example.test/search?q=1"},
        }

        # LIKELY MUST NEVER return PASSED
        likely_f = {**base, "status": FindingStatus.LIKELY}
        entry_l, reason_l = FinalEvidenceCourt.audit_one(likely_f)
        assert entry_l.verdict == "DEMOTED"
        assert reason_l is not None

        # CANDIDATE MUST NEVER return PASSED
        cand_f = {**base, "status": FindingStatus.CANDIDATE}
        entry_c, reason_c = FinalEvidenceCourt.audit_one(cand_f)
        assert entry_c.verdict == "DEMOTED"
        assert reason_c is not None

        # Missing 'verified' key in evidence dict defaults to False -> DEMOTED!
        missing_ver = {
            **base,
            "status": FindingStatus.CONFIRMED,
            "evidence": [{"description": "claimed without verified key", "proof_snippet": "x"}],
        }
        entry_mv, reason_mv = FinalEvidenceCourt.audit_one(missing_ver)
        assert entry_mv.verdict == "DEMOTED"
        assert reason_mv == "unverified_evidence"

    @pytest.mark.asyncio
    async def test_legacy_tribunal_and_waf_court_delegate_truthfully(self):
        from core.adversarial_court.tribunal import CourtEvidence, EvidenceCourt as TribunalCourt, Verdict
        from hunter_ai.evidence.evidence_court import BypassContext, CourtVerdict as WafVerdict, EvidenceCourt as WafCourt

        # Tribunal: high confidence arithmetic alone WITHOUT checkable proof MUST NOT confirm
        tribunal = TribunalCourt()
        case_no_proof = await tribunal.try_case(
            case_id="T-1",
            finding_type="sqli",
            target="https://target.example/search",
            evidence=[
                CourtEvidence("e1", "tool_a", "corroboration", "high conf", 0.99, {"evidence_level": "E1"}),
                CourtEvidence("e2", "tool_b", "corroboration", "high conf", 0.99, {"evidence_level": "E1"}),
            ],
            initial_confidence=0.95,
        )
        assert case_no_proof.verdict != Verdict.CONFIRMED

        # Tribunal: with real DERIVED proof payload -> CONFIRMED
        case_real = await tribunal.try_case(
            case_id="T-2",
            finding_type="sqli",
            target="https://target.example/search",
            evidence=[
                CourtEvidence(
                    "e3",
                    "verifier",
                    "proof",
                    "dbms banner",
                    0.95,
                    {"artifact_type": "sqli", "response_text": "PostgreSQL 15.2 on x86_64", "baseline_text": "ok"},
                ),
            ],
        )
        assert case_real.verdict == Verdict.CONFIRMED
        assert case_real.canonical_verdict == "CONFIRMED"

        # WAF Court: naive substring reflection MUST NOT return PROVEN_BYPASS!
        waf_court = WafCourt()
        ctx_reflect = BypassContext(
            target="https://target.example",
            endpoint="/search",
            original_payload="<script>alert(1)</script>",
            bypass_payload="test_reflected_payload",
            waf_type="Cloudflare",
            waf_detected=True,
            status_code=200,
            response_body="<html>Search results for: test_reflected_payload</html>",
            response_headers={},
            request_headers={},
            response_time_ms=42.0,
            technique_level="L2",
        )
        res_reflect = waf_court.verify_bypass(ctx_reflect, case_id="W-1")
        assert res_reflect.verdict == WafVerdict.REFUTED
        assert res_reflect.bypass_confirmed is False

        # WAF Court: 403 block with waf_detected=True MUST return REFUTED (not PROVEN_BYPASS!)
        ctx_403 = BypassContext(
            target="https://target.example",
            endpoint="/search",
            original_payload="x",
            bypass_payload="x",
            waf_type="Cloudflare",
            waf_detected=True,
            status_code=403,
            response_body="Access Denied by WAF",
            response_headers={},
            request_headers={},
            response_time_ms=10.0,
            technique_level="L1",
        )
        res_403 = waf_court.verify_bypass(ctx_403, case_id="W-2")
        assert res_403.verdict == WafVerdict.REFUTED
        assert res_403.bypass_confirmed is False

        # WAF Court: DERIVED proof with waf_detected=True -> PROVEN_BYPASS
        ctx_real = BypassContext(
            target="https://target.example",
            endpoint="/ping",
            original_payload=";id",
            bypass_payload="53+19",
            waf_type="Cloudflare",
            waf_detected=True,
            status_code=200,
            response_body="PING output: 72",
            baseline_body="PING output: ok",
            response_headers={},
            request_headers={},
            response_time_ms=50.0,
            technique_level="L3",
            vuln_class="cmdi",
            expected_result="72",
        )
        res_real = waf_court.verify_bypass(ctx_real, case_id="W-3")
        assert res_real.verdict == WafVerdict.PROVEN_BYPASS
        assert res_real.bypass_confirmed is True

    def test_validation_gate_and_seven_question_gate_enforce_derived_proof_and_fail_closed(self):
        from core.seven_question_gate import SevenQuestionGate
        from hunter_ai.validation_gate import GateVerdict, ValidationGate

        # 1. ValidationGate rejects caller-set boolean flags without DERIVED proof
        vg = ValidationGate()
        vg.safety_loop.kg.add_in_scope("example.com")
        vg.safety_loop.kg.add_in_scope("https://example.com/api")

        bare_flags = {
            "title": "Claimed SQLi",
            "target": "https://example.com/api",
            "evidence": {
                "poc": "curl https://example.com/api?id=1'",
                "differential_response": True,
                "poe_verified": True,
                "deterministic_proof": True,
                "real_exploit_path": True,
                "impact": "Full DB extraction across customer table",
                "request_hash": "a" * 64,
                "response_hash": "b" * 64,
                "severity": "high",
            },
        }
        v_res_bad = vg.validate(bare_flags)
        assert v_res_bad.status != GateVerdict.PROVEN
        assert v_res_bad.proof_strength == ProofStrength.DECLARED.value

        # ValidationGate approves when backed by canonical DERIVED proof
        derived_finding = {
            **bare_flags,
            "evidence": {
                **bare_flags["evidence"],
                "vuln_class": "sqli",
                "proof_payload": {
                    "artifact_type": "sqli",
                    "response_text": "PostgreSQL 15.1 on x86_64",
                    "baseline_text": "normal item",
                },
            },
        }
        v_res_ok = vg.validate(derived_finding)
        assert v_res_ok.status == GateVerdict.PROVEN
        assert v_res_ok.proof_strength == ProofStrength.DERIVED.value

        # 2. SevenQuestionGate: len(evidence) > 20 alone MUST NOT pass Q3; empty in_scope fails Q7;
        #    missing recommendation gets 0.0 (not +0.8) on Q6!
        weak_long = {
            "title": "Noise claim",
            "type": "sqli",
            "severity": "High",
            "url": "https://api.target.com/items",
            "target": "api.target.com",
            "evidence": "A" * 100,  # >20 chars, zero proof
            "recommendation": "",
        }
        g_weak = SevenQuestionGate.evaluate_finding(weak_long, in_scope_list=[])
        assert g_weak.passed is False
        assert any("Q3" in m for m in g_weak.missing_items)
        assert any("Q6" in m for m in g_weak.missing_items)
        assert any("Q7" in m for m in g_weak.missing_items)
        # Q1(1) + Q2(1) + Q5(1) = 3/7 = 0.43 (NO +0.8 on Q6, NO +1.0 on Q7, NO +1.0 on Q3/Q4!)
        assert g_weak.score == round(3.0 / 7.0, 2)

        # Solid finding with DERIVED proof, concrete reproduction, remediation, and non-empty in_scope passes
        solid = {
            "title": "SQLi on /items",
            "type": "sqli",
            "severity": "Critical",
            "url": "https://api.target.com/items?id=1'",
            "target": "api.target.com",
            "evidence": "PostgreSQL 15.4 on x86_64-pc-linux-gnu",
            "poc": "curl 'https://api.target.com/items?id=1%27'",
            "recommendation": "Use parameterized SQL prepared statements.",
        }
        g_ok = SevenQuestionGate.evaluate_finding(solid, in_scope_list=["api.target.com"])
        assert g_ok.passed is True
        assert g_ok.score == 1.0
        assert g_ok.proof_strength == ProofStrength.DERIVED.value


# ── 5. Anti-Stub Cleanup: ZERO Synthetic verified=True Across All Modules ────

class TestAntiStubCleanup:
    def test_tool_agent_factory_and_real_tool_adapter_fail_closed_and_reap_timeout(self):
        from core.arsenal.tool_agent_factory import ToolAgentFactory
        from core.engine.real_tool_adapter import RealToolAdapter

        adapter = RealToolAdapter(force_fallback=True)
        factory = ToolAgentFactory(adapter=adapter)

        for tool_name in ("subfinder", "nmap", "katana", "nuclei", "ffuf"):
            agent = factory.get_agent(tool_name)
            res = agent.execute(target="example.com", deliberate=False)
            assert res.success is False
            assert res.exit_code == 127
            assert res.used_fallback is False
            assert res.status == "UNAVAILABLE"
            assert res.structured_data.get("status") == "UNAVAILABLE"
            assert "cve-2023-sample" not in res.stdout
            assert "/backup.zip" not in res.stdout

        # RealToolAdapter unavailable methods
        for r in (
            adapter.execute_subfinder("example.com"),
            adapter.execute_nmap_ports("example.com"),
            adapter.execute_httpx_endpoints(["https://example.com"]),
        ):
            assert r.success is False
            assert r.exit_code == 127
            assert r.used_fallback is False
            assert r.status == "UNAVAILABLE"

        # RealToolAdapter timeout properly awaits kill_process_tree(proc) without RuntimeWarning
        live_adapter = RealToolAdapter(force_fallback=False)
        ec, out, err = live_adapter._run_subprocess(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=0.15,
        )
        assert ec == -1
        assert "TimeoutExpired" in err

    def test_world_elite_orchestrator_returns_unavailable_not_simulated(self, tmp_path):
        from core.brain.world_elite_orchestrator import MissionConfig, WorldEliteOrchestrator

        orch = WorldEliteOrchestrator(MissionConfig(target="https://target.example", scope=["target.example"], output_dir=str(tmp_path)))
        with patch("shutil.which", return_value=None):
            for name in ("port_scanner", "web_crawler", "nuclei_scan", "sqlmap_scan", "subdomain_enum", "web_fingerprint", "nikto_scan", "exploit_runner", "privilege_checker"):
                out = orch.tool_registry[name](target="https://target.example")
                assert "[SIMULATED]" not in out
                parsed = json.loads(out)
                assert parsed["status"] == "UNAVAILABLE"
                assert parsed["verified"] is False

    @pytest.mark.asyncio
    async def test_controllers_fail_closed_and_allow_explicit_transport_fn(self):
        from core.burp_gateway.correlation import BurpCorrelationContext
        from core.burp_gateway.traffic_normalizer import (
            CanonicalIdentity,
            CanonicalRequest,
            CanonicalResponse,
            CanonicalTransaction,
            TargetStateContext,
            TrafficSource,
        )
        from core.controllers.browser_controller import BrowserController
        from core.controllers.burp_research_controller import ActionStatus, BurpResearchController
        from core.scope_guard import ScopeGuard

        # BrowserController: network error -> UNAVAILABLE, NEVER "Simulated Lab" HTML
        bc_fail = BrowserController(timeout=0.5)
        nav_fail = await bc_fail.navigate("http://127.0.0.1:1/unreachable")
        assert nav_fail.status == "UNAVAILABLE"
        assert nav_fail.status_code == 0
        assert "Simulated Lab" not in nav_fail.dom_snippet

        # BrowserController: explicit transport_fn works in isolated unit tests
        bc_inj = BrowserController(transport_fn=lambda url, hdrs: (200, "<html><title>Unit</title></html>"))
        nav_ok = await bc_inj.navigate("https://unit.test/")
        assert nav_ok.status == "OK"
        assert nav_ok.status_code == 200
        assert nav_ok.title == "Unit"

        # BurpResearchController: no _default_mock_transport; production fails closed on unreachable target
        assert not hasattr(BurpResearchController, "_default_mock_transport")
        guard = ScopeGuard(in_scope=["127.0.0.1", "unit.test"])
        brc_prod = BurpResearchController(scope_guard=guard, timeout=0.5)
        tx = CanonicalTransaction(
            tx_id="tx_1",
            source=TrafficSource.PROXY,
            correlation=BurpCorrelationContext(transaction_id="tx_1"),
            request=CanonicalRequest(method="GET", url="http://127.0.0.1:1/api/users?user_id=102", host="127.0.0.1"),
            response=CanonicalResponse(status_code=403, body="Forbidden"),
            identity=CanonicalIdentity(),
            state=TargetStateContext(),
        )
        brc_prod.ingest_canonical(tx)
        res_fail = brc_prod.replay("tx_1")
        assert res_fail.receipt.status == ActionStatus.FAILED
        assert "UNAVAILABLE" in res_fail.receipt.reason
        assert res_fail.transaction is None

        # BurpResearchController: explicit transport_fn works in isolated unit tests
        brc_inj = BurpResearchController(
            scope_guard=guard,
            transport_fn=lambda req: CanonicalResponse(status_code=200, body="injected_ok"),
        )
        brc_inj.ingest_canonical(tx)
        res_ok = brc_inj.replay("tx_1")
        assert res_ok.receipt.status == ActionStatus.EXECUTED
        assert res_ok.transaction is not None
        assert res_ok.transaction.response.body == "injected_ok"

    @pytest.mark.asyncio
    async def test_all_cleaned_agent_and_workspace_skills_never_fabricate_verified_true(self, tmp_path):
        from agents.skills.cache_poisoning_skill import CachePoisoningSkill
        from agents.skills.jwt_advanced_skill import JWTAdvancedSkill
        from agents.skills.path_traversal_skill import PathTraversalSkill
        from agents.skills.prototype_pollution_skill import PrototypePollutionSkill
        from core.workspace_manager import WorkspaceManager
        from skills.base_skill import SkillContext
        from skills.browser.auth_session_extractor.skill import AuthSessionExtractorSkill
        from skills.browser.dom_xss_hunter.skill import DOMXSSHunterSkill
        from skills.browser.spa_api_extractor.skill import SPAAPIExtractorSkill
        from skills.burp.burp_browser_fusion.skill import BurpBrowserFusionSkill
        from skills.burp.burp_traffic_analyzer.skill import BurpTrafficAnalyzerSkill
        from skills.burp.request_mutator.skill import RequestMutatorSkill
        from skills.cognitive.exploit_chain_builder.skill import ExploitChainBuilderSkill
        from skills.cognitive.threat_modeler.skill import ThreatModelerSkill
        from tools.tool_manager import ToolManager

        # 1. Agent skills (4): missing token / transport error -> verified=False, status=UNAVAILABLE, confidence=0.0
        jwt_res = await JWTAdvancedSkill().run("http://127.0.0.1:1/api", "token")
        assert jwt_res.verified is False and jwt_res.status == "UNAVAILABLE" and jwt_res.confidence == 0.0

        for skill_cls in (PathTraversalSkill, PrototypePollutionSkill, CachePoisoningSkill):
            with patch("httpx.AsyncClient", side_effect=RuntimeError("offline")):
                r = await skill_cls().run("http://127.0.0.1:1/api", "p")
                assert r.verified is False, skill_cls.__name__
                assert r.status == "UNAVAILABLE", skill_cls.__name__
                assert r.confidence == 0.0, skill_cls.__name__

        # 2. RequestMutatorSkill: on exception records error, NEVER mut_status=200!
        ws = WorkspaceManager(str(tmp_path / "ws"))
        tm = ToolManager()
        ctx_mut = SkillContext(
            target="http://127.0.0.1:1",
            session_id="sess_mut",
            workspace=ws,
            tool_manager=tm,
            extra={"requests": [{"method": "GET", "url": "http://127.0.0.1:1/api/users", "params": {"user_id": "1"}, "headers": {}}]},
        )
        mut_res = await RequestMutatorSkill().execute(ctx_mut)
        assert mut_res.success is False
        assert mut_res.findings == []
        assert mut_res.metadata.get("status") == "UNAVAILABLE"
        assert len(mut_res.errors) > 0

        # 3. Browser / Burp / Cognitive skills (7): offline/empty -> status=UNAVAILABLE, verified=False, zero fake findings
        base_ctx = SkillContext(target="http://127.0.0.1:1", session_id="sess_off", workspace=ws, tool_manager=tm, extra={})

        with patch("core.browser.ai_browser_operator.AIBrowserOperator", side_effect=RuntimeError("no browser")):
            auth_res = await AuthSessionExtractorSkill().execute(base_ctx)
            assert auth_res.success is False
            assert auth_res.metadata["session_valid"] is False
            assert auth_res.metadata["verified"] is False
            assert auth_res.metadata["status"] == "UNAVAILABLE"
            assert auth_res.findings == []

        with patch("core.browser.ai_browser_operator.run_ai_browser_session_sync", side_effect=RuntimeError("no browser")):
            dom_res = await DOMXSSHunterSkill().execute(base_ctx)
            assert dom_res.success is False
            assert dom_res.metadata["status"] == "UNAVAILABLE"
            assert dom_res.metadata["verified"] is False
            assert dom_res.findings == []

            spa_res = await SPAAPIExtractorSkill().execute(base_ctx)
            assert spa_res.success is False
            assert spa_res.metadata["status"] == "UNAVAILABLE"
            assert spa_res.metadata["verified"] is False
            assert spa_res.findings == []

            fusion_res = await BurpBrowserFusionSkill().execute(base_ctx)
            assert fusion_res.success is False
            assert fusion_res.metadata["status"] == "UNAVAILABLE"
            assert fusion_res.metadata["verified"] is False
            assert fusion_res.findings == []

        ctx_burp = SkillContext(target="http://127.0.0.1:1", session_id="sess_bta", workspace=ws, tool_manager=tm, extra={"burp_port": 1})
        bta_res = await BurpTrafficAnalyzerSkill().execute(ctx_burp)
        assert bta_res.success is False
        assert bta_res.metadata["status"] == "UNAVAILABLE"
        assert bta_res.metadata["verified"] is False
        assert bta_res.findings == []

        tm_res = await ThreatModelerSkill().execute(base_ctx)
        assert tm_res.success is False
        assert tm_res.metadata["status"] == "UNAVAILABLE"
        assert tm_res.metadata["verified"] is False
        assert tm_res.findings == []

        ec_res = await ExploitChainBuilderSkill().execute(base_ctx)
        assert ec_res.success is False
        assert ec_res.metadata["status"] == "UNAVAILABLE"
        assert ec_res.metadata["verified"] is False
        assert ec_res.findings == []


# ── 6. OmniHunterEngine & live_scanner Court Routing ─────────────────────────

class TestEngineAndLiveScannerRouting:
    def test_omni_hunter_engine_routes_candidates_through_evidence_court(self, tmp_path):
        from core.engine.omni_hunter_engine import AssessmentConfig, OmniHunterEngine

        cfg = AssessmentConfig(
            target_url="https://authorized.example",
            scope_domains=["authorized.example"],
            snapshot_dir=str(tmp_path / "snaps"),
            engagement_id="ENG-COURT-1",
        )
        engine = OmniHunterEngine(cfg)

        # Unproven candidate -> stays out of confirmed_findings!
        engine._emit_candidate_finding({
            "vuln_class": "XSS",
            "target": "https://authorized.example/search?q=test",
            "title": "Reflected text only",
            "evidence": "plain reflection",
        })
        # Proven SQLi candidate with checkable DBMS banner -> promoted to confirmed_findings!
        engine._emit_candidate_finding({
            "vuln_class": "sqli",
            "target": "https://authorized.example/items?id=1'",
            "title": "SQLi with Postgres banner",
            "evidence": "PostgreSQL 15.3 on x86_64",
            "proof_payload": {
                "artifact_type": "sqli",
                "response_text": "PostgreSQL 15.3 on x86_64",
                "baseline_text": "normal item page",
            },
            "verifier_result": {"reproduced": True, "status_code": 500},
        })
        assert len(engine.confirmed_findings) == 0  # Nothing confirmed before adjudication!

        engine._run_adjudication_phase()
        assert len(engine.confirmed_findings) == 1
        assert engine.confirmed_findings[0]["vuln_class"] == "sqli"
        assert engine.confirmed_findings[0]["verdict"] == "CONFIRMED"
        assert engine.confirmed_findings[0]["proof_strength"] == "DERIVED"
        assert len(engine.candidate_findings) == 1
        assert engine.candidate_findings[0]["verdict"] != "CONFIRMED"

    @pytest.mark.asyncio
    async def test_live_scanner_routes_findings_through_evidence_court(self, loopback_server):
        from core.live_scanner import run_live_security_scan

        res = await run_live_security_scan(
            target=f"{loopback_server}/live_scan_root",
            run_id="run_truth_1",
            mode="full",
        )
        findings_by_class = {f["vuln_class"]: f for f in res["findings"]}

        # Passive missing headers MUST NEVER be CONFIRMED
        assert "http-missing-security-headers" in findings_by_class
        assert findings_by_class["http-missing-security-headers"]["status"] != "CONFIRMED"

        # Inert reflected XSS marker without DOM execution telemetry MUST NEVER be CONFIRMED
        if "reflected-xss" in findings_by_class:
            assert findings_by_class["reflected-xss"]["status"] != "CONFIRMED"

        # Real .env secret exposure & CORS ACAC reflection have DERIVED proof via EvidenceCourt
        assert "exposed-dotenv-file" in findings_by_class
        assert findings_by_class["exposed-dotenv-file"]["status"] == "CONFIRMED"
        assert findings_by_class["exposed-dotenv-file"]["proof_strength"] == "DERIVED"

        assert "cors-arbitrary-origin-reflection" in findings_by_class
        assert findings_by_class["cors-arbitrary-origin-reflection"]["status"] == "CONFIRMED"
        assert findings_by_class["cors-arbitrary-origin-reflection"]["proof_strength"] == "DERIVED"


# ── 7. Real Differential HTTP Replay (ReplayLab, ReplayBundle, Verifier) ─────

class TestTruthfulDifferentialReplay:
    def test_replay_lab_parameterized_json_and_real_loopback_replay(self, tmp_path, loopback_server):
        from core.replay_lab.replay_lab import ReplayLab

        lab = ReplayLab(base_dir=tmp_path)
        tricky_payload = '"; import os; os.system("echo pwn") # \n53+19'
        bundle_vuln = lab.freeze_finding(
            finding_id="VULN-CMD-1",
            target_url=f"{loopback_server}/vuln/cmd?expr=53%2B19",
            baseline_url=f"{loopback_server}/vuln/cmd?expr=baseline",
            method="GET",
            parameter="expr",
            payload=tricky_payload,
            vuln_class="cmdi",
            probed_expression="53+19",
            expected_result="72",
            raw_request="GET /vuln/cmd?expr=53%2B19 HTTP/1.1",
            raw_response="HTTP/1.1 200 OK\r\n\r\ncalc output: 72",
            raw_baseline="HTTP/1.1 200 OK\r\n\r\ncalc output: ok",
        )
        assert (bundle_vuln / "replay_spec.json").exists()
        replay_src = (bundle_vuln / "replay.py").read_text(encoding="utf-8")
        # Must compile cleanly as valid Python despite quotes/newlines in payload (no raw interpolation!)
        compile(replay_src, str(bundle_vuln / "replay.py"), "exec")
        assert 'print("CONFIRMED: Payload reflected' not in replay_src

        # Real loopback replay against vulnerable endpoint -> CONFIRMED, zero drift
        res_vuln = lab.replay_against_target("VULN-CMD-1")
        assert res_vuln.is_reproducible is True
        assert res_vuln.canonical_verdict == "CONFIRMED"
        assert res_vuln.evidence_drift_detected is False

        # Real loopback replay against safe/reflection-only endpoint -> REJECTED, drift detected!
        lab.freeze_finding(
            finding_id="SAFE-CMD-1",
            target_url=f"{loopback_server}/safe/cmd?expr=53%2B19",
            baseline_url=f"{loopback_server}/safe/cmd?expr=baseline",
            method="GET",
            parameter="expr",
            payload="53+19",
            vuln_class="cmdi",
            probed_expression="53+19",
            expected_result="72",
            raw_request="GET /safe/cmd?expr=53%2B19 HTTP/1.1",
            raw_response="HTTP/1.1 200 OK\r\n\r\ncalc output: 72",
            raw_baseline="HTTP/1.1 200 OK\r\n\r\ncalc output: ok",
        )
        res_safe = lab.replay_against_target("SAFE-CMD-1")
        assert res_safe.is_reproducible is False
        assert res_safe.canonical_verdict == "REJECTED"
        assert res_safe.evidence_drift_detected is True

    def test_replay_bundle_factory_generates_executable_http_replay(self, tmp_path, loopback_server):
        from core.reproducibility.replay_bundle import ReplayBundleFactory

        bundle = ReplayBundleFactory.create_bundle(
            finding_id="RB-1",
            target=f"{loopback_server}/vuln/sqli?id=1'",
            vulnerability_type="sqli",
            request_raw=f"GET {loopback_server}/vuln/sqli?id=1' HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            response_raw="HTTP/1.1 500 Internal Server Error\r\n\r\nERROR: PostgreSQL 15.4 on x86_64-pc-linux-gnu near syntax",
            baseline_body="Item #1: Standard Product Page",
        )
        assert "# ... (Reproducible execution template)" not in bundle.replay_code_snippet
        bdir = bundle.to_bundle_dir(tmp_path)
        assert (bdir / "replay_spec.json").exists()

        # Dynamically load and execute the generated replay.py against our real loopback server!
        spec = importlib.util.spec_from_file_location("generated_replay", bdir / "replay.py")
        mod = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(mod)
        out = mod.replay_test()
        assert out["verdict"] == "CONFIRMED"
        assert out["reproduced"] is True
        assert out["sha_match"] is True

    def test_verifier_real_differential_replay_and_body_sha_fix(self, tmp_path, loopback_server):
        from hunter_ai.tools.poc_bundler import PocBundler
        from hunter_ai.tools.verifier import Verifier

        bundler = PocBundler(base_dir=str(tmp_path / "findings"))
        vuln_body = "ERROR: PostgreSQL 15.4 on x86_64-pc-linux-gnu near syntax"

        # 1. Vulnerable endpoint bundle -> PROVEN + saved_sha_match True + sha_match True!
        vuln_dir = bundler.capture(
            target="loopback_vuln",
            vuln_class="sqli",
            request={"method": "GET", "url": f"{loopback_server}/vuln/sqli?id=1'", "host": "127.0.0.1", "headers": {}, "body": ""},
            response={"status_code": 500, "reason": "Internal Server Error", "headers": {}, "body": vuln_body},
        )
        verifier = Verifier()
        v_vuln = verifier.check(vuln_dir)
        assert v_vuln["verdict"] == "PROVEN"
        assert v_vuln["canonical_verdict"] == "CONFIRMED"
        assert v_vuln["saved_sha_match"] is True
        assert v_vuln["sha_match"] is True

        # 2. Safe/patched endpoint bundle (even if original bundle had DBMS banner!) -> REFUTED on live replay!
        patched_dir = bundler.capture(
            target="loopback_safe",
            vuln_class="sqli",
            request={"method": "GET", "url": f"{loopback_server}/safe/sqli?id=1'", "host": "127.0.0.1", "headers": {}, "body": ""},
            response={"status_code": 500, "reason": "Internal Server Error", "headers": {}, "body": vuln_body},
        )
        v_safe = verifier.check(patched_dir)
        assert v_safe["verdict"] == "REFUTED"
        assert v_safe["canonical_verdict"] == "REJECTED"
        assert v_safe["saved_sha_match"] is True
        assert v_safe["sha_match"] is False

        # 3. Injectable hermetic transport error -> UNPROVEN / UNAVAILABLE
        def _offline_transport(_req):
            raise ConnectionRefusedError("target down")

        v_down = Verifier(transport=_offline_transport).check(vuln_dir)
        assert v_down["verdict"] == "UNPROVEN"
        assert v_down["canonical_verdict"] == "UNAVAILABLE"

        # 4. Unsafe method refused without confirm_unsafe=True
        unsafe_dir = bundler.capture(
            target="loopback_unsafe",
            vuln_class="idor",
            request={"method": "DELETE", "url": f"{loopback_server}/vuln/idor?id=2", "host": "127.0.0.1", "headers": {}, "body": ""},
            response={"status_code": 200, "reason": "OK", "headers": {}, "body": "VICTIM_CANARY_9944"},
            confirm_unsafe=True,
        )
        v_unsafe = Verifier(confirm_unsafe=False).check(unsafe_dir)
        assert v_unsafe["verdict"] == "UNPROVEN"
        assert v_unsafe["canonical_verdict"] == "UNAVAILABLE"
