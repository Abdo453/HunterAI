"""
Unit Tests for Evidence-Driven Pentest System
============================================
Tests:
1. EvidenceCourt multi-agent adjudication gate
2. EvidenceCourt rejection of literal reflection
3. EvidenceCourt confirmation with verified arithmetic PoE
4. ProofOfExecutionEngine reflection vs execution checks
5. ResponseFingerprinter dynamic noise and DOM structural delta
6. ThirdPartyDependencyFirewall blocking GTM, Google Play, Cloudflare
7. RiskScheduler prioritizes API routes and deprioritizes UI sliders
8. TargetMemory persistent do_not_repeat suppression
9. AuthMatrix guest vs user BOLA evaluation
10. EvidenceLedger cryptographic lineage chaining
11. ReplayEngine reproducible test bundling
"""
import pytest
from pathlib import Path
from core.evidence_court import EvidenceCourt, CourtVerdict
from core.poe_engine import ProofOfExecutionEngine
from core.response_fingerprinter import ResponseFingerprinter
from core.attack_surface_graph import AttackSurfaceGraph, ThirdPartyDependencyFirewall
from core.risk_scheduler import RiskScheduler
from core.target_memory import TargetMemory
from core.auth_matrix import AuthMatrix, SecurityState
from core.evidence_ledger import EvidenceLedger
from core.replay_engine import ReplayBundle


class TestEvidenceDrivenSystem:

    def test_evidence_court_multi_agent_requires_verifier(self):
        judgment = EvidenceCourt.adjudicate(
            target_url="https://target.com/page",
            parameter="cmd",
            vuln_class="cmd_injection",
            finder_claim={"is_real_vuln": True, "claim": "Critical RCE"},
            verifier_result=None,
            is_in_scope=True
        )
        assert judgment.verdict == CourtVerdict.INCONCLUSIVE
        assert judgment.reportable is False

    def test_evidence_court_rejects_reflection(self):
        judgment = EvidenceCourt.adjudicate(
            target_url="https://target.com/page",
            parameter="modal",
            vuln_class="cmd_injection",
            finder_claim={"is_real_vuln": True},
            verifier_result={
                "reproduced": False,
                "is_reflection": True,
                "proof_detail": "Literal reflection detected in DOM script tag"
            },
            is_in_scope=True
        )
        assert judgment.verdict == CourtVerdict.FALSE_POSITIVE
        assert judgment.reportable is False
        assert "Reflection != Execution" in judgment.adjudication_rationale

    def test_evidence_court_confirms_with_arithmetic_proof(self):
        judgment = EvidenceCourt.adjudicate(
            target_url="https://target.com/page",
            parameter="ip",
            vuln_class="cmd_injection",
            finder_claim={"is_real_vuln": True},
            verifier_result={
                "reproduced": True,
                "arithmetic_proof_confirmed": True,
                "confidence": 0.98,
                "proof_detail": "Evaluated 53+19 to 72"
            },
            is_in_scope=True
        )
        assert judgment.verdict == CourtVerdict.CONFIRMED
        assert judgment.reportable is True
        assert judgment.calibrated_severity == "Critical"

    def test_evidence_court_blocks_out_of_scope(self):
        judgment = EvidenceCourt.adjudicate(
            target_url="https://www.googletagmanager.com/gtm.js?id=GTM-123",
            parameter="id",
            vuln_class="xss",
            finder_claim={"is_real_vuln": True},
            verifier_result={"reproduced": True},
            is_in_scope=False
        )
        assert judgment.verdict == CourtVerdict.OUT_OF_SCOPE
        assert judgment.reportable is False

    def test_poe_engine_detects_reflection_vs_execution(self):
        resp_reflected = '<html><script>var x = "$((53+19))";</script></html>'
        ok, reason = ProofOfExecutionEngine.verify_command_injection(resp_reflected, "72", "53+19")
        assert ok is False
        assert "Reflection != Execution" in reason

        resp_executed = '<html><body>System check status: 72 processed.</body></html>'
        ok, reason = ProofOfExecutionEngine.verify_command_injection(resp_executed, "72", "53+19")
        assert ok is True
        assert "Arithmetic execution confirmed" in reason

    def test_poe_engine_sqli_dbms_extraction(self):
        pg_resp = "PostgreSQL 14.2 on x86_64-pc-linux-gnu, compiled by gcc"
        ok, dbms, proof = ProofOfExecutionEngine.verify_sqli_extraction(pg_resp)
        assert ok is True
        assert dbms == "postgresql"
        assert "PostgreSQL 14.2" in proof

    def test_response_fingerprinter_detects_meaningful_deviation_vs_noise(self):
        fp1 = ResponseFingerprinter.fingerprint(200, "<html><body>Hello Page</body></html>")
        fp2 = ResponseFingerprinter.fingerprint(200, "<html><body>Hello Page</body></html>")
        is_dev, reason = ResponseFingerprinter.is_meaningful_deviation(fp1, fp2)
        assert is_dev is False

        fp3 = ResponseFingerprinter.fingerprint(500, "<html><body>Internal Server Error</body></html>")
        is_dev, reason = ResponseFingerprinter.is_meaningful_deviation(fp1, fp3)
        assert is_dev is True
        assert "500" in reason

    def test_third_party_firewall_blocks_gtm_and_external(self):
        base_target = "bancoplata.mx"
        assert ThirdPartyDependencyFirewall.is_external_dependency("https://bancoplata.mx/api", base_target) is False
        assert ThirdPartyDependencyFirewall.is_external_dependency("https://sub.bancoplata.mx/login", base_target) is False

        assert ThirdPartyDependencyFirewall.is_external_dependency("https://www.googletagmanager.com/gtm.js", base_target) is True
        assert ThirdPartyDependencyFirewall.is_external_dependency("https://play.google.com/store/apps", base_target) is True
        assert ThirdPartyDependencyFirewall.is_external_dependency("https://cloudflare.com", base_target) is True

    def test_risk_scheduler_priority_scoring(self):
        score_api = RiskScheduler.calculate_priority("https://target.com/api/v1/user", "user_id", "idor")
        assert score_api >= 0.80

        score_ui = RiskScheduler.calculate_priority("https://target.com/security", "slide", "cmd_injection")
        assert score_ui <= 0.20
        assert RiskScheduler.should_execute_skill(score_ui) is False

    def test_target_memory_do_not_repeat(self, tmp_path):
        mem = TargetMemory("target_test.com", base_dir=str(tmp_path))
        assert mem.should_skip_param("slide", "cmd_injection") is False

        mem.record_benign_param("slide", "cmd_injection", reason="benign_slider")
        assert mem.should_skip_param("slide", "cmd_injection") is True

    def test_auth_matrix_bola_evaluation(self):
        ok, reason = AuthMatrix.evaluate_bola(SecurityState.STATE_0_GUEST, SecurityState.STATE_0_GUEST, 200, False)
        assert ok is False

        ok, reason = AuthMatrix.evaluate_bola(SecurityState.STATE_2_ADMIN, SecurityState.STATE_1_USER, 200, True)
        assert ok is True
        assert "BOLA confirmed" in reason

    def test_evidence_ledger_cryptographic_chaining(self):
        ledger = EvidenceLedger()
        e1 = ledger.record_step("observation", "Target reachable", {"status": 200})
        e2 = ledger.record_step("test", "Probed parameter", {"param": "id", "status": 500})

        assert len(ledger.entries) == 2
        assert e2.prev_entry_hash == e1.entry_hash
        assert len(e2.entry_hash) == 64

    def test_replay_bundle_serialization(self, tmp_path):
        bundle = ReplayBundle(
            finding_id="fnd_123",
            target_url="https://target.com/test",
            method="GET",
            param_name="ip",
            payload="127.0.0.1",
            raw_request="GET /test?ip=127.0.0.1 HTTP/1.1",
            raw_response="HTTP/1.1 200 OK",
            raw_baseline="HTTP/1.1 200 OK",
            evidence_data={"verified": True}
        )
        saved_dir = bundle.save_to_dir(str(tmp_path))
        saved_path = Path(saved_dir)
        assert (saved_path / "request.txt").exists()
        assert (saved_path / "response.txt").exists()
        assert (saved_path / "evidence.json").exists()