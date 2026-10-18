# -*- coding: utf-8 -*-
"""
اختبارات جلسة المحكمة النهائية (Phase 3 — Final Evidence Court).
قواعد R1..R6 + الشبكة الموحدة لأحكام الـ EvidenceStore + الإسقاط في الـ pipeline.
كله offline — لا شبكة ولا هدف.
"""
import json
import pytest

from hunter_ai.pipeline.final_court import FinalEvidenceCourt
from hunter_ai.pipeline.schemas import (
    HunterFinding,
    FindingStatus,
    VerificationEvidence,
    ReproductionArtifact,
)
from core.evidence_store import EvidenceStore


def _confirmed_finding(**overrides):
    base = dict(
        finding="SQL Injection in /search",
        asset="example.test",
        endpoint="https://example.test/search",
        vuln_type="SQLi",
        status=FindingStatus.CONFIRMED,
        evidence=[VerificationEvidence(description="differential alert",
                                        proof_snippet="alert(1)", verified=True)],
        reproduction=ReproductionArtifact(curl_command="curl /search?q=1'"),
    )
    base.update(overrides)
    return HunterFinding(**base)


class TestAuditOneRules:
    def test_clean_confirmed_finding_passes(self):
        f = _confirmed_finding()
        entry, reason = FinalEvidenceCourt.audit_one(f)
        assert reason is None
        assert entry.verdict == "PASSED"

    def test_r1_robots_txt_demoted(self):
        f = _confirmed_finding(endpoint="https://example.test/robots.txt",
                               finding="Open robots.txt file")
        entry, reason = FinalEvidenceCourt.audit_one(f)
        assert reason == "standard_web_behavior"
        assert entry.verdict == "DEMOTED"

    def test_r1_sitemap_demoted(self):
        f = _confirmed_finding(endpoint="https://example.test/sitemap.xml",
                               finding="Exposed sitemap")
        assert FinalEvidenceCourt.audit_one(f)[1] == "standard_web_behavior"

    def test_r1_open_ports_demoted(self):
        f = _confirmed_finding(vuln_type="open_ports", finding="Open ports 22,80")
        assert FinalEvidenceCourt.audit_one(f)[1] == "standard_web_behavior"

    def test_r2_confirmed_without_evidence_demoted(self):
        f = _confirmed_finding(evidence=[])
        entry, reason = FinalEvidenceCourt.audit_one(f)
        assert reason == "no_evidence"
        assert entry.verdict == "DEMOTED"

    def test_r3_unverified_evidence_demoted(self):
        f = _confirmed_finding(evidence=[
            VerificationEvidence(description="claimed", proof_snippet="x", verified=False),
        ])
        assert FinalEvidenceCourt.audit_one(f)[1] == "unverified_evidence"

    def test_r4_confirmed_without_reproduction_or_fp_checks_demoted(self):
        f = _confirmed_finding(reproduction=None)
        assert FinalEvidenceCourt.audit_one(f)[1] == "no_reproduction"
        # لكن مع false_positive_checks بدلاً منه = مقبول
        f2 = _confirmed_finding(reproduction=None,
                                false_positive_checks={"differentiator": "time-based check"})
        assert FinalEvidenceCourt.audit_one(f2)[1] is None

    def test_r5_incomplete_record_demoted(self):
        f = _confirmed_finding(finding="")
        entry, reason = FinalEvidenceCourt.audit_one(f)
        assert reason == "incomplete_record"
        assert entry.verdict == "DEMOTED"

    def test_r6_unverified_never_reaches_report(self):
        f = _confirmed_finding(status=FindingStatus.UNVERIFIED)
        entry, reason = FinalEvidenceCourt.audit_one(f)
        assert reason == "unreported_unverified"
        assert entry.verdict == "DEMOTED"

    def test_false_positive_never_reaches_report(self):
        f = _confirmed_finding(status=FindingStatus.FALSE_POSITIVE)
        assert FinalEvidenceCourt.audit_one(f)[1] == "unreported_unverified"


class TestAuditDocket:
    def test_docket_separates_and_counts(self):
        findings = [
            _confirmed_finding(),                       # PASSED
            _confirmed_finding(endpoint="https://example.test/robots.txt"),  # R1
            _confirmed_finding(evidence=[]),            # R2
            _confirmed_finding(status=FindingStatus.UNVERIFIED),  # R6
        ]
        report = FinalEvidenceCourt(run_id="run_x").audit_docket(findings)
        assert report.stats == {"PASSED": 1, "DEMOTED": 3}
        assert len(report.accepted) == 1
        assert len(report.demoted) == 3
        reason_codes = {d["reason_code"] for d in report.demoted}
        assert reason_codes == {"standard_web_behavior", "no_evidence", "unreported_unverified"}

    def test_docket_works_with_plain_dicts(self):
        d = _confirmed_finding().model_dump()
        report = FinalEvidenceCourt().audit_docket([d])
        assert report.stats["PASSED"] == 1


class TestEvidenceStoreVerdicts:
    def test_record_and_list_roundtrip(self, tmp_path):
        store = EvidenceStore(root_dir=str(tmp_path))
        rec = store.record_court_verdict(
            run_id="run-1", finding_id="fid12", title="SQLi",
            endpoint="https://e.test/s", verdict="PASSED", reason_code="",
        )
        assert rec.court_id.startswith("CRT-")
        assert len(store.list_court_verdicts(run_id="run-1")) == 1
        assert len(store.list_court_verdicts(run_id="run-other")) == 0
        # legacy records without the new fields stay loadable (Phase-2 axiom)
        rec2 = store.record_court_verdict(
            run_id="run-1", finding_id="fid9", title="XSS",
            endpoint="https://e.test/c", verdict="DEMOTED", reason_code="no_evidence",
            rationale="no proof", session_id="sess-1",
        )
        got = store.list_court_verdicts(run_id="run-1")
        assert {r.verdict for r in got} == {"PASSED", "DEMOTED"}
        assert got[-1].rationale == "no proof"


class TestPipelineIntegration:
    @pytest.mark.asyncio
    async def test_final_court_inside_orchestrator(self, monkeypatch, tmp_path):
        """الجلسة داخل الـ pipeline: الإسقاط الفعلي + التدوين + الـ artifact."""
        from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator

        # EvidenceStore مزيف — بدون كتابة على القرص الحقيقي
        recorded = []

        class _FakeStore:
            def __init__(self, *a, **kw):
                pass

            def record_court_verdict(self, **kw):
                recorded.append(dict(kw))
                return dict(kw)

        monkeypatch.setattr("core.evidence_store.EvidenceStore", _FakeStore)

        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, skip_ai_probe=True,
        )
        orch.artifact_root = str(tmp_path)
        good = _confirmed_finding()
        bad = _confirmed_finding(evidence=[], finding="SQLi with no proof",
                                 endpoint="https://example.test/nope")
        orch.findings = [good, bad]

        session = orch._run_final_court()

        # الإسقاط الفعلي: نتيجة واحدة فقط وصلت للتقرير
        assert session["stats"] == {"PASSED": 1, "DEMOTED": 1}
        assert len(orch.findings) == 1
        assert orch.findings[0].evidence and orch.findings[0].status == FindingStatus.CONFIRMED
        # المنهوس راح للفرضيات المؤجلة مع كود السبب
        assert orch.deferred_hypotheses[-1]["reason_code"] == "no_evidence"
        # الجلسة كاملة موثقة في الـ artifact
        court_file = tmp_path / "13_evidence" / "court_session.json"
        session_data = json.loads(court_file.read_text(encoding="utf-8"))
        assert session_data["stats"]["DEMOTED"] == 1
        assert session_data["deferred_by_court"][0]["reason_code"] == "no_evidence"

    @pytest.mark.asyncio
    async def test_final_court_records_verdicts_in_store(self, monkeypatch, tmp_path):
        """كل حكم — حتى PASSED — يُسجل في EvidenceStore الموحد."""
        from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
        import core.evidence_store as es_mod

        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, skip_ai_probe=True,
        )
        orch.artifact_root = str(tmp_path)
        orch.session_id = "sess_court_check"
        orch.findings = [_confirmed_finding()]
        # EvidenceStore حقيقي لكن معزول في مجلد مؤقت
        _RealStore = es_mod.EvidenceStore
        monkeypatch.setattr(
            es_mod, "EvidenceStore",
            lambda *a, **kw: _RealStore(root_dir=str(tmp_path)),
        )

        orch._run_final_court()

        store = EvidenceStore(root_dir=str(tmp_path))
        verdicts = store.list_court_verdicts(run_id="sess_court_check")
        assert len(verdicts) == 1
        assert verdicts[0].verdict == "PASSED"
        assert verdicts[0].session_id == "sess_court_check"
