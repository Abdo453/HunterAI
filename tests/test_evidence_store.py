"""
اختبارات متجر الأدلة الدائم (core/evidence_store.py) — Phase D.
يختبر: إضافة الأدلة، استرجاعها، الفرضيات، الطرق المسدودة، تنفيذ الأدوات،
الأحداث، إخفاء الأسرار، عدم إمكانية تغيير السجلات (append-only).
لا يستهدف أي نظام خارجي.
"""
import os
import shutil
import tempfile
import pytest

from core.evidence_store import (
    EvidenceStore, EvidenceRecord, HypothesisRecord, DeadEndRecord,
    ToolExecutionRecord, EventRecord, _redact_secrets,
)


@pytest.fixture
def store():
    root = tempfile.mkdtemp(prefix="evidence_store_test_")
    s = EvidenceStore(root_dir=root)
    yield s
    shutil.rmtree(root, ignore_errors=True)


class TestRedaction:
    def test_redacts_api_keys(self):
        out = _redact_secrets("token sk-abcdef123456 here")
        assert "sk-abcdef123456" not in out
        assert "***" in out

    def test_redacts_bearer(self):
        out = _redact_secrets("Authorization: Bearer eyJhbGci...")
        assert "eyJhbGci..." not in out
        assert "***" in out


class TestEvidence:
    def test_add_and_get_evidence(self, store):
        rec = store.add_evidence(
            run_id="run-1", source_worker="w-recon",
            source_tool="nmap.scan", evidence_type="observation",
            content="port 443 open on example.com",
            provenance="nmap", confidence=0.9)
        assert rec.evidence_id.startswith("EV-")
        got = store.get_evidence(rec.evidence_id)
        assert got is not None
        assert got.sanitized_content == "port 443 open on example.com"
        assert got.content_hash == rec.content_hash
        assert got.verification_status == "unverified"

    def test_list_evidence_by_run(self, store):
        store.add_evidence(run_id="run-1", source_worker="w1", source_tool="t",
                           evidence_type="observation", content="a")
        store.add_evidence(run_id="run-2", source_worker="w1", source_tool="t",
                           evidence_type="observation", content="b")
        r1 = store.list_evidence(run_id="run-1")
        assert len(r1) == 1
        assert r1[0].content == "a" if False else r1[0].sanitized_content == "a"

    def test_mark_evidence_verified(self, store):
        rec = store.add_evidence(run_id="r", source_worker="w", source_tool="t",
                                 evidence_type="observation", content="x")
        assert store.mark_evidence(rec.evidence_id, "verified")
        got = store.get_evidence(rec.evidence_id)
        # append-only: آخر إصدار يربح
        assert got.verification_status == "verified"

    def test_min_confidence_filter(self, store):
        store.add_evidence(run_id="r", source_worker="w", source_tool="t",
                           evidence_type="obs", content="low", confidence=0.2)
        store.add_evidence(run_id="r", source_worker="w", source_tool="t",
                           evidence_type="obs", content="high", confidence=0.9)
        hi = store.list_evidence(run_id="r", min_confidence=0.5)
        assert len(hi) == 1
        assert hi[0].sanitized_content == "high"


class TestHypothesis:
    def test_add_and_link(self, store):
        hyp = store.add_hypothesis(run_id="r", description="SQLi on /login")
        ev = store.add_evidence(run_id="r", source_worker="w", source_tool="t",
                                evidence_type="observation", content="param sensitive")
        assert store.link_hypothesis(hyp.hypothesis_id, ev.evidence_id,
                                     supporting=True)
        got = store.get_hypothesis(hyp.hypothesis_id)
        assert ev.evidence_id in got.supporting_evidence


class TestDeadEnd:
    def test_record_dead_end(self, store):
        de = store.record_dead_end(run_id="r", approach="brute force",
                                   reason="rate limited",
                                   supporting_evidence=["EV-00000001"])
        assert de.dead_end_id.startswith("DE-")
        assert de.reason == "rate limited"


class TestToolExecution:
    def test_tool_execution_lifecycle(self, store):
        te = store.record_tool_execution(
            run_id="r", worker_id="w", tool_id="nmap.scan",
            redacted_arguments={"target": "example.com", "ports": "443"},
            artifact_reference="art-123")
        assert store.finish_tool_execution(te.execution_id, "finished", 0)
        recs = store._read_all("tool_execution")
        last = [r for r in recs if r["execution_id"] == te.execution_id][-1]
        assert last["status"] == "finished"
        assert last["exit_code"] == 0


class TestEvents:
    def test_events_append_and_order(self, store):
        store.add_event(run_id="r", event_type="RUN_CREATED", payload={"g": "x"})
        store.add_event(run_id="r", event_type="TASK_ASSIGNED",
                        payload={"task": "t1"})
        events = store.get_events("r")
        assert len(events) == 2
        assert events[0].event_type == "RUN_CREATED"
        assert events[1].event_type == "TASK_ASSIGNED"
        # إعادة التشغيل (إعادة استرجاع) تعطي نفس الترتيب
        events2 = store.get_events("r")
        assert [e.event_id for e in events2] == [e.event_id for e in events]


class TestSnapshot:
    def test_snapshot_counts(self, store):
        store.add_evidence(run_id="r", source_worker="w", source_tool="t",
                           evidence_type="obs", content="x")
        s = store.snapshot()
        assert s["evidence"] >= 1

    def test_secret_not_stored_in_evidence(self, store):
        store.add_evidence(run_id="r", source_worker="w", source_tool="t",
                           evidence_type="obs",
                           content="key sk-abcdef123456 leak")
        rec = store.list_evidence(run_id="r")[0]
        assert "sk-abcdef123456" not in rec.sanitized_content
        assert "***" in rec.sanitized_content
