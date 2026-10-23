# -*- coding: utf-8 -*-
"""
اختبارات سجل الاستدلال الموحد (Phase 4 — Reasoning Ledger).
كل استدلال AI يوثق في EvidenceStore (RSN-) — الطلب digest بلا أسرار،
والمخرجات منقّاة، وفشل التسجيل لا يسقط الفحص. ربط بالـ orchestrator.
"""
import shutil
import tempfile

import pytest

from core.evidence_store import EvidenceStore
from hunter_ai.pipeline import pipeline_orchestrator as po_module
from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(root_dir=str(tmp_path))
    yield s
    shutil.rmtree(tmp_path, ignore_errors=True)


class TestReasoningRecords:
    def test_record_and_list_roundtrip(self, store):
        rec = store.record_reasoning(
            run_id="run-r1", kind="triage_recon_assets", model="xploiter/pentester",
            prompt_digest="d" * 64, output_excerpt="prioritize sub1.example.test",
            latency_ms=98.5,
        )
        assert rec.reasoning_id.startswith("RSN-")
        assert rec.decided_at > 0
        got = store.list_reasoning(run_id="run-r1")
        assert len(got) == 1
        assert got[0].kind == "triage_recon_assets"
        assert got[0].model == "xploiter/pentester"
        assert got[0].latency_ms == 98.5
        # فلترة بالنوع
        assert store.list_reasoning(kind="js_audit") == []

    def test_multiple_kinds_filterability(self, store):
        store.record_reasoning(run_id="r", kind="triage_recon_assets", model="m1",
                               prompt_digest="x", output_excerpt="out1")
        store.record_reasoning(run_id="r", kind="js_audit", model="m2",
                               prompt_digest="y", output_excerpt="out2")
        store.record_reasoning(run_id="r2", kind="js_audit", model="m2",
                               prompt_digest="z", output_excerpt="out3")
        assert len(store.list_reasoning(run_id="r")) == 2
        assert len(store.list_reasoning(kind="js_audit")) == 2
        assert len(store.list_reasoning()) == 3


class TestOrchestratorWiring:
    def _orchestrator(self, tmp_path, store):
        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, skip_ai_probe=True,
        )
        orch.master_tools.evidence_store = store
        orch.master_tools.run_id = orch.session_id
        return orch

    def test_record_reasoning_persists_through_orchestrator(self, tmp_path, store):
        orch = self._orchestrator(tmp_path, store)
        orch._record_reasoning(
            kind="triage_recon_assets", model="xploiter/pentester",
            prompt_frame="https://example.test|[sub1]|[]|[ep]",
            output={"analysis": "prioritize admin panels", "confidence": 0.8},
        )
        recs = store.list_reasoning(run_id=orch.session_id)
        assert len(recs) == 1
        assert recs[0].kind == "triage_recon_assets"
        # digest ثابت لنفس الإطار في نفس الدالة (متجانس)
        orch._record_reasoning(kind="triage_recon_assets", model="xploiter/pentester",
                               prompt_frame="https://example.test|[sub1]|[]|[ep]",
                               output={"analysis": "second call same frame"})
        recs = store.list_reasoning(run_id=orch.session_id)
        assert recs[0].prompt_digest == recs[1].prompt_digest
        assert len(recs) == 2

    def test_secrets_never_hit_label_raw(self, tmp_path, store):
        """سر في مخرجات العقل لا يدخل السجل كنص صريح."""
        orch = self._orchestrator(tmp_path, store)
        orch._record_reasoning(
            kind="js_audit", model="qwen2.5-coder",
            prompt_frame="js.example.test/bundle.js",
            output={"finding": "leaked key sk-abcdef123456 in bundle"},
        )
        recs = store.list_reasoning(run_id=orch.session_id)
        assert recs and "sk-abcdef123456" not in recs[0].output_excerpt
        assert "***" in recs[0].output_excerpt

    def test_broken_store_never_breaks_scan(self, tmp_path, store, monkeypatch):
        def boom(*a, **kw):
            raise RuntimeError("ledger exploded")

        monkeypatch.setattr(store, "record_reasoning", boom)
        orch = self._orchestrator(tmp_path, store)
        # لا يُرفع استثناء — telemetry فقط
        orch._record_reasoning(kind="strategy", model="m", prompt_frame="f",
                               output="out")

    def test_missing_store_is_a_noop(self, tmp_path):
        """orchestrator بدون store — السجل يجارب السلاسة يكمل."""
        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, skip_ai_probe=True,
        )
        orch.master_tools.evidence_store = None
        # لا يجب أن يرفع
        orch._record_reasoning(kind="strategy", model="m", prompt_frame="f",
                               output="out")
