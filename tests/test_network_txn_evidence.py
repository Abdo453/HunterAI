# -*- coding: utf-8 -*-
"""
اختبارات الترافيك المعترض الموحد (Phase 5 — Network Transaction Evidence).
ingest_request/ingest_response في TrafficBridge يكتبان NET- سجلاً في EvidenceStore
(بلا قيم هيدرز) ، وفشل التسجيل لا يعطّل الاستيذاء، ووصل الـ orchestrator.
"""
import shutil

import pytest

from core.browser.traffic_bridge import TrafficBridge
from core.evidence_store import EvidenceStore


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(root_dir=str(tmp_path))
    yield s
    shutil.rmtree(tmp_path, ignore_errors=True)


def _bridge(store, run_id="run-net"):
    return TrafficBridge(
        db_path=":memory:",
        evidence_graph=None,
        evidence_store=store,
        run_id=run_id,
    )


class TestIngestRequestEvidence:
    def test_request_writes_full_unified_record(self, store, tmp_path):
        b = _bridge(store, run_id="run-req")
        b.db_path = str(tmp_path / "traffic.db")  # SQLite حقيقي معزول
        b.ingest_request({
            "url": "https://api.example.test/api/users?id=1",
            "method": "post", "resource_type": "xhr",
            "headers": {"Authorization": "Bearer eyJSECRET", "Origin": "https://app.test"},
        })
        txns = store.list_network_transactions(run_id="run-req")
        assert len(txns) == 1
        t = txns[0]
        assert t.txn_id.startswith("NET-")
        assert t.source == "browser"
        assert t.method == "POST"
        assert t.host == "api.example.test"
        assert t.path == "/api/users"
        assert t.is_api is True
        assert t.status_code == 0
        # أسماء الهيدرز موجودة — القيم أبدًا لا
        assert "Authorization" in t.header_names
        assert "Origin" in t.header_names
        assert "eyJSECRET" not in t.header_names

    def test_response_writes_status_and_api_flag(self, store, tmp_path):
        b = _bridge(store, run_id="run-res")
        b.db_path = str(tmp_path / "traffic.db")
        b.ingest_response({
            "url": "https://example.test/static/app.js",
            "status": 200, "resource_type": "script",
            "method": "GET", "headers": {"Server": "cloudflare"},
        })
        t = store.list_network_transactions(run_id="run-res")[0]
        assert t.status_code == 200
        assert t.is_api is False
        assert t.header_names == ["Server"]

    def test_same_request_yields_stable_digest(self, store, tmp_path):
        b = _bridge(store, run_id="run-dig")
        b.db_path = str(tmp_path / "traffic.db")
        payload = {"url": "https://example.test/x", "method": "GET", "headers": {}}
        b.ingest_request(dict(payload))
        b.ingest_request(dict(payload))
        txns = store.list_network_transactions(run_id="run-dig")
        assert len(txns) == 2
        assert txns[0].request_digest == txns[1].request_digest

    def test_missing_store_never_breaks_ingestion(self, tmp_path):
        b = TrafficBridge(db_path=str(tmp_path / "traffic.db"),
                          evidence_graph=None, evidence_store=None)
        b.ingest_request({"url": "https://example.test/", "method": "GET", "headers": {}})
        # مفيش crash — الصمت مقبول هنا لأن الـ SQLite نفسه شغّال

    def test_broken_store_never_breaks_ingestion(self, store, tmp_path, monkeypatch):
        def boom(*a, **kw):
            raise RuntimeError("ledger exploded")

        monkeypatch.setattr(store, "record_network_transaction", boom)
        b = _bridge(store, run_id="run-boom")
        b.db_path = str(tmp_path / "traffic.db")
        # لا يُرفع
        b.ingest_request({"url": "https://example.test/", "method": "GET", "headers": {}})

    def test_source_passthrough_burp(self, store, tmp_path):
        """المصدر يمر كما هو — Burp proxy ما يختلطش مع المتصفح في القائمة."""
        b = _bridge(store, run_id="run-src")
        b.db_path = str(tmp_path / "traffic.db")
        b.ingest_request({"url": "https://example.test/a", "method": "GET",
                          "headers": {}, "source": "burp_proxy"})
        b.ingest_request({"url": "https://example.test/b", "method": "GET",
                          "headers": {}, "source": "browser"})
        burp = store.list_network_transactions(source="burp_proxy")
        browser = store.list_network_transactions(source="browser")
        assert len(burp) == 1 and len(browser) == 1


class TestOrchestratorWiring:
    def test_orchestrator_wires_bridge_to_same_store(self, tmp_path):
        from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator

        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, skip_ai_probe=True,
        )
        assert orch.traffic_bridge.evidence_store is orch.master_tools.evidence_store
        assert orch.traffic_bridge.run_id == orch.session_id
        assert orch.traffic_bridge.evidence_store is not None

    def test_orchestrator_bridge_records_on_ingest(self, tmp_path):
        """الوصل الحقيقي: ingest عبر الـ orchestrator bridge يترك سجلًا NET-."""
        from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
        from hunter_ai.pipeline import pipeline_orchestrator as po

        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, skip_ai_probe=True,
        )
        # عزل الوجهة الحقيقية — حوّل root الـ Store الحقيقي إلى مجلد مؤقت موجود
        import os as _os
        ev_dir = tmp_path / "evstore"
        _os.makedirs(str(ev_dir), exist_ok=True)
        real_store = orch.master_tools.evidence_store
        real_store.root_dir = str(ev_dir)

        orch.traffic_bridge.db_path = str(tmp_path / "traffic.db")
        orch.traffic_bridge.ingest_request({
            "url": "https://api.example.test/api/orders",
            "method": "GET", "headers": {"X-Test": "1"},
        })
        txns = real_store.list_network_transactions(run_id=orch.session_id)
        assert len(txns) == 1
        assert txns[0].path == "/api/orders"
        assert txns[0].source == "browser"
