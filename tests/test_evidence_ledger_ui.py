# -*- coding: utf-8 -*-
"""
اختبارات تبويب سجل الأدلة الموحد (Phase 7 — Evidence Ledger UI + API).
الـ endpoint لازم يرجع عدادات + runs + آخر سجلات لكل كيان، بأمان تام:
لا قيم هيدرز ولا أسرار تُرسل للـ frontend أبدًا (الأسماء فقط مسموحة).
"""
import json
import os
import threading

import pytest

from core.evidence_store import EvidenceStore


@pytest.fixture
def isolated_store_root(tmp_path, monkeypatch):
    """توجيه الـ EvidenceStore الافتراضي (الذي يبنيه الـ endpoint) إلى مجلد مؤقت."""
    ev_dir = tmp_path / "evidence_store"
    os.makedirs(str(ev_dir), exist_ok=True)
    real_cls = EvidenceStore

    def patched_init(self, root_dir=None):
        self.root_dir = str(ev_dir)
        os.makedirs(self.root_dir, exist_ok=True)
        self._lock = threading.RLock()
        self._handles = {}

    monkeypatch.setattr(real_cls, "__init__", patched_init)
    yield ev_dir


@pytest.fixture
def client(isolated_store_root):
    from fastapi.testclient import TestClient
    from ui.web.app import app
    return TestClient(app)


class TestLedgerEndpoint:
    def test_empty_store_returns_zero_counts(self, client):
        r = client.get("/api/evidence/ledger")
        assert r.status_code == 200
        d = r.json()
        assert set(d) == {"counts", "runs", "recent"}
        assert all(isinstance(v, int) and v >= 0 for v in d["counts"].values())
        assert d["runs"] == []
        # الكيانات الموحدة الأربعة موجودة في العدادات والـ recent
        for e in ("tool_execution", "reasoning", "network_txn", "court_verdict"):
            assert e in d["counts"]
            assert e in d["recent"]

    def test_network_txn_safe_fields_and_no_secret_values(
            self, client, isolated_store_root):
        store = EvidenceStore(root_dir=str(isolated_store_root))
        store.record_network_transaction(
            run_id="run-netx", source="browser",
            method="GET", url="https://api.x.test/api/users",
            host="api.x.test", path="/api/users", status_code=200,
            headers={"Authorization": "Bearer TOPSECRET"},
        )
        d = client.get("/api/evidence/ledger").json()
        rows = d["recent"]["network_txn"]
        assert len(rows) == 1
        row = rows[0]
        assert row["host"] == "api.x.test" and row["status_code"] == 200
        assert row["header_names"] == ["Authorization"]
        assert set(row) <= {"txn_id", "run_id", "source", "method", "host",
                            "path", "status_code", "is_api", "header_names",
                            "request_digest", "captured_at"}
        blob = json.dumps(d)
        assert "TOPSECRET" not in blob, "قيمة الهيدر السرية ما تطلعش في الـ API أبدًا"
        assert "Authorization" in blob, "اسم الهيدر مسموح (بلا قيمة)"

    def test_reasoning_and_court_visible(self, client, isolated_store_root):
        store = EvidenceStore(root_dir=str(isolated_store_root))
        from core.evidence_store import ReasoningRecord
        store.record_reasoning(run_id="run-rs", kind="js_audit",
                               model="qwen2.5-coder", prompt_digest="ab" * 12,
                               output_excerpt="looks fine", latency_ms=12.5)
        d = client.get("/api/evidence/ledger").json()
        rs = d["recent"]["reasoning"]
        assert len(rs) == 1
        assert rs[0]["kind"] == "js_audit" and rs[0]["model"] == "qwen2.5-coder"
        assert rs[0]["prompt_digest"] == "ab" * 12

    def test_recent_capped_at_15_counts_complete(
            self, client, isolated_store_root):
        store = EvidenceStore(root_dir=str(isolated_store_root))
        for i in range(20):
            store.record_network_transaction(
                run_id="run-cap", source="browser", method="GET",
                url=f"https://x.test/p{i}", host="x.test", path=f"/p{i}",
            )
        d = client.get("/api/evidence/ledger").json()
        assert len(d["recent"]["network_txn"]) <= 15
        assert d["counts"]["network_txn"] == 20  # العداد كامل؛ recent = آخر مقطع فقط

    def test_runs_distinct_sorted_limited(self, client, isolated_store_root):
        store = EvidenceStore(root_dir=str(isolated_store_root))
        for rid in ("run-b", "run-a", "run-c", "run-b"):
            store.record_network_transaction(
                run_id=rid, source="browser", method="GET",
                url="https://x.test/", host="x.test", path="/",
            )
        runs = client.get("/api/evidence/ledger").json()["runs"]
        assert runs == sorted(set(runs)) == ["run-a", "run-b", "run-c"]

    def test_store_failure_surfaces_as_json_500(self, client, monkeypatch):
        def boom(self, entity):
            raise RuntimeError("disk dead")
        monkeypatch.setattr(EvidenceStore, "_read_all", boom)
        r = client.get("/api/evidence/ledger")
        assert r.status_code == 500
        assert "disk dead" in r.json()["error"]


class TestLedgerUIWiring:
    def test_html_elements_exist(self):
        from pathlib import Path
        html = Path("ui/web/templates/index.html").read_text(encoding="utf-8")
        assert "switchTab('ledger'" in html
        assert 'id="tab-ledger"' in html
        assert 'id="ledger-btn"' in html
        assert 'id="ledger-state-badge"' in html
        assert 'id="ledger-summary"' in html
        assert 'id="ledger-list"' in html

    def test_js_functions_exist(self):
        from pathlib import Path
        js = Path("ui/web/static/app.js").read_text(encoding="utf-8")
        assert "async function loadLedger(" in js
        assert "function _renderLedger(" in js
        assert "if(tab === 'ledger') loadLedger();" in js
