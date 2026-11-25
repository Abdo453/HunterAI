"""Tests for FIX 4: CaptureStore default persistence and previous session reload."""
from __future__ import annotations

import inspect
import json
import shutil
import tempfile
from pathlib import Path

from core.burp_gateway.capture_store import CaptureStore, CapturedTransaction


def test_default_base_dir_is_persistent_default(tmp_path, monkeypatch):
    sig = inspect.signature(CaptureStore.__init__)
    assert sig.parameters["base_dir"].default == "data/engagements/default"

    # Run inside tmp_path so workspace data/engagements/default is never polluted.
    monkeypatch.chdir(tmp_path)

    store1 = CaptureStore("app.example.com")
    assert store1._session_only is False
    assert store1.base_dir == Path("data/engagements/default")
    assert store1.root_dir == Path("data/engagements/default") / "app_example_com"

    for subdir in ("requests", "responses", "evidence", "findings", "cases"):
        assert (store1.root_dir / subdir).is_dir()

    store1.record_finding({
        "id": "fnd_default_01",
        "title": "Reflected XSS in search",
        "severity": "High",
    })

    store2 = CaptureStore("app.example.com")
    assert len(store2.findings) == 1
    assert store2.findings[0]["id"] == "fnd_default_01"
    assert store2.findings[0]["title"] == "Reflected XSS in search"


def test_explicit_string_and_path_base_dir_created(tmp_path):
    str_base = str(tmp_path / "nested" / "str_engagements")
    store_str = CaptureStore("api.target.local", base_dir=str_base)
    assert store_str.base_dir == Path(str_base)
    assert store_str.root_dir == Path(str_base) / "api_target_local"
    for subdir in ("requests", "responses", "evidence", "findings", "cases"):
        assert (store_str.root_dir / subdir).is_dir()

    path_base = tmp_path / "nested" / "path_engagements"
    store_path = CaptureStore("api.target.local", base_dir=path_base)
    assert store_path.base_dir == path_base
    assert store_path.root_dir == path_base / "api_target_local"
    for subdir in ("requests", "responses", "evidence", "findings", "cases"):
        assert (store_path.root_dir / subdir).is_dir()


def test_explicit_none_base_dir_handled_gracefully():
    store = CaptureStore("ephemeral.target", base_dir=None)
    try:
        assert store._session_only is True
        assert store.root_dir.is_dir()
        for subdir in ("requests", "responses", "evidence", "findings", "cases"):
            assert (store.root_dir / subdir).is_dir()
        assert Path(tempfile.gettempdir()).resolve() in store.base_dir.resolve().parents or (
            store.base_dir.resolve() == Path(tempfile.gettempdir()).resolve()
        )
    finally:
        shutil.rmtree(store.base_dir, ignore_errors=True)


def test_persistence_across_two_instances(tmp_path):
    store1 = CaptureStore("portal.target.local", base_dir=tmp_path)

    tx1 = CapturedTransaction(
        tx_id="tx_persist_01",
        target_host="portal.target.local",
        method="POST",
        url="https://portal.target.local/api/login?next=/home",
        status_code=200,
        req_headers={
            "Authorization": "Bearer secret_token_123456",
            "Content-Type": "application/json",
        },
        req_body='{"username": "alice"}',
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"ok": true}',
        tool_source="proxy",
        timestamp=1000.0,
        trace_id="TRACE-FIX4-01",
        browser_action_id="BA-FIX4-01",
    )
    tx2 = CapturedTransaction(
        tx_id="tx_persist_02",
        parent_request="tx_persist_01",
        target_host="portal.target.local",
        method="GET",
        url="https://portal.target.local/api/orders/99?expand=items",
        status_code=200,
        req_headers={"Authorization": "Bearer secret_token_123456"},
        resp_headers={"Content-Type": "application/json"},
        resp_body='{"order_id": 99}',
        tool_source="repeater",
        timestamp=1001.0,
        trace_id="TRACE-FIX4-01",
        browser_action_id="BA-FIX4-02",
    )
    store1.store_transaction(tx1)
    store1.store_transaction(tx2)

    store1.add_hypothesis(
        vuln_type="IDOR",
        endpoint="/api/orders/99",
        rationale="Order ID predictable in path",
        required_evidence=["Cross-account replay"],
    )
    store1.record_finding({
        "id": "fnd_explicit_01",
        "title": "IDOR on /api/orders/99",
        "severity": "High",
        "lifecycle_verdict": "CONFIRMED",
    })
    store1.record_finding({
        "title": "Sensitive token disclosure",
        "severity": "Medium",
        "lifecycle_verdict": "CONFIRMED",
    })
    assert len(store1.findings) == 2

    # Separate instance pointing to the exact same directory
    store2 = CaptureStore("portal.target.local", base_dir=tmp_path)

    assert len(store2.findings) == 2
    titles = {f["title"] for f in store2.findings}
    assert titles == {"IDOR on /api/orders/99", "Sensitive token disclosure"}

    assert [t.tx_id for t in store2.list_transactions()] == ["tx_persist_01", "tx_persist_02"]
    loaded_tx2 = store2.get_transaction("tx_persist_02")
    assert loaded_tx2 is not None
    assert loaded_tx2.parent_request == "tx_persist_01"
    assert loaded_tx2.resp_body == '{"order_id": 99}'

    lineage = store2.get_request_lineage("tx_persist_02")
    assert [step["tx_id"] for step in lineage] == ["tx_persist_01", "tx_persist_02"]

    assert [t.tx_id for t in store2.get_by_trace_id("TRACE-FIX4-01")] == [
        "tx_persist_01",
        "tx_persist_02",
    ]
    assert [t.tx_id for t in store2.get_by_browser_action_id("BA-FIX4-02")] == ["tx_persist_02"]

    assert "https://portal.target.local/api/login" in store2.endpoints
    assert "https://portal.target.local/api/orders/99" in store2.endpoints
    assert {"next", "username", "expand"}.issubset(store2.parameters)
    assert len(store2.identities) == 1
    assert len(store2.hypotheses) == 1
    assert len(store2.timeline) == len(store1.timeline)

    summary = store2.get_summary()
    assert summary["findings_count"] == 2
    assert summary["total_transactions"] == 2
    assert summary["hypotheses_count"] == 1
    assert summary["identities_count"] == 1


def test_load_previous_session_is_idempotent_no_duplicates(tmp_path):
    store1 = CaptureStore("dup.target.local", base_dir=tmp_path)
    tx = CapturedTransaction(
        tx_id="tx_dup_01",
        target_host="dup.target.local",
        method="GET",
        url="https://dup.target.local/api/me",
        trace_id="TRACE-DUP",
        browser_action_id="BA-DUP",
    )
    store1.store_transaction(tx)
    store1.add_hypothesis("XSS", "/api/me", "Test", ["PoC"])
    store1.record_finding({"id": "fnd_dup_01", "title": "Stored XSS", "severity": "High"})

    store2 = CaptureStore("dup.target.local", base_dir=tmp_path)
    initial_timeline_len = len(store2.timeline)
    store2.load_previous_session()
    store2.load_previous_session()

    assert len(store2.findings) == 1
    assert len(store2.hypotheses) == 1
    assert len(store2.list_transactions()) == 1
    assert len(store2.timeline) == initial_timeline_len
    assert [t.tx_id for t in store2.get_by_trace_id("TRACE-DUP")] == ["tx_dup_01"]
    assert [t.tx_id for t in store2.get_by_browser_action_id("BA-DUP")] == ["tx_dup_01"]


def test_load_previous_session_ignores_corrupt_json(tmp_path):
    store1 = CaptureStore("corrupt.target.local", base_dir=tmp_path)
    store1.record_finding({"id": "fnd_valid_01", "title": "Valid Finding", "severity": "Low"})

    bad_finding = store1.root_dir / "findings" / "bad_corrupt.json"
    bad_finding.write_text("{not valid json", encoding="utf-8")
    (store1.root_dir / "endpoints.json").write_text("{bad", encoding="utf-8")

    store2 = CaptureStore("corrupt.target.local", base_dir=tmp_path)
    assert len(store2.findings) == 1
    assert store2.findings[0]["id"] == "fnd_valid_01"
    assert json.loads((store2.root_dir / "findings" / "fnd_valid_01.json").read_text(encoding="utf-8"))["title"] == "Valid Finding"
