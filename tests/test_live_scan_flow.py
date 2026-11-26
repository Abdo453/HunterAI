"""End-to-end verification tests for Django Hub live scanner, /events 200 parity, and Overview results."""
from __future__ import annotations

import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

import core.global_state as gs
import core.platform_store as ps
import hunter_backend.apps.arsenal_api as arsenal_api
import hunter_backend.apps.operations_api as ops_api
import hunter_backend.runtime as rt
from core.evidence_store import EvidenceStore
from core.run_control import GLOBAL_RUN_CONTROLLER
from hunter_backend.testing import ASGISyncClient


class _LiveTargetHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        origin = self.headers.get("Origin")

        def send_resp(code: int, ctype: str, body: str, extra_headers=None) -> None:
            raw = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Server", "LiveLab/3.1.4")
            if origin:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        if parsed.path == "/":
            send_resp(
                200,
                "text/html",
                "<html><head><title>Vulnerable Lab</title></head>"
                "<body><a href='/search?q=hi'>Search</a><a href='/redirect?next=/home'>Go</a></body></html>",
            )
            return
        if parsed.path == "/.git/HEAD":
            send_resp(200, "text/plain", "ref: refs/heads/main\n")
            return
        if parsed.path == "/search":
            q = (qs.get("q") or [""])[0]
            send_resp(200, "text/html", f"<html><body>Result: {q}</body></html>")
            return
        if parsed.path == "/redirect":
            dest = (qs.get("next") or ["/home"])[0]
            self.send_response(302)
            self.send_header("Location", dest)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/home":
            send_resp(200, "text/html", f"<html><body>{html.escape('Home')}</body></html>")
            return
        send_resp(404, "application/json", json.dumps({"error": "Not found"}))


@pytest.fixture()
def live_target_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LiveTargetHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", port
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=3.0)


@pytest.fixture()
def isolated_scan_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "data"
    reports_dir = data_dir / "reports"
    ev_dir = data_dir / "evidence_store"
    db_file = tmp_path / "platform_state.sqlite3"
    for d in (data_dir, reports_dir, data_dir / "sessions", ev_dir):
        d.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("HUNTER_DATA_DIR", str(data_dir))
    monkeypatch.setenv("HUNTER_PLATFORM_DB_PATH", str(db_file))
    monkeypatch.setenv("HUNTER_PIPELINE_PHASE_DELAY_S", "0.02")
    monkeypatch.setattr(rt, "DATA_DIR", data_dir)
    monkeypatch.setattr(rt, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(ops_api, "DATA_DIR", data_dir)
    monkeypatch.setattr(ops_api, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(arsenal_api, "DATA_DIR", data_dir)

    ev_store = EvidenceStore(root_dir=str(ev_dir))
    monkeypatch.setattr(gs, "GLOBAL_EVIDENCE_STORE", ev_store)
    monkeypatch.setattr(ops_api, "GLOBAL_EVIDENCE_STORE", ev_store)

    prev_store = ps._GLOBAL_PLATFORM_STORE
    prev_wired = rt._WIRED
    prev_hook = GLOBAL_RUN_CONTROLLER.on_state_change
    prev_runs = dict(GLOBAL_RUN_CONTROLLER._runs)
    ps._GLOBAL_PLATFORM_STORE = None
    rt.EVENT_BUS._history.clear()
    rt._WIRED = False
    GLOBAL_RUN_CONTROLLER.on_state_change = None
    GLOBAL_RUN_CONTROLLER._runs.clear()

    with ASGISyncClient() as client:
        yield client, data_dir

    GLOBAL_RUN_CONTROLLER.stop_all()
    GLOBAL_RUN_CONTROLLER._runs.clear()
    GLOBAL_RUN_CONTROLLER._runs.update(prev_runs)
    GLOBAL_RUN_CONTROLLER.on_state_change = prev_hook
    rt._WIRED = prev_wired
    if ps._GLOBAL_PLATFORM_STORE is not None:
        ps._GLOBAL_PLATFORM_STORE.close()
    ps._GLOBAL_PLATFORM_STORE = prev_store
    rt.EVENT_BUS._history.clear()


def test_django_hub_live_scan_populates_assets_findings_events_and_overview(
    live_target_server, isolated_scan_client, monkeypatch
) -> None:
    target_url, _port = live_target_server
    client, data_dir = isolated_scan_client
    monkeypatch.setenv("HUNTER_ALLOW_LOCALHOST_SCOPE", "1")

    start_resp = client.post(
        "/api/platform/runs/start",
        json={"kind": "omni", "target": target_url, "mode": "full", "scope": ["127.0.0.1"]},
    )
    assert start_resp.status_code == 200, start_resp.text
    run_id = start_resp.json()["run_id"]

    # Wait until live scan finishes (must complete promptly against local lab)
    store = ps.get_platform_store()
    deadline = time.time() + 12.0
    final_run = None
    while time.time() < deadline:
        cur = store.get_run(run_id)
        if cur and cur.get("status") == "completed":
            final_run = cur
            break
        if cur and cur.get("status") == "failed":
            pytest.fail(f"Run failed unexpectedly: {cur}")
        time.sleep(0.08)

    assert final_run is not None, "Live scan did not complete within 12s"
    meta = final_run.get("meta") or {}
    assert meta.get("scan_stats", {}).get("live_endpoints", 0) >= 1
    assert len(meta.get("discovered_assets") or []) >= 2
    findings = meta.get("discovered_findings") or []
    vuln_classes = {f.get("vuln_class") for f in findings}
    assert "cors-arbitrary-origin-reflection" in vuln_classes
    assert "exposed-git-head" in vuln_classes
    assert "reflected-xss" in vuln_classes
    assert "open-redirect" in vuln_classes

    # /api/runs/<run_id>/events must return 200 with recorded events (never 404)
    ev_resp = client.get(f"/api/runs/{run_id}/events")
    assert ev_resp.status_code == 200, ev_resp.text
    assert ev_resp.json()["count"] >= 3

    # /api/runs/<run_id>/findings & /evidence must return populated detections
    fd_resp = client.get(f"/api/runs/{run_id}/findings")
    assert fd_resp.status_code == 200, fd_resp.text
    assert fd_resp.json()["findings_count"] >= 4

    evi_resp = client.get(f"/api/runs/{run_id}/evidence")
    assert evi_resp.status_code == 200, evi_resp.text
    assert evi_resp.json()["count"] >= 4

    # /api/platform/overview must aggregate Hub assets & findings cleanly
    ov_resp = client.get("/api/platform/overview")
    assert ov_resp.status_code == 200, ov_resp.text
    ov = ov_resp.json()
    assert ov["counts"]["assets"] >= 2
    assert ov["counts"]["findings"] >= 4
    assert len(ov["assets"]) >= 2
    assert len(ov["findings"]) >= 4

    # Session & report dossiers persisted for /findings Explorer
    assert (data_dir / "sessions" / f"{run_id}.json").is_file()
    assert any((data_dir / "reports").glob(f"{run_id}_f*.json"))
