"""Backend API & multi-bug workflow tests for all example pentest target presets."""
from __future__ import annotations

import html
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

import pytest

import agents.burp_agent.evidence.evidence_model as evidence_model
import core.copilot_service as cs
import core.global_state as gs
import core.platform_store as ps
import hunter_backend.apps.arsenal_api as arsenal_api
import hunter_backend.apps.operations_api as ops_api
import hunter_backend.runtime as rt
from agents.burp_agent.evidence.evidence_model import UnifiedEvidenceStore
from core.evidence_court import CourtVerdict, EvidenceCourt, ProofPayload
from core.evidence_store import EvidenceStore
from core.run_control import GLOBAL_RUN_CONTROLLER
from core.security_mode import web_governance_enforced
from core.session_manager import Finding, SessionManager
from core.seven_question_gate import SevenQuestionGate
from hunter_backend.testing import ASGISyncClient

EXAMPLE_TARGETS: List[Tuple[str, str]] = [
    ("http://testphp.vulnweb.com", "public"),
    ("http://testhtml5.vulnweb.com", "public"),
    ("https://juice-shop.herokuapp.com", "public"),
    ("https://demo.testfire.net", "public"),
    ("https://example.com", "public"),
    ("http://127.0.0.1:3001", "local_lab"),
    ("http://127.0.0.1:8080", "local_lab"),
    ("http://localhost:8081", "local_lab"),
]

NON_OVERRIDABLE_BLOCKED_TARGETS: Tuple[str, ...] = (
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "evil;id",
)


class _PracticeLabHandler(BaseHTTPRequestHandler):
    """Isolated HTTP practice lab simulating Acunetix testphp + OWASP Juice Shop bugs."""

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(
        self,
        code: int,
        content_type: str,
        body: str,
        extra_headers: Dict[str, str] | None = None,
    ) -> None:
        raw = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/":
            self._send(
                200,
                "text/html",
                (
                    "<html><body><h1>Acunetix & JuiceShop Practice Lab</h1>"
                    "<a href='/listproducts.php?cat=1'>Products</a>"
                    "<a href='/search.php?test=posters'>Search</a>"
                    "<a href='/api/users?id=1'>Users</a>"
                    "<a href='/redirect?to=/home'>Redirect</a>"
                    "</body></html>"
                ),
            )
            return

        if parsed.path == "/listproducts.php":
            cat = (qs.get("cat") or ["1"])[0]
            if "'" in cat or "union" in cat.lower() or "order by" in cat.lower():
                self._send(
                    500,
                    "text/html",
                    (
                        "<html><body><h1>Database Error</h1>"
                        "<p>You have an error in your SQL syntax; check the manual that "
                        "corresponds to your MySQL server version 8.0.36-community near "
                        "\"'1'\" at line 1. Leaked row: admin:pbkdf2_sha256_demo_hash_9911</p>"
                        "</body></html>"
                    ),
                )
                return
            self._send(
                200,
                "text/html",
                (
                    f"<html><body><h2>Category {html.escape(cat)}: Art Posters</h2>"
                    "<ul><li>Landscape Print - $25</li><li>Cityscape - $40</li></ul>"
                    "</body></html>"
                ),
            )
            return

        if parsed.path == "/search.php":
            q = (qs.get("test") or [""])[0]
            # Deliberate unescaped reflected XSS sink matching testphp.vulnweb.com/search.php
            self._send(
                200,
                "text/html",
                f"<html><body><h2>Search results for: {q}</h2><div id='results'>{q}</div></body></html>",
            )
            return

        if parsed.path == "/search-safe.php":
            q = (qs.get("test") or [""])[0]
            escaped = html.escape(q)
            self._send(
                200,
                "text/html",
                f"<html><body><h2>Search results for: {escaped}</h2><div id='safe'>{escaped}</div></body></html>",
            )
            return

        if parsed.path == "/api/users":
            user_id = (qs.get("id") or ["1"])[0]
            if user_id == "2":
                # Deliberate cross-tenant IDOR ignoring caller X-User header
                self._send(
                    200,
                    "application/json",
                    json.dumps(
                        {
                            "id": 2,
                            "username": "bob",
                            "email": "bob@juiceshop.local",
                            "role": "admin",
                            "api_token": "BOB_ADMIN_SECRET_TOKEN_777",
                            "permissions": ["users:read", "users:write", "billing:export", "audit:all"],
                        }
                    ),
                )
                return
            self._send(
                200,
                "application/json",
                json.dumps(
                    {
                        "id": 1,
                        "username": "alice",
                        "email": "alice@juiceshop.local",
                        "role": "customer",
                        "api_token": "ALICE_OWN_TOKEN_101",
                    }
                ),
            )
            return

        if parsed.path == "/redirect":
            dest = (qs.get("to") or ["/home"])[0]
            self.send_response(302)
            self.send_header("Location", dest)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self._send(404, "application/json", json.dumps({"error": "Not found"}))


@pytest.fixture()
def practice_lab_server():
    """Start an isolated local HTTP practice server on an ephemeral 127.0.0.1 port."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _PracticeLabHandler)
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
def isolated_example_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate all SQLite, evidence, report, session, and runtime data under tmp_path."""
    data_dir = tmp_path / "data"
    reports_dir = data_dir / "reports"
    snapshots_dir = data_dir / "snapshots"
    runs_dir = data_dir / "runs"
    tool_outputs_dir = data_dir / "tool_outputs"
    sessions_dir = data_dir / "sessions"
    ev_dir = data_dir / "evidence_store"
    unified_db = data_dir / "evidence" / "unified_evidence.sqlite3"
    att_dir = tmp_path / "copilot_attachments"
    db_file = tmp_path / "platform_state.sqlite3"

    for d in (
        data_dir,
        reports_dir,
        snapshots_dir,
        runs_dir,
        tool_outputs_dir,
        sessions_dir,
        ev_dir,
        unified_db.parent,
        att_dir,
    ):
        d.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("HUNTER_DATA_DIR", str(data_dir))
    monkeypatch.setenv("HUNTER_PLATFORM_DB_PATH", str(db_file))
    monkeypatch.setenv("HUNTER_COPILOT_ATTACHMENTS_DIR", str(att_dir))
    monkeypatch.setenv("HUNTER_PIPELINE_PHASE_DELAY_S", "0.02")
    monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)
    monkeypatch.delenv("HUNTER_ALLOW_LOCALHOST_SCOPE", raising=False)
    monkeypatch.delenv("HUNTER_ALLOW_PRIVATE_LAB_SCOPE", raising=False)

    # Isolate runtime and app file-system paths away from repository data/
    monkeypatch.setattr(rt, "DATA_DIR", data_dir)
    monkeypatch.setattr(rt, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(rt, "SNAPSHOTS_DIR", snapshots_dir)
    monkeypatch.setattr(rt, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(rt, "TARGETS_FILE", data_dir / "targets.json")
    monkeypatch.setattr(rt, "CONTROL_SETTINGS_FILE", data_dir / "control_settings.json")
    monkeypatch.setattr(rt, "CHECKLIST_STATE_FILE", data_dir / "checklist_state.json")
    monkeypatch.setattr(rt, "RADAR_STATE_FILE", data_dir / "radar" / "latest_state.json")

    monkeypatch.setattr(arsenal_api, "DATA_DIR", data_dir)
    monkeypatch.setattr(arsenal_api, "TARGETS_FILE", data_dir / "targets.json")
    monkeypatch.setattr(arsenal_api, "CONTROL_SETTINGS_FILE", data_dir / "control_settings.json")
    monkeypatch.setattr(arsenal_api, "CHECKLIST_STATE_FILE", data_dir / "checklist_state.json")
    monkeypatch.setattr(arsenal_api, "RADAR_STATE_FILE", data_dir / "radar" / "latest_state.json")
    monkeypatch.setattr(arsenal_api, "GRANT_PATH", data_dir / "root_controller" / "grant.json")

    monkeypatch.setattr(ops_api, "DATA_DIR", data_dir)
    monkeypatch.setattr(ops_api, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(ops_api, "SNAPSHOTS_DIR", snapshots_dir)
    monkeypatch.setattr(ops_api, "RUNS_DIR", runs_dir)
    monkeypatch.setattr(ops_api, "TOOL_OUTPUTS_DIR", tool_outputs_dir)

    monkeypatch.setattr(cs, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        cs,
        "detect_live_providers",
        lambda: {
            "cloud": [],
            "ollama_reachable": False,
            "ollama_host": "http://127.0.0.1:11434",
            "lm_studio_reachable": False,
            "lm_studio_host": "http://127.0.0.1:1234",
            "any_live": False,
        },
    )

    monkeypatch.setattr(evidence_model, "DATA_DIR", unified_db.parent)
    monkeypatch.setattr(evidence_model, "DB_PATH", unified_db)
    _orig_unified_init = UnifiedEvidenceStore.__init__
    monkeypatch.setattr(
        UnifiedEvidenceStore,
        "__init__",
        lambda self, db_path=unified_db: _orig_unified_init(self, db_path=unified_db),
    )

    isolated_ev_store = EvidenceStore(root_dir=str(ev_dir))
    monkeypatch.setattr(gs, "GLOBAL_EVIDENCE_STORE", isolated_ev_store)
    monkeypatch.setattr(ops_api, "GLOBAL_EVIDENCE_STORE", isolated_ev_store)
    _orig_ev_init = EvidenceStore.__init__
    monkeypatch.setattr(
        EvidenceStore,
        "__init__",
        lambda self, root_dir=str(ev_dir): _orig_ev_init(self, root_dir=str(ev_dir)),
    )

    monkeypatch.setattr(
        SessionManager,
        "__init__",
        lambda self, sessions_dir=str(sessions_dir): (
            setattr(self, "dir", Path(sessions_dir))
            or self.dir.mkdir(parents=True, exist_ok=True)
        ),
    )

    prev_store = ps._GLOBAL_PLATFORM_STORE
    prev_wired = rt._WIRED
    prev_hook = GLOBAL_RUN_CONTROLLER.on_state_change
    prev_runs = dict(GLOBAL_RUN_CONTROLLER._runs)
    prev_scope_in = list(rt._SCOPE_STATE["in_scope"])
    prev_scope_out = list(rt._SCOPE_STATE["out_of_scope"])
    prev_pipelines = dict(rt._active_pipelines)

    ps._GLOBAL_PLATFORM_STORE = None
    rt.EVENT_BUS._history.clear()
    rt._WIRED = False
    rt._SCOPE_STATE["in_scope"] = []
    rt._SCOPE_STATE["out_of_scope"] = []
    rt._active_pipelines.clear()
    GLOBAL_RUN_CONTROLLER.on_state_change = None
    GLOBAL_RUN_CONTROLLER._runs.clear()

    with ASGISyncClient() as client:
        yield client, tmp_path, reports_dir, sessions_dir, isolated_ev_store

    GLOBAL_RUN_CONTROLLER.stop_all()
    GLOBAL_RUN_CONTROLLER._runs.clear()
    GLOBAL_RUN_CONTROLLER._runs.update(prev_runs)
    GLOBAL_RUN_CONTROLLER.on_state_change = prev_hook
    rt._WIRED = prev_wired
    rt._SCOPE_STATE["in_scope"] = prev_scope_in
    rt._SCOPE_STATE["out_of_scope"] = prev_scope_out
    rt._active_pipelines.clear()
    rt._active_pipelines.update(prev_pipelines)
    if ps._GLOBAL_PLATFORM_STORE is not None:
        ps._GLOBAL_PLATFORM_STORE.close()
    ps._GLOBAL_PLATFORM_STORE = prev_store
    rt.EVENT_BUS._history.clear()


def test_all_example_targets_pass_scope_engagement_and_recon_run(isolated_example_env, monkeypatch):
    """All 8 public demo and local lab presets pass validate-scope, scope/check, engagement, and recon run under opt-in web unrestricted mode."""
    client, _tmp_path, _reports_dir, _sessions_dir, _ev_store = isolated_example_env
    assert web_governance_enforced() is True
    monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "1")
    assert web_governance_enforced() is False

    csrf_token = client.get("/api/csrf").json()["csrfToken"]
    headers = {"X-CSRFToken": csrf_token}

    # Activate an unrelated restrictive workspace + global scope state first to prove
    # other active workspaces or mismatched in_scope/out_of_scope never block explicit targets.
    locked_eng = client.post(
        "/api/platform/engagements",
        json={
            "name": "Locked Restrictive Workspace",
            "target": "https://locked-workspace.internal.example",
            "in_scope": ["locked-workspace.internal.example"],
            "out_of_scope": [
                "testphp.vulnweb.com",
                "testhtml5.vulnweb.com",
                "juice-shop.herokuapp.com",
                "demo.testfire.net",
                "example.com",
                "127.0.0.1",
                "localhost",
            ],
            "set_active": True,
        },
        headers=headers,
    )
    assert locked_eng.status_code == 201, locked_eng.text
    locked_eid = locked_eng.json()["engagement_id"]

    scope_cfg = client.post(
        "/api/scope",
        json={
            "in_scope": ["locked-workspace.internal.example"],
            "out_of_scope": ["testphp.vulnweb.com", "127.0.0.1", "localhost"],
        },
        headers=headers,
    )
    assert scope_cfg.status_code == 200

    for target, category in EXAMPLE_TARGETS:
        # 1a. /api/control/targets/validate-scope (with no in_scope and with mismatched in_scope)
        val_default = client.post(
            "/api/control/targets/validate-scope",
            json={"target_url": target},
            headers=headers,
        )
        assert val_default.status_code == 200, (target, val_default.text)
        assert val_default.json()["allowed"] is True, (target, val_default.json())

        val_mismatch = client.post(
            "/api/control/targets/validate-scope",
            json={"target_url": target, "in_scope": ["unrelated-only.example"]},
            headers=headers,
        )
        assert val_mismatch.status_code == 200, (target, val_mismatch.text)
        assert val_mismatch.json()["allowed"] is True, (target, val_mismatch.json())

        # 1b. /api/scope/check
        chk = client.post(
            "/api/scope/check",
            json={"target": target, "in_scope": ["unrelated-only.example"]},
            headers=headers,
        )
        assert chk.status_code == 200, (target, chk.text)
        chk_body = chk.json()
        assert chk_body["allowed"] is True, (target, chk_body)
        assert chk_body["in_scope"] is True, (target, chk_body)

        # 1c. /api/platform/runs/start (kind="pipeline", mode="recon") while locked workspace is active
        #     and without matching in_scope
        run_unmatched = client.post(
            "/api/platform/runs/start",
            json={
                "kind": "pipeline",
                "mode": "recon",
                "target": target,
                "scope": ["unrelated-only.example"],
            },
            headers=headers,
        )
        assert run_unmatched.status_code == 200, (target, run_unmatched.text)
        run_payload = run_unmatched.json()
        run_id = run_payload["run_id"]
        assert isinstance(run_id, str) and run_id.startswith("run_"), run_payload
        assert run_payload["run"]["kind"] == "pipeline"
        assert run_payload["run"]["meta"]["mode"] == "recon"

        # Verify recon run also starts cleanly when tied to the unrelated active engagement_id
        stop_r = client.post(f"/api/platform/runs/{run_id}/stop", headers=headers)
        assert stop_r.status_code == 200
        client.put(
            "/api/platform/context",
            json={"active_engagement_id": locked_eid},
            headers={"Origin": "http://127.0.0.1:8000", "X-CSRFToken": csrf_token},
        )

        # 1d. /api/platform/engagements -> 201
        eng_resp = client.post(
            "/api/platform/engagements",
            json={
                "name": f"Example ({category}): {target}",
                "target": target,
                "set_active": False,
            },
            headers=headers,
        )
        assert eng_resp.status_code == 201, (target, eng_resp.text)
        eng_data = eng_resp.json()
        assert eng_data["engagement_id"].startswith("eng_")
        assert eng_data["engagement"]["target"] == target

    # Overview and engagement list retain all created example target workspaces
    eng_list = client.get("/api/platform/engagements")
    assert eng_list.status_code == 200
    saved_targets = {item["target"] for item in eng_list.json()["engagements"]}
    for target, _category in EXAMPLE_TARGETS:
        assert target in saved_targets


def test_non_overridable_safety_invariants_blocked(isolated_example_env, monkeypatch):
    """Cloud metadata SSRF, unsafe file:// scheme, shell metacharacters, and DNS rebind stay 403/blocked."""
    client, _tmp_path, _reports_dir, _sessions_dir, _ev_store = isolated_example_env
    csrf_token = client.get("/api/csrf").json()["csrfToken"]
    headers = {"X-CSRFToken": csrf_token}

    async def _fake_run(cmd, timeout_s=60.0):
        return {"command": " ".join(cmd), "stdout": "should_never_execute", "stderr": "", "returncode": 0}

    monkeypatch.setattr(arsenal_api, "run_command_no_shell", _fake_run)

    # Verify invariants hold both in default web unrestricted mode and with explicit HUNTER_UNRESTRICTED=1
    for env_mode in ("default", "explicit_unrestricted"):
        if env_mode == "explicit_unrestricted":
            monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
            monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "1")
        else:
            monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
            monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)

        for bad_target in NON_OVERRIDABLE_BLOCKED_TARGETS:
            scope_override = ["169.254.169.254", "localhost", "127.0.0.1", bad_target]

            # Scope validation endpoints reject with allowed=False
            val_r = client.post(
                "/api/control/targets/validate-scope",
                json={"target_url": bad_target, "in_scope": scope_override},
                headers=headers,
            )
            assert val_r.status_code == 200
            assert val_r.json()["allowed"] is False, (env_mode, bad_target, val_r.json())

            chk_r = client.post(
                "/api/scope/check",
                json={"target": bad_target, "in_scope": scope_override},
                headers=headers,
            )
            assert chk_r.status_code == 200
            assert chk_r.json()["allowed"] is False, (env_mode, bad_target, chk_r.json())

            # Mutating / execution endpoints reject strictly with HTTP 403
            eng_r = client.post(
                "/api/platform/engagements",
                json={"name": "Blocked Invariant", "target": bad_target, "in_scope": scope_override},
                headers=headers,
            )
            assert eng_r.status_code == 403, (env_mode, bad_target, eng_r.status_code, eng_r.text)

            run_r = client.post(
                "/api/platform/runs/start",
                json={"kind": "pipeline", "mode": "recon", "target": bad_target, "scope": scope_override},
                headers=headers,
            )
            assert run_r.status_code == 403, (env_mode, bad_target, run_r.status_code, run_r.text)

            rep_r = client.post(
                "/api/burp/repeater/send",
                json={"url": bad_target, "method": "GET", "scope": scope_override},
                headers=headers,
            )
            assert rep_r.status_code == 403, (env_mode, bad_target, rep_r.status_code, rep_r.text)

        # Tool execution blocks shell metacharacters, metadata IP, and file://
        for bad_cmd in (
            "nmap evil;id",
            "curl http://169.254.169.254/latest/meta-data/",
            "curl file:///etc/passwd",
        ):
            tool_r = client.post(
                "/api/run-tool",
                json={"command": bad_cmd},
                headers=headers,
            )
            assert tool_r.status_code == 403, (env_mode, bad_cmd, tool_r.status_code, tool_r.text)

    # DNS rebinding to metadata IP remains 403 even on a public-looking hostname
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))],
    )
    rebind_r = client.post(
        "/api/burp/repeater/send",
        json={"url": "http://testphp.vulnweb.com/listproducts.php?cat=1", "method": "GET"},
        headers=headers,
    )
    assert rebind_r.status_code == 403


def test_practice_lab_repeater_diff_seven_gate_and_report_export(
    practice_lab_server, isolated_example_env, monkeypatch
):
    """End-to-end multi-bug flow against isolated Acunetix/JuiceShop HTTP server via Django ASGI."""
    base_url, _port = practice_lab_server
    client, _tmp_path, reports_dir, sessions_dir, ev_store = isolated_example_env
    monkeypatch.setenv("HUNTER_ALLOW_LOCALHOST_SCOPE", "1")

    csrf_token = client.get("/api/csrf").json()["csrfToken"]
    headers = {"X-CSRFToken": csrf_token}

    # 1. Validate scope + register engagement + launch recon pipeline run
    assert client.post(
        "/api/control/targets/validate-scope",
        json={"target_url": base_url, "in_scope": ["127.0.0.1"]},
        headers=headers,
    ).json()["allowed"] is True

    assert client.post(
        "/api/scope/check",
        json={"target": base_url, "in_scope": ["127.0.0.1"]},
        headers=headers,
    ).json()["allowed"] is True

    eng_resp = client.post(
        "/api/platform/engagements",
        json={
            "name": "Isolated Acunetix & JuiceShop Practice Lab",
            "target": base_url,
            "in_scope": ["127.0.0.1"],
            "out_of_scope": ["169.254.169.254"],
            "set_active": True,
        },
        headers=headers,
    )
    assert eng_resp.status_code == 201, eng_resp.text
    eng_id = eng_resp.json()["engagement_id"]

    run_resp = client.post(
        "/api/platform/runs/start",
        json={"kind": "pipeline", "target": base_url, "engagement_id": eng_id, "mode": "recon"},
        headers=headers,
    )
    assert run_resp.status_code == 200, run_resp.text
    run_id = run_resp.json()["run_id"]
    assert run_id.startswith("run_")

    sse_resp = client.get(
        "/api/platform/stream",
        params={"since_seq": 0, "once": "1", "run_id": run_id},
    )
    assert sse_resp.status_code == 200
    assert "run.started" in sse_resp.text

    # 2. Probe all vulnerable endpoints via POST /api/burp/repeater/send
    def _repeater(path_and_query: str, req_headers: Dict[str, str] | None = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "url": f"{base_url}{path_and_query}",
            "method": "GET",
            "engagement_id": eng_id,
        }
        if req_headers:
            payload["headers"] = req_headers
        resp = client.post("/api/burp/repeater/send", json=payload, headers=headers)
        assert resp.status_code == 200, (path_and_query, resp.text)
        return resp.json()

    # 2a. Error-based SQLi on /listproducts.php?cat=1
    r_sqli_base = _repeater("/listproducts.php?cat=1")
    assert r_sqli_base["status_code"] == 200
    assert "Art Posters" in r_sqli_base["body"]

    r_sqli = _repeater("/listproducts.php?cat=1%27%20UNION%20SELECT%201--")
    assert r_sqli["status_code"] == 500
    assert "MySQL server version 8.0.36-community" in r_sqli["body"]
    assert "pbkdf2_sha256_demo_hash_9911" in r_sqli["body"]

    # 2b. Reflected XSS on /search.php?test=... + safe escaped reflection control
    r_xss_base = _repeater("/search.php?test=posters")
    assert r_xss_base["status_code"] == 200

    r_xss = _repeater("/search.php?test=%3Csvg%20onload%3Dalert(1)%3E")
    assert r_xss["status_code"] == 200
    assert "<svg onload=alert(1)>" in r_xss["body"]

    r_xss_safe = _repeater("/search-safe.php?test=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert r_xss_safe["status_code"] == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r_xss_safe["body"]
    assert "<script>alert(1)</script>" not in r_xss_safe["body"]

    # 2c. Cross-tenant IDOR on /api/users?id=2
    r_idor_base = _repeater("/api/users?id=1", req_headers={"X-User": "alice"})
    assert r_idor_base["status_code"] == 200
    assert "ALICE_OWN_TOKEN_101" in r_idor_base["body"]

    r_idor = _repeater("/api/users?id=2", req_headers={"X-User": "alice"})
    assert r_idor["status_code"] == 200
    assert "BOB_ADMIN_SECRET_TOKEN_777" in r_idor["body"]

    # 2d. Open redirect on /redirect?to=...
    r_redir_base = _repeater("/redirect?to=/home")
    assert r_redir_base["status_code"] == 302
    assert r_redir_base["headers"].get("location") == "/home"

    r_redir = _repeater("/redirect?to=https://evil.example/phish")
    assert r_redir["status_code"] == 302
    assert r_redir["headers"].get("location") == "https://evil.example/phish"

    # 2e. Non-overridable SSRF check inside active repeater session
    r_meta = client.post(
        "/api/burp/repeater/send",
        json={"url": "http://169.254.169.254/latest/meta-data/", "method": "GET", "engagement_id": eng_id},
        headers=headers,
    )
    assert r_meta.status_code == 403

    # 3. Behavioral differential analysis via POST /api/analyzer/diff
    diff_sqli = client.post(
        "/api/analyzer/diff",
        json={
            "baseline_status": r_sqli_base["status_code"],
            "baseline_body": r_sqli_base["body"],
            "test_status": r_sqli["status_code"],
            "test_body": r_sqli["body"],
            "transaction_id": "tx_lab_sqli",
        },
        headers=headers,
    )
    assert diff_sqli.status_code == 200, diff_sqli.text
    diff_sqli_json = diff_sqli.json()
    assert diff_sqli_json["is_statistically_significant"] is True
    assert diff_sqli_json["differential_score"] >= 0.8
    assert diff_sqli_json["status_match"] is False
    assert diff_sqli_json["body_hash_match"] is False
    assert diff_sqli_json["error_signature_observed"] is not None

    diff_idor = client.post(
        "/api/analyzer/diff",
        json={
            "baseline_status": r_idor_base["status_code"],
            "baseline_body": r_idor_base["body"],
            "test_status": r_idor["status_code"],
            "test_body": r_idor["body"],
            "transaction_id": "tx_lab_idor",
        },
        headers=headers,
    )
    assert diff_idor.status_code == 200, diff_idor.text
    diff_idor_json = diff_idor.json()
    assert diff_idor_json["is_statistically_significant"] is True
    assert diff_idor_json["body_hash_match"] is False
    assert diff_idor_json["length_delta"] > 50
    assert diff_idor_json["differential_score"] >= 0.5

    diff_xss = client.post(
        "/api/analyzer/diff",
        json={
            "baseline_status": r_xss_base["status_code"],
            "baseline_body": r_xss_base["body"],
            "test_status": r_xss["status_code"],
            "test_body": r_xss["body"],
            "transaction_id": "tx_lab_xss",
        },
        headers=headers,
    )
    assert diff_xss.status_code == 200, diff_xss.text
    assert diff_xss.json()["body_hash_match"] is False
    assert diff_xss.json()["differential_score"] >= 0.4

    # 4. EvidenceCourt adjudication + /api/control/seven-gate/evaluate + SevenQuestionGate
    court = EvidenceCourt()

    fp_xss_judgment = court.adjudicate(
        target_url=f"{base_url}/search-safe.php",
        parameter="test",
        vuln_class="xss_reflected",
        finder_claim={"title": "HTML-escaped reflection FP", "is_reflection": True},
        verifier_result={"reproduced": False, "is_reflection": True},
        is_in_scope=True,
    )
    assert fp_xss_judgment.verdict == CourtVerdict.FALSE_POSITIVE
    assert fp_xss_judgment.reportable is False

    sqli_judgment = court.adjudicate(
        target_url=f"{base_url}/listproducts.php",
        parameter="cat",
        vuln_class="sqli",
        finder_claim={"title": "Error-based SQL Injection on /listproducts.php"},
        verifier_result={"reproduced": True, "extracted_data": True},
        proof_payload=ProofPayload(
            artifact_type="sqli",
            baseline_text=r_sqli_base["body"],
            response_text=r_sqli["body"],
        ),
        is_in_scope=True,
    )
    assert sqli_judgment.verdict == CourtVerdict.CONFIRMED
    assert sqli_judgment.reportable is True
    assert sqli_judgment.calibrated_severity == "Critical"
    assert sqli_judgment.proof_strength == "DERIVED"

    xss_judgment = court.adjudicate(
        target_url=f"{base_url}/search.php",
        parameter="test",
        vuln_class="xss_reflected",
        finder_claim={"title": "Reflected XSS on /search.php"},
        verifier_result={"reproduced": True, "dom_breakout_confirmed": True},
        proof_payload=ProofPayload(
            artifact_type="token",
            expected_token="<svg onload=alert(1)>",
            probed_expression="",
            baseline_text=r_xss_base["body"],
            response_text=r_xss["body"],
        ),
        is_in_scope=True,
    )
    assert xss_judgment.verdict == CourtVerdict.CONFIRMED
    assert xss_judgment.reportable is True
    assert xss_judgment.calibrated_severity == "Medium"

    idor_judgment = court.adjudicate(
        target_url=f"{base_url}/api/users",
        parameter="id",
        vuln_class="idor",
        finder_claim={"title": "Cross-Tenant IDOR on /api/users"},
        verifier_result={"reproduced": True, "token_bypass_confirmed": True},
        proof_payload=ProofPayload(
            artifact_type="token",
            expected_token="BOB_ADMIN_SECRET_TOKEN_777",
            probed_expression="",
            baseline_text=r_idor_base["body"],
            response_text=r_idor["body"],
        ),
        is_in_scope=True,
    )
    assert idor_judgment.verdict == CourtVerdict.CONFIRMED
    assert idor_judgment.reportable is True
    assert idor_judgment.calibrated_severity == "High"

    redirect_judgment = court.adjudicate(
        target_url=f"{base_url}/redirect",
        parameter="to",
        vuln_class="open_redirect",
        finder_claim={"title": "Open Redirect on /redirect"},
        verifier_result={"reproduced": True, "token_bypass_confirmed": True},
        proof_payload=ProofPayload(
            artifact_type="token",
            expected_token="https://evil.example/phish",
            probed_expression="",
            baseline_text=r_redir_base["headers"].get("location", ""),
            response_text=r_redir["headers"].get("location", ""),
        ),
        is_in_scope=True,
    )
    assert redirect_judgment.verdict == CourtVerdict.CONFIRMED
    assert redirect_judgment.reportable is True

    confirmed_specs = [
        {
            "id": "FIND-LAB-SQLI",
            "title": "SQL Injection on /listproducts.php",
            "asset": f"{base_url}/listproducts.php?cat=1",
            "poc": f"GET {base_url}/listproducts.php?cat=1%27%20UNION%20SELECT%201-- -> MySQL 8.0.36-community error & hash leak",
            "impact": "Database error disclosure and credential hash extraction",
            "vulnerability_class": "sqli",
            "severity": sqli_judgment.calibrated_severity,
            "cvss_score": 9.8,
            "evidence": r_sqli["body"],
            "recommendation": "Use parameterized SQL prepared statements for the cat parameter.",
            "rationale": sqli_judgment.adjudication_rationale,
            "reason_code": "POE_SQLI_DERIVED",
        },
        {
            "id": "FIND-LAB-XSS",
            "title": "Reflected XSS on /search.php",
            "asset": f"{base_url}/search.php?test=posters",
            "poc": f"GET {base_url}/search.php?test=%3Csvg%20onload%3Dalert(1)%3E -> unescaped <svg onload=alert(1)>",
            "impact": "Arbitrary JavaScript execution in victim browser session",
            "vulnerability_class": "xss_reflected",
            "severity": xss_judgment.calibrated_severity,
            "cvss_score": 6.1,
            "evidence": r_xss["body"],
            "recommendation": "HTML-encode reflected query parameter test before rendering.",
            "rationale": xss_judgment.adjudication_rationale,
            "reason_code": "POE_XSS_DERIVED",
        },
        {
            "id": "FIND-LAB-IDOR",
            "title": "Cross-Tenant IDOR on /api/users",
            "asset": f"{base_url}/api/users?id=2",
            "poc": f"GET {base_url}/api/users?id=2 with X-User: alice -> returned BOB_ADMIN_SECRET_TOKEN_777",
            "impact": "Unauthorized access to admin user PII and API token",
            "vulnerability_class": "idor",
            "severity": idor_judgment.calibrated_severity,
            "cvss_score": 8.2,
            "evidence": r_idor["body"],
            "recommendation": "Enforce object-level authorization checking authenticated user ownership.",
            "rationale": idor_judgment.adjudication_rationale,
            "reason_code": "POE_IDOR_DERIVED",
        },
        {
            "id": "FIND-LAB-REDIR",
            "title": "Open Redirect on /redirect",
            "asset": f"{base_url}/redirect?to=/home",
            "poc": f"GET {base_url}/redirect?to=https://evil.example/phish -> 302 Location: https://evil.example/phish",
            "impact": "Phishing redirect off trusted domain",
            "vulnerability_class": "open_redirect",
            "severity": redirect_judgment.calibrated_severity,
            "cvss_score": 4.7,
            "evidence": f"HTTP 302 Location: {r_redir['headers'].get('location')}",
            "recommendation": "Validate redirect destination against an explicit relative-path or host allowlist.",
            "rationale": redirect_judgment.adjudication_rationale,
            "reason_code": "POE_REDIRECT_DERIVED",
        },
    ]

    for spec in confirmed_specs:
        gate_resp = client.post(
            "/api/control/seven-gate/evaluate",
            json={
                "title": spec["title"],
                "asset": spec["asset"],
                "poc": spec["poc"],
                "impact": spec["impact"],
                "vulnerability_class": spec["vulnerability_class"],
                "in_scope": ["127.0.0.1"],
            },
            headers=headers,
        )
        assert gate_resp.status_code == 200, (spec["id"], gate_resp.text)
        gate_body = gate_resp.json()
        assert gate_body["ok"] is True
        assert "evaluation" in gate_body
        assert "triage_statement" in gate_body["evaluation"]

        direct_gate = SevenQuestionGate.evaluate_finding(
            {
                "title": spec["title"],
                "url": spec["asset"],
                "evidence": spec["evidence"],
                "type": spec["vulnerability_class"],
                "severity": spec["severity"],
                "tool": "burp_repeater",
                "recommendation": spec["recommendation"],
                "target": base_url,
            },
            in_scope_list=["127.0.0.1"],
        )
        assert direct_gate.passed is True, (spec["id"], direct_gate.missing_items)
        assert direct_gate.score == 1.0

    # 5. Record court verdicts & proof evidence in isolated EvidenceStore, then verify ledger & run findings
    for spec in confirmed_specs:
        ev_store.record_court_verdict(
            run_id=run_id,
            finding_id=spec["id"],
            title=spec["title"],
            endpoint=spec["asset"],
            verdict="CONFIRMED",
            reason_code=spec["reason_code"],
            rationale=spec["rationale"],
        )
        rec = ev_store.add_evidence(
            run_id=run_id,
            source_worker="repeater_probe",
            source_tool="burp_repeater",
            evidence_type="proof",
            content=spec["evidence"],
            provenance="test_example_targets_flow",
            confidence=0.98,
            metadata={"target": base_url, "finding_id": spec["id"]},
        )
        assert rec.evidence_id.startswith("EV-")

    ev_store.record_court_verdict(
        run_id=run_id,
        finding_id="FIND-LAB-FP-REFLECT",
        title="HTML-escaped reflection FP",
        endpoint=f"{base_url}/search-safe.php",
        verdict="FALSE_POSITIVE",
        reason_code="REFLECTION_ONLY",
        rationale=fp_xss_judgment.adjudication_rationale,
    )

    ledger_resp = client.get("/api/evidence/ledger")
    assert ledger_resp.status_code == 200
    assert ledger_resp.json()["counts"]["court_verdict"] == len(confirmed_specs) + 1
    assert ledger_resp.json()["counts"]["evidence"] == len(confirmed_specs)

    run_findings_resp = client.get(f"/api/runs/{run_id}/findings")
    assert run_findings_resp.status_code == 200
    assert run_findings_resp.json()["findings_count"] == len(confirmed_specs)

    # 6. Persist confirmed findings & verify /api/control/results + Markdown & JSON report exports
    sm = SessionManager(sessions_dir=str(sessions_dir))
    session = sm.create_session(base_url, "hunt")
    for spec in confirmed_specs:
        sm.add_finding(
            session,
            Finding(
                id=spec["id"],
                title=spec["title"],
                description=spec["impact"],
                severity=spec["severity"],
                cvss_score=spec["cvss_score"],
                tool="burp_repeater",
                evidence=spec["evidence"],
                recommendation=spec["recommendation"],
            ),
        )
        (reports_dir / f"{spec['id']}.json").write_text(
            json.dumps(
                {
                    "report_id": spec["id"],
                    "title": spec["title"],
                    "severity": spec["severity"],
                    "vulnerability_type": spec["vulnerability_class"],
                    "target": base_url,
                    "report_ready": True,
                    "summary": spec["impact"],
                    "evidence": spec["evidence"],
                    "remediation": spec["recommendation"],
                }
            ),
            encoding="utf-8",
        )
    sm.complete(session)
    sm.save(session)

    results_resp = client.get("/api/control/results")
    assert results_resp.status_code == 200
    results_json = results_resp.json()
    assert results_json["total"] == len(confirmed_specs)
    assert all(f["classification"] == "CONFIRMED" for f in results_json["findings"])
    assert {f["id"] for f in results_json["findings"]} == {s["id"] for s in confirmed_specs}

    # Export HackerOne Markdown, standard Markdown, and JSON reports via ASGI endpoints
    h1_resp = client.get(f"/api/report/{session.id}/hackerone")
    assert h1_resp.status_code == 200
    assert "text/markdown" in h1_resp.headers.get("content-type", "")

    md_resp = client.get(f"/api/report/{session.id}/md")
    assert md_resp.status_code == 200
    assert "text/markdown" in md_resp.headers.get("content-type", "")

    json_resp = client.get(f"/api/report/{session.id}/json")
    assert json_resp.status_code == 200
    json_payload = json_resp.json()
    assert json_payload["session_id"] == session.id
    assert json_payload["target"] == base_url
    assert len(json_payload["findings"]) == len(confirmed_specs)

    for spec in confirmed_specs:
        assert spec["title"] in h1_resp.text
        assert spec["title"] in md_resp.text
        assert any(f["title"] == spec["title"] for f in json_payload["findings"])

    enhanced_list = client.get("/api/enhanced/reports")
    assert enhanced_list.status_code == 200
    expected_md_name = f"{session.id}_hackerone.md"
    assert any(r["filename"] == expected_md_name for r in enhanced_list.json()["reports"])

    enhanced_detail = client.get(f"/api/enhanced/reports/{expected_md_name}")
    assert enhanced_detail.status_code == 200
    assert "SQL Injection on /listproducts.php" in enhanced_detail.json()["content"]

    stop_resp = client.post(f"/api/platform/runs/{run_id}/stop", headers=headers)
    assert stop_resp.status_code == 200

    run_md = client.get(f"/api/report/{run_id}/md")
    assert run_md.status_code == 200
    assert base_url in run_md.text

    run_json = client.get(f"/api/report/{run_id}/json")
    assert run_json.status_code == 200
    assert run_json.json()["session_id"] == run_id
