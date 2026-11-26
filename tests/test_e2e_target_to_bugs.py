"""Isolated end-to-end target-to-bugs pipeline tests against a local vulnerable lab."""
from __future__ import annotations

import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import parse_qs, urlparse

import pytest

import core.copilot_service as cs
import core.global_state as gs
import core.platform_store as ps
import hunter_backend.apps.operations_api as ops_api
from core.evidence.differential_analyzer import DifferentialAnalyzer
from core.evidence_court import CourtVerdict, EvidenceCourt, ProofPayload
from core.evidence_store import EvidenceStore
from core.gateway.schemas import GovernedExecutionResult, RiskTier
from core.gateway.tool_gateway import GovernedToolGateway
from core.run_control import GLOBAL_RUN_CONTROLLER
from core.session_manager import Finding, SessionManager
import hunter_backend.runtime as rt
from hunter_backend.testing import ASGISyncClient


class _VulnLabHandler(BaseHTTPRequestHandler):
    """Isolated local mock vulnerable HTTP target server for deterministic E2E tests."""

    logout_hits: List[str] = []

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, code: int, content_type: str, body: str, extra_headers: Dict[str, str] | None = None) -> None:
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
                "<html><body><h1>Mock Target</h1><a href='/search?q=hi'>Search</a><a href='/api/item?id=1'>Item</a></body></html>",
            )
            return

        if parsed.path == "/search":
            q = (qs.get("q") or [""])[0]
            # Deliberate unescaped reflected XSS sink
            self._send(200, "text/html", f"<html><body><div id='results'>{q}</div></body></html>")
            return

        if parsed.path == "/reflect":
            q = (qs.get("q") or [""])[0]
            # Benign HTML-escaped reflection (false positive test case)
            self._send(200, "text/html", f"<html><body><div data-safe='true'>{html.escape(q)}</div></body></html>")
            return

        if parsed.path == "/api/item":
            item_id = (qs.get("id") or ["1"])[0]
            if "'" in item_id or "union" in item_id.lower():
                self._send(
                    500,
                    "application/json",
                    json.dumps(
                        {
                            "error": "SQLite version 3.45.1 syntax error near UNION SELECT password FROM users",
                            "rows": ["admin:pbkdf2_hash_9911"],
                        }
                    ),
                )
                return
            if item_id == "2":
                # Deliberate cross-tenant IDOR (ignores token=userA)
                self._send(
                    200,
                    "application/json",
                    json.dumps({"id": 2, "owner": "bob", "secret": "BOB_CONFIDENTIAL_TOKEN_999"}),
                )
                return
            self._send(
                200,
                "application/json",
                json.dumps({"id": 1, "owner": "alice", "secret": "ALICE_PRIVATE_100"}),
            )
            return

        if parsed.path == "/redirect":
            nxt = (qs.get("next") or ["/"])[0]
            self.send_response(302)
            self.send_header("Location", nxt)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if parsed.path == "/logout":
            self.__class__.logout_hits.append(self.path)
            self._send(200, "application/json", json.dumps({"logged_out": True}))
            return

        if parsed.path == "/admin":
            self._send(403, "application/json", json.dumps({"error": "Admin access denied"}))
            return

        self._send(404, "application/json", json.dumps({"error": "Not found"}))


@pytest.fixture()
def vuln_lab_server():
    _VulnLabHandler.logout_hits = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _VulnLabHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}", port, _VulnLabHandler
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=3.0)


@pytest.fixture()
def isolated_lab_env(tmp_path, monkeypatch):
    db_file = tmp_path / "platform_state.sqlite3"
    att_dir = tmp_path / "copilot_attachments"
    reports_dir = tmp_path / "data" / "reports"
    sessions_dir = tmp_path / "data" / "sessions"
    ev_dir = tmp_path / "evidence_store"
    for d in (att_dir, reports_dir, sessions_dir, ev_dir):
        d.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("HUNTER_PLATFORM_DB_PATH", str(db_file))
    monkeypatch.setenv("HUNTER_COPILOT_ATTACHMENTS_DIR", str(att_dir))
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
    monkeypatch.setattr(rt, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(ops_api, "REPORTS_DIR", reports_dir)
    monkeypatch.setattr(SessionManager, "__init__", lambda self, sessions_dir=str(sessions_dir): setattr(self, "dir", Path(sessions_dir)) or self.dir.mkdir(parents=True, exist_ok=True))

    isolated_ev_store = EvidenceStore(root_dir=str(ev_dir))
    monkeypatch.setattr(gs, "GLOBAL_EVIDENCE_STORE", isolated_ev_store)
    _orig_ev_init = EvidenceStore.__init__
    monkeypatch.setattr(
        EvidenceStore,
        "__init__",
        lambda self, root_dir=str(ev_dir): _orig_ev_init(self, root_dir=str(ev_dir)),
    )

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
        yield client, tmp_path, reports_dir, sessions_dir, isolated_ev_store

    GLOBAL_RUN_CONTROLLER.stop_all()
    GLOBAL_RUN_CONTROLLER._runs.clear()
    GLOBAL_RUN_CONTROLLER._runs.update(prev_runs)
    GLOBAL_RUN_CONTROLLER.on_state_change = prev_hook
    rt._WIRED = prev_wired
    if ps._GLOBAL_PLATFORM_STORE is not None:
        ps._GLOBAL_PLATFORM_STORE.close()
    ps._GLOBAL_PLATFORM_STORE = prev_store
    rt.EVENT_BUS._history.clear()


def _parse_sse(raw_text: str) -> List[Dict[str, Any]]:
    frames: List[Dict[str, Any]] = []
    cur_event = "message"
    cur_data: List[str] = []
    for line in raw_text.replace("\r\n", "\n").splitlines():
        if line == "":
            if cur_data:
                joined = "\n".join(cur_data)
                try:
                    payload = json.loads(joined)
                except Exception:
                    payload = {"raw": joined}
                frames.append({"event": cur_event, "data": payload})
                cur_event = "message"
                cur_data = []
        elif line.startswith("event:"):
            cur_event = line.split(":", 1)[1].strip()
        elif line.startswith("data:"):
            cur_data.append(line.split(":", 1)[1].strip())
    if cur_data:
        try:
            payload = json.loads("\n".join(cur_data))
        except Exception:
            payload = {"raw": "\n".join(cur_data)}
        frames.append({"event": cur_event, "data": payload})
    return frames


def test_end_to_end_target_to_confirmed_bugs_pipeline(vuln_lab_server, isolated_lab_env, monkeypatch):
    base_url, port, handler_cls = vuln_lab_server
    client, tmp_path, reports_dir, sessions_dir, ev_store = isolated_lab_env

    # 1. Verify default fail-closed SSRF guard rejects loopback before lab opt-in
    monkeypatch.delenv("HUNTER_ALLOW_LOCALHOST_SCOPE", raising=False)
    blocked_eng = client.post(
        "/api/platform/engagements",
        json={"name": "BlockedLab", "target": base_url, "in_scope": ["127.0.0.1"]},
    )
    assert blocked_eng.status_code == 403

    # Enable explicit local lab loopback ONLY (metadata & RFC1918 remain strictly 403)
    monkeypatch.setenv("HUNTER_ALLOW_LOCALHOST_SCOPE", "1")
    meta_blocked = client.post(
        "/api/platform/engagements",
        json={"name": "MetaBlocked", "target": "http://169.254.169.254", "in_scope": ["169.254.169.254"]},
    )
    assert meta_blocked.status_code == 403

    # 2. Engagement + scope registration + context activation
    csrf_resp = client.get("/api/csrf")
    csrf_token = csrf_resp.json()["csrfToken"]

    eng_resp = client.post(
        "/api/platform/engagements",
        json={
            "name": "Local Vuln Lab",
            "target": base_url,
            "in_scope": ["127.0.0.1"],
            "out_of_scope": ["169.254.169.254", "10.0.0.5"],
            "notes": "Isolated E2E vulnerability discovery test",
        },
        headers={"X-CSRFToken": csrf_token},
    )
    assert eng_resp.status_code in (200, 201), eng_resp.text
    eng_id = eng_resp.json()["engagement_id"]

    ctx_resp = client.put(
        "/api/platform/context",
        json={"active_engagement_id": eng_id, "mode": "analyst"},
        headers={"Origin": "http://127.0.0.1:3000", "X-CSRFToken": csrf_token},
    )
    assert ctx_resp.status_code == 200

    # 3. Managed run start + SSE lifecycle stream
    run_resp = client.post(
        "/api/platform/runs/start",
        json={"engagement_id": eng_id, "target": base_url, "kind": "hunt", "mode": "auto"},
        headers={"X-CSRFToken": csrf_token},
    )
    assert run_resp.status_code == 200, run_resp.text
    run_id = run_resp.json()["run_id"]

    sse_resp = client.get(
        "/api/platform/stream",
        params={"since_seq": 0, "once": 1, "run_id": run_id},
    )
    assert sse_resp.status_code == 200
    assert "run." in sse_resp.text

    # 4. Active HTTP probing through governed Repeater endpoint
    r_home = client.post(
        "/api/burp/repeater/send",
        json={"url": f"{base_url}/", "method": "GET", "engagement_id": eng_id, "scope": ["127.0.0.1"]},
    )
    assert r_home.status_code == 200
    assert r_home.json()["status_code"] == 200

    r_admin = client.post(
        "/api/burp/repeater/send",
        json={"url": f"{base_url}/admin", "method": "GET", "engagement_id": eng_id, "scope": ["127.0.0.1"]},
    )
    assert r_admin.status_code == 200
    assert r_admin.json()["status_code"] == 403

    r_xss = client.post(
        "/api/burp/repeater/send",
        json={
            "url": f"{base_url}/search?q=%3Csvg%20onload%3Dalert(1)%3E",
            "method": "GET",
            "engagement_id": eng_id,
            "scope": ["127.0.0.1"],
        },
    )
    assert r_xss.status_code == 200
    assert "<svg onload=alert(1)>" in r_xss.json()["body"]

    r_reflect_fp = client.post(
        "/api/burp/repeater/send",
        json={
            "url": f"{base_url}/reflect?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "method": "GET",
            "engagement_id": eng_id,
            "scope": ["127.0.0.1"],
        },
    )
    assert r_reflect_fp.status_code == 200
    assert "&lt;script&gt;" in r_reflect_fp.json()["body"]

    r_base_item = client.post(
        "/api/burp/repeater/send",
        json={"url": f"{base_url}/api/item?id=1&token=userA", "method": "GET", "engagement_id": eng_id, "scope": ["127.0.0.1"]},
    )
    r_idor = client.post(
        "/api/burp/repeater/send",
        json={"url": f"{base_url}/api/item?id=2&token=userA", "method": "GET", "engagement_id": eng_id, "scope": ["127.0.0.1"]},
    )
    r_sqli = client.post(
        "/api/burp/repeater/send",
        json={"url": f"{base_url}/api/item?id=1%27%20UNION%20SELECT%201", "method": "GET", "engagement_id": eng_id, "scope": ["127.0.0.1"]},
    )
    assert "ALICE_PRIVATE_100" in r_base_item.json()["body"]
    assert "BOB_CONFIDENTIAL_TOKEN_999" in r_idor.json()["body"]
    assert r_sqli.json()["status_code"] == 500
    assert "SQLite version 3.45.1" in r_sqli.json()["body"]

    r_redirect = client.post(
        "/api/burp/repeater/send",
        json={"url": f"{base_url}/redirect?next=https://evil.example/phish", "method": "GET", "engagement_id": eng_id, "scope": ["127.0.0.1"]},
    )
    assert r_redirect.status_code == 200
    assert r_redirect.json()["status_code"] == 302
    assert r_redirect.json()["headers"].get("location") == "https://evil.example/phish"

    # Out-of-scope /logout and metadata SSRF are blocked BEFORE touching server
    r_logout = client.post(
        "/api/burp/repeater/send",
        json={
            "url": f"{base_url}/logout",
            "method": "GET",
            "engagement_id": eng_id,
            "scope": ["127.0.0.1"],
            "out_of_scope": [f"127.0.0.1:{port}/logout"],
        },
    )
    assert r_logout.status_code == 403
    assert handler_cls.logout_hits == []

    r_meta = client.post(
        "/api/burp/repeater/send",
        json={"url": "http://169.254.169.254/latest/meta-data/", "method": "GET", "engagement_id": eng_id},
    )
    assert r_meta.status_code == 403

    # 5. Differential analysis + Evidence Court FP filtering & confirmation
    diff = DifferentialAnalyzer().compare_responses(
        baseline_status=r_base_item.json()["status_code"],
        baseline_body=r_base_item.json()["body"],
        test_status=r_sqli.json()["status_code"],
        test_body=r_sqli.json()["body"],
        transaction_id="tx_e2e_sqli",
    )
    assert diff.is_statistically_significant is True
    assert diff.differential_score > 0.5
    assert diff.error_signature_observed is not None

    court = EvidenceCourt()
    fp_reflection = court.adjudicate(
        target_url=f"{base_url}/reflect",
        parameter="q",
        vuln_class="xss",
        finder_claim={"title": "Reflected input FP", "is_reflection": True},
        verifier_result={"reproduced": False, "is_reflection": True},
        is_in_scope=True,
    )
    assert fp_reflection.verdict == CourtVerdict.FALSE_POSITIVE
    assert fp_reflection.reportable is False

    fp_length_only = court.adjudicate(
        target_url=f"{base_url}/admin",
        parameter="path",
        vuln_class="auth_bypass",
        finder_claim={"title": "403 length delta FP"},
        verifier_result={"reproduced": True, "length_delta_only": True},
        is_in_scope=True,
    )
    assert fp_length_only.verdict == CourtVerdict.FALSE_POSITIVE
    assert fp_length_only.reportable is False

    sqli_judgment = court.adjudicate(
        target_url=f"{base_url}/api/item",
        parameter="id",
        vuln_class="sqli",
        finder_claim={"title": "SQL Injection on /api/item"},
        verifier_result={"reproduced": True, "extracted_data": True},
        proof_payload=ProofPayload(artifact_type="sqli", response_text=r_sqli.json()["body"], baseline_text=r_base_item.json()["body"]),
        is_in_scope=True,
    )
    assert sqli_judgment.verdict == CourtVerdict.CONFIRMED
    assert sqli_judgment.reportable is True
    assert sqli_judgment.calibrated_severity == "Critical"

    idor_judgment = court.adjudicate(
        target_url=f"{base_url}/api/item",
        parameter="id",
        vuln_class="idor",
        finder_claim={"title": "Cross-tenant IDOR exposing Bob secret"},
        verifier_result={"reproduced": True, "token_bypass_confirmed": True},
        proof_payload=ProofPayload(
            artifact_type="token",
            expected_token="BOB_CONFIDENTIAL_TOKEN_999",
            baseline_text=r_base_item.json()["body"],
            response_text=r_idor.json()["body"],
        ),
        is_in_scope=True,
    )
    assert idor_judgment.verdict == CourtVerdict.CONFIRMED
    assert idor_judgment.reportable is True
    assert idor_judgment.calibrated_severity == "High"

    # 6. Seven-Question Gate + EvidenceStore + Findings + HackerOne/Markdown Export
    gate_resp = client.post(
        "/api/control/seven-gate/evaluate",
        json={
            "title": "SQL Injection on /api/item",
            "asset": f"{base_url}/api/item?id=1",
            "poc": "GET /api/item?id=1%27%20UNION%20SELECT%201 -> SQLite version 3.45.1 extracted admin row",
            "impact": "Full database credential disclosure",
            "vulnerability_class": "sqli",
            "in_scope": ["127.0.0.1"],
        },
    )
    assert gate_resp.status_code == 200
    assert gate_resp.json()["ok"] is True

    ev_store.record_court_verdict(
        run_id=run_id,
        finding_id="FIND-SQLI-01",
        title="SQL Injection on /api/item",
        endpoint=f"{base_url}/api/item",
        verdict="CONFIRMED",
        reason_code="POE_SQLI_DERIVED",
        rationale=sqli_judgment.adjudication_rationale,
    )
    ev_store.record_court_verdict(
        run_id=run_id,
        finding_id="FIND-FP-01",
        title="Reflected input FP",
        endpoint=f"{base_url}/reflect",
        verdict="FALSE_POSITIVE",
        reason_code="REFLECTION_ONLY",
        rationale=fp_reflection.adjudication_rationale,
    )

    ledger_resp = client.get("/api/evidence/ledger")
    assert ledger_resp.status_code == 200
    assert ledger_resp.json()["counts"]["court_verdict"] >= 2

    sm = SessionManager(sessions_dir=str(sessions_dir))
    session = sm.create_session(base_url, "hunt")
    sm.add_finding(
        session,
        Finding(
            id="FIND-SQLI-01",
            title="SQL Injection on /api/item",
            description="SQLi parameter id leaked SQLite 3.45.1 error/rows",
            severity="Critical",
            cvss_score=9.8,
            tool="repeater",
            evidence=r_sqli.json()["body"],
            recommendation="Use parameterized SQL queries",
        ),
    )
    sm.complete(session)
    sm.save(session)

    (reports_dir / "FIND-SQLI-01.json").write_text(
        json.dumps(
            {
                "report_id": "FIND-SQLI-01",
                "title": "SQL Injection on /api/item",
                "severity": "Critical",
                "target": base_url,
                "evidence": r_sqli.json()["body"],
            }
        ),
        encoding="utf-8",
    )

    h1_resp = client.get(f"/api/report/{session.id}/hackerone")
    assert h1_resp.status_code == 200
    assert "SQL Injection on /api/item" in h1_resp.text

    md_resp = client.get(f"/api/report/{session.id}/md")
    assert md_resp.status_code == 200
    assert "SQL Injection on /api/item" in md_resp.text

    # 7. Copilot grounds response on confirmed finding and queues scoped approval -> Reject / Approve
    chat_stream = client.post(
        "/api/copilot/chat/stream",
        json={
            "message": f"Review confirmed finding and run nmap {base_url}",
            "engagement_id": eng_id,
            "run_id": run_id,
            "mode": "analyst",
        },
        headers={"X-CSRFToken": csrf_token},
    )
    assert chat_stream.status_code == 200
    frames = _parse_sse(chat_stream.text)
    events = [f["event"] for f in frames]
    assert "context" in events
    assert "approval_request" in events
    assert "done" in events

    ctx_payload = next(f["data"] for f in frames if f["event"] == "context")
    assert any(ref.get("kind") == "finding" and ref.get("id") == "FIND-SQLI-01" for ref in ctx_payload.get("refs", []))
    queued_approval = next(f["data"]["approval"] for f in frames if f["event"] == "approval_request")
    queued_id = queued_approval["approval_id"]

    # Reject first queued action -> not executed
    rej = client.post(
        f"/api/platform/approvals/{queued_id}/decide",
        json={"decision": "rejected", "reason": "Operator declined active nmap sweep"},
        headers={"X-CSRFToken": csrf_token},
    )
    assert rej.status_code == 200
    assert rej.json()["decision"] == "rejected"
    assert rej.json()["executed"] is False

    # Out-of-scope approval decision must be denied with 403
    store = ps.get_platform_store()
    bad_ap = store.create_approval(
        action_type="RUN_TOOL",
        target="http://169.254.169.254/latest/meta-data/",
        tool_name="curl",
        command_args="",
        risk_tier="TIER_2_PROBE",
        rationale="Out of scope SSRF approval test",
        engagement_id=eng_id,
        run_id=run_id,
    )
    bad_dec = client.post(
        f"/api/platform/approvals/{bad_ap['approval_id']}/decide",
        json={"decision": "approved"},
        headers={"X-CSRFToken": csrf_token},
    )
    assert bad_dec.status_code == 403

    # Scoped passive tool approval decision succeeds cleanly via GovernedToolGateway
    def _fake_gateway_exec(self, proposal):
        return GovernedExecutionResult(
            proposal_id=proposal.id,
            tool_name=proposal.tool_name,
            target=proposal.target,
            success=True,
            blocked=False,
            risk_tier=RiskTier.TIER_0_PASSIVE,
            returncode=0,
            raw_stdout=f"SCOPED_PASSIVE_REVIEW_OK:{proposal.target}",
        )

    monkeypatch.setattr(GovernedToolGateway, "execute_proposal", _fake_gateway_exec)

    good_ap = store.create_approval(
        action_type="RUN_TOOL",
        target=base_url,
        tool_name="passive_summary",
        command_args="",
        risk_tier="TIER_0_PASSIVE",
        rationale="Approve scoped report review",
        engagement_id=eng_id,
        run_id=run_id,
    )
    good_dec = client.post(
        f"/api/platform/approvals/{good_ap['approval_id']}/decide",
        json={"decision": "approved"},
        headers={"X-CSRFToken": csrf_token},
    )
    assert good_dec.status_code == 200
    assert good_dec.json()["decision"] == "approved"
    assert good_dec.json()["executed"] is True
    assert "SCOPED_PASSIVE_REVIEW_OK" in good_dec.json()["execution"]["stdout_excerpt"]
