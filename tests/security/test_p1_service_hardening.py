"""Phase 1B Service Plane Security Hardening Verification Suite.

Covers real end-to-end enforcement across:
1. Local bearer/session auth, PBKDF2-SHA512 KDF, sgn revocation, userTier vs tokenTier,
   LoginGuard rate limiting, and TRUSTED_PROXIES client IP extraction.
2. JSON CSRF protection, missing-Origin rejection, strict CSP (no unsafe-inline/unsafe-eval),
   and fail-closed WebSocket Origin/bearer checks.
3. EDITOR_ALLOWED_ROOTS containment blocking core/scripts/tools/agents/bughunter writes.
4. Strict subprocess binary allowlist & shell metacharacter guards (str & list) across
   run_command_no_shell, arsenal_run_view, run_tool_view, SandboxRunView (properly awaited),
   and burp_repeater_send_view proxy SSRF validation.
5. legacy_api_chat_view fail-closed defaults, no auto-execution of bash fences, and
   SettingsSaveView operator-tier + OLLAMA_HOST validation.
6. Approval identity binding, uncorrupted execution fields vs redacted display copies,
   immutable SHA-256 proposal_digest tamper detection, and payload kind/mode allowlists.
7. BugHunter MCP policy engine (blocking args.approve & scope_domains, timing-safe token).
8. BurpGateway loopback binding and X-Hunter-Token / Bearer auth.
9. bughunter/brain.py shell=False + env allowlist, shell TLS verification defaults,
   opencode.json / install_agent.ps1 supply-chain portability, and reconciled security docs.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

import pytest
from fastapi.testclient import TestClient

from core.burp_gateway.capture_store import CaptureStore
from core.burp_gateway.gateway import BurpGateway
from core.platform_store import PlatformStore, compute_proposal_digest, verify_proposal_digest
from hunter_backend.apps.common import run_command_no_shell, validate_proxy_url
from hunter_backend.asgi import application
from hunter_backend.auth import (
    LOGIN_GUARD,
    TOKEN_TIER,
    USER_TIER,
    derive_domain_key,
    extract_client_ip,
    get_or_create_api_token,
    get_session_generation,
    issue_session_token,
    revoke_all_sessions,
    verify_session_token,
)
from hunter_backend.testing import ASGISyncClient
from hunter_backend.websocket import is_ws_origin_allowed

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _isolate_auth_state(tmp_path, monkeypatch):
    import hunter_backend.auth as auth_mod

    LOGIN_GUARD.reset()
    prev_tok = auth_mod._CACHED_FILE_TOKEN
    prev_sgn = auth_mod._SESSION_GENERATION
    monkeypatch.setenv("HUNTER_API_TOKEN_FILE", str(tmp_path / ".api_token"))
    monkeypatch.setenv("HUNTER_SESSION_GEN_FILE", str(tmp_path / ".session_gen"))
    auth_mod._CACHED_FILE_TOKEN = None
    auth_mod._SESSION_GENERATION = None
    yield
    auth_mod._CACHED_FILE_TOKEN = prev_tok
    auth_mod._SESSION_GENERATION = prev_sgn
    LOGIN_GUARD.reset()


def _load_bughunter_mcp_policy_engine():
    mcp_dir = REPO_ROOT / "bughunter" / "mcp" / "bughunter-mcp"
    if str(mcp_dir) not in sys.path:
        sys.path.insert(0, str(mcp_dir))
    # Import package modules cleanly from bughunter-mcp directory
    from policy.engine import PolicyEngine  # type: ignore[import-not-found]
    from policy.decisions import DecisionKind  # type: ignore[import-not-found]

    return PolicyEngine, DecisionKind


# ---------------------------------------------------------------------------
# 1. Auth, PBKDF2-SHA512 KDF, sgn Revocation, Tiers, LoginGuard, Trusted Proxies
# ---------------------------------------------------------------------------


def test_unauthenticated_requests_fail_closed_while_public_health_stays_open():
    with ASGISyncClient(authenticated=False) as anon:
        # Public read endpoints stay readable without auth
        r_health = anon.get("/api/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "ok"

        r_csrf = anon.get("/api/csrf")
        assert r_csrf.status_code == 200
        assert len(r_csrf.json()["csrfToken"]) >= 16

        r_artex_health = anon.get("/api/platform/artex/health")
        assert r_artex_health.status_code == 200

        # Protected reads and mutations fail closed with 401
        for method, path, body in (
            ("GET", "/api/settings", None),
            ("GET", "/api/platform/overview", None),
            ("GET", "/api/platform/approvals", None),
            ("GET", "/api/editor/file?path=skills/hunterai-redteam/SKILL.md", None),
            ("POST", "/api/platform/engagements", {"name": "X", "target": "https://example.com"}),
            ("POST", "/api/settings/save", {"default_provider": "ollama"}),
            ("POST", "/api/arsenal/run", {"tool": "nmap", "target": "example.com"}),
            ("POST", "/api/run-tool", {"command": "nmap example.com"}),
            ("POST", "/api/platform/approvals/apr_nonexistent/decide", {"decision": "approved"}),
        ):
            resp = anon.request(method, path, json=body) if body is not None else anon.request(method, path)
            assert resp.status_code in (401, 403), f"{method} {path} unexpectedly returned {resp.status_code}"
            assert resp.status_code == 401, f"{method} {path} expected 401, got {resp.status_code}"


def test_pbkdf2_domain_separation_sgn_revocation_and_tier_separation(isolated_platform_client, monkeypatch):
    # PBKDF2-SHA512 domain separation yields distinct deterministic keys per domain
    k1 = derive_domain_key("secret-material-xyz", "operator_session_signing")
    k2 = derive_domain_key("secret-material-xyz", "agent_token_signing")
    k1_again = derive_domain_key("secret-material-xyz", "operator_session_signing")
    assert len(k1) == 32 and len(k2) == 32
    assert k1 != k2
    assert k1 == k1_again

    # Issue signed operator session token and verify sgn revocation invalidates it
    sgn_before = get_session_generation()
    sess_tok = issue_session_token(principal="alice", tier=USER_TIER)
    parsed = verify_session_token(sess_tok, is_bearer=False)
    assert parsed is not None
    assert parsed.authenticated is True
    assert parsed.principal == "alice"
    assert parsed.tier == USER_TIER
    assert parsed.sgn == sgn_before

    # Exchange bearer token via /api/auth/session -> HttpOnly cookie + CSRF token
    op_token = get_or_create_api_token()
    with ASGISyncClient(authenticated=False) as browser:
        login_r = browser.post(
            "/api/auth/session",
            json={"token": op_token},
            headers={"Origin": "http://127.0.0.1:3000"},
        )
        assert login_r.status_code == 200, login_r.text
        assert "hunter_session" in browser._client.cookies

        # Cookie-authenticated GET works before revocation
        assert browser.get("/api/platform/context").status_code == 200

        # Revoke all sessions via operator endpoint -> bumps sgn
        rev_r = isolated_platform_client.post("/api/auth/revoke")
        assert rev_r.status_code == 200
        assert rev_r.json()["sgn"] == sgn_before + 1

        # Previously issued signed token & browser cookie are immediately invalid (401)
        assert verify_session_token(sess_tok, is_bearer=False) is None
        after_rev = browser.get("/api/platform/context")
        assert after_rev.status_code == 401

    # tokenTier (agent token) can read overview but is blocked (403) on operator-only mutations
    monkeypatch.setenv("HUNTER_AGENT_TOKEN", "agent-scoped-token-32bytes-minimum-value")
    with ASGISyncClient(authenticated=True, api_token="agent-scoped-token-32bytes-minimum-value") as agent_client:
        assert agent_client.get("/api/platform/context").status_code == 200
        for path, payload in (
            ("/api/settings/save", {"default_provider": "ollama"}),
            ("/api/control/redteam-policy/issue", {"scope": "example.com", "authorized_by": "agent"}),
            ("/api/editor/file/save", {"path": "scratch/agent_note.txt", "content": "nope"}),
            ("/api/platform/approvals/apr_test/decide", {"decision": "approved"}),
        ):
            r = agent_client.post(path, json=payload)
            assert r.status_code == 403, f"tokenTier should get 403 on {path}, got {r.status_code}: {r.text}"
            assert r.json().get("error") == "operator_tier_required"


def test_login_guard_rate_limiting_and_trusted_proxies(monkeypatch):
    # Trusted proxies guard: untrusted REMOTE_ADDR cannot spoof X-Forwarded-For
    class _FakeReq:
        def __init__(self, remote: str, xff: str = ""):
            self.META = {"REMOTE_ADDR": remote}
            if xff:
                self.META["HTTP_X_FORWARDED_FOR"] = xff

    assert extract_client_ip(_FakeReq("198.51.100.9", "10.0.0.1"), trusted_proxies=[]) == "198.51.100.9"
    assert extract_client_ip(_FakeReq("10.0.0.2", "203.0.113.45"), trusted_proxies=["10.0.0.0/24"]) == "203.0.113.45"
    assert extract_client_ip(_FakeReq("198.51.100.9", "203.0.113.45"), trusted_proxies=["10.0.0.0/24"]) == "198.51.100.9"

    # LoginGuard triggers 429 after max_failures wrong bearer attempts
    monkeypatch.setattr(LOGIN_GUARD, "max_failures", 3)
    with ASGISyncClient(authenticated=False) as bad_client:
        for i in range(2):
            r = bad_client.get("/api/settings", headers={"Authorization": "Bearer wrong-token"})
            assert r.status_code == 401, f"attempt {i+1}: expected 401, got {r.status_code}"
        r_lock = bad_client.get("/api/settings", headers={"Authorization": "Bearer wrong-token"})
        assert r_lock.status_code == 429
        assert int(r_lock.headers.get("retry-after", "0")) >= 1


# ---------------------------------------------------------------------------
# 2. JSON CSRF Protection, Missing-Origin Rejection, CSP, and WS Fail-Closed
# ---------------------------------------------------------------------------


def test_json_csrf_protection_missing_origin_and_strict_csp(isolated_platform_client):
    op_token = get_or_create_api_token()
    with ASGISyncClient(authenticated=False) as browser:
        # Establish browser session cookie (non-bearer auth)
        sess = browser.post(
            "/api/auth/session",
            json={"token": op_token},
            headers={"Origin": "http://127.0.0.1:3000"},
        )
        assert sess.status_code == 200
        csrf_token = sess.json()["csrfToken"]

        # Verify strict CSP removes 'unsafe-inline' and 'unsafe-eval'
        csp = sess.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "'unsafe-inline'" not in csp
        assert "'unsafe-eval'" not in csp

        # 1. JSON POST with trusted Origin + session cookie BUT missing X-CSRFToken MUST fail 403
        r_no_csrf = browser.post(
            "/api/platform/engagements",
            json={"name": "NoCSRF", "target": "https://example.com"},
            headers={"Origin": "http://127.0.0.1:3000"},
        )
        assert r_no_csrf.status_code == 403
        assert r_no_csrf.json().get("error") == "csrf_token_required"

        # 2. JSON POST with valid X-CSRFToken + session cookie BUT missing Origin MUST fail 403
        r_no_origin = browser.post(
            "/api/platform/engagements",
            json={"name": "NoOrigin", "target": "https://example.com"},
            headers={"X-CSRFToken": csrf_token},
        )
        assert r_no_origin.status_code == 403
        assert r_no_origin.json().get("error") == "csrf_origin_required"

        # 3. JSON POST with BOTH trusted Origin AND valid double-submit X-CSRFToken succeeds
        r_ok = browser.post(
            "/api/platform/engagements",
            json={"name": "ValidBrowser", "target": "https://example.com"},
            headers={"Origin": "http://127.0.0.1:3000", "X-CSRFToken": csrf_token},
        )
        assert r_ok.status_code == 201, r_ok.text


def test_websocket_fails_closed_when_origin_missing_without_bearer():
    assert is_ws_origin_allowed(None) is False
    assert is_ws_origin_allowed(None, has_valid_bearer=False) is False
    assert is_ws_origin_allowed(None, has_valid_bearer=True) is True
    assert is_ws_origin_allowed("https://evil.example") is False
    assert is_ws_origin_allowed("http://127.0.0.1:3000") is True

    async def _probe(headers: list[tuple[bytes, bytes]]):
        in_q: asyncio.Queue = asyncio.Queue()
        out_q: asyncio.Queue = asyncio.Queue()
        await in_q.put({"type": "websocket.connect"})
        scope = {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "path": "/ws/platform",
            "headers": headers,
            "query_string": b"",
        }
        task = asyncio.create_task(application(scope, in_q.get, out_q.put))
        first = await asyncio.wait_for(out_q.get(), timeout=3.0)
        await in_q.put({"type": "websocket.disconnect", "code": 1000})
        try:
            await asyncio.wait_for(task, timeout=2.0)
        except Exception:
            task.cancel()
        return first

    # Missing Origin without bearer -> 4403
    no_origin = asyncio.run(_probe([]))
    assert no_origin["type"] == "websocket.close"
    assert no_origin["code"] == 4403

    # Trusted Origin WITHOUT any auth credentials -> 4401 (never admit unauth WS upgrades)
    trusted_origin_unauth = asyncio.run(_probe([(b"origin", b"http://127.0.0.1:3000")]))
    assert trusted_origin_unauth["type"] == "websocket.close"
    assert trusted_origin_unauth["code"] == 4401

    # Invalid bearer -> 4401
    bad_bearer = asyncio.run(_probe([(b"authorization", b"Bearer invalid-token")]))
    assert bad_bearer["type"] == "websocket.close"
    assert bad_bearer["code"] == 4401

    # Missing Origin WITH valid bearer -> accept
    token = get_or_create_api_token()
    ok_bearer = asyncio.run(_probe([(b"authorization", f"Bearer {token}".encode("utf-8"))]))
    assert ok_bearer["type"] == "websocket.accept"

    # Trusted Origin WITH valid signed session cookie -> accept
    sess_tok = issue_session_token(principal="ws-operator", tier=USER_TIER)
    ok_cookie = asyncio.run(
        _probe(
            [
                (b"origin", b"http://127.0.0.1:3000"),
                (b"cookie", f"hunter_session={sess_tok}".encode("utf-8")),
            ]
        )
    )
    assert ok_cookie["type"] == "websocket.accept"


# ---------------------------------------------------------------------------
# 3. EDITOR_ALLOWED_ROOTS Containment
# ---------------------------------------------------------------------------


def test_editor_allowed_roots_blocks_code_directories(tmp_path, monkeypatch):
    import hunter_backend.apps.intelligence_api as intel_api

    with ASGISyncClient() as client:
        for forbidden in (
            "core/security_mode.py",
            "scripts/authorize_full_power.py",
            "tools/tool_manager.py",
            "agents/burp_agent/__init__.py",
            "bughunter/brain.py",
            "skills/../core/security_mode.py",
            "hunter_backend/settings.py",
        ):
            r_get = client.get("/api/editor/file", params={"path": forbidden})
            assert r_get.status_code == 403, f"GET {forbidden} expected 403, got {r_get.status_code}"
            r_save = client.post("/api/editor/file/save", json={"path": forbidden, "content": "# pwn"})
            assert r_save.status_code == 403, f"SAVE {forbidden} expected 403, got {r_save.status_code}"
            r_create = client.post("/api/editor/file/create", json={"path": forbidden, "content": "# pwn"})
            assert r_create.status_code == 403, f"CREATE {forbidden} expected 403, got {r_create.status_code}"

        # Safe non-code root (scratch/ inside redirected tmp BASE_DIR) works cleanly
        safe_scratch = tmp_path / "scratch"
        safe_scratch.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(intel_api, "BASE_DIR", tmp_path)
        monkeypatch.setattr(
            intel_api,
            "EDITOR_ALLOWED_ROOTS",
            [tmp_path / "skills", tmp_path / "data" / "reports", safe_scratch],
        )
        r_ok = client.post("/api/editor/file/create", json={"path": "scratch/note.md", "content": "hello"})
        assert r_ok.status_code == 201
        assert (safe_scratch / "note.md").read_text(encoding="utf-8") == "hello"


# ---------------------------------------------------------------------------
# 4. Subprocess Allowlist, Shell Metacharacters, SandboxRunView await, Proxy Guard
# ---------------------------------------------------------------------------


def test_arsenal_and_run_tool_block_interpreters_and_metachars_on_str_and_list():
    with ASGISyncClient() as client:
        for forbidden_bin in ("python", "python3", "node", "sh", "bash", "cmd", "powershell", "pwsh", "curl", "wget"):
            r1 = client.post(
                "/api/arsenal/run",
                json={"tool": forbidden_bin, "args": ["-c", "print(1)"], "target": "example.com"},
            )
            assert r1.status_code == 403, f"arsenal/run failed to block {forbidden_bin}: {r1.status_code}"

            r2 = client.post(
                "/api/run-tool",
                json={"command": f"{forbidden_bin} -c id"},
            )
            assert r2.status_code == 403, f"run-tool str failed to block {forbidden_bin}: {r2.status_code}"

            r3 = client.post(
                "/api/run-tool",
                json={"command": [forbidden_bin, "-c", "id"]},
            )
            assert r3.status_code == 403, f"run-tool list failed to block {forbidden_bin}: {r3.status_code}"

        # Shell metacharacters including (, ), \n, ;, |, &, $, ` blocked on BOTH str and list
        for bad_arg in ("example.com;id", "example.com|id", "example.com&id", "$(id)", "`id`", "a(b)", "a\nid"):
            r_list = client.post(
                "/api/arsenal/run",
                json={"tool": "nmap", "args": [bad_arg], "target": "example.com"},
            )
            assert r_list.status_code == 403, f"arsenal/run list failed to block {bad_arg!r}"

            r_rt_list = client.post(
                "/api/run-tool",
                json={"command": ["nmap", bad_arg]},
            )
            assert r_rt_list.status_code == 403, f"run-tool list failed to block {bad_arg!r}"

        # Direct run_command_no_shell list enforcement
        with pytest.raises(PermissionError):
            asyncio.run(run_command_no_shell(["python", "-c", "print(1)"]))
        with pytest.raises(PermissionError):
            asyncio.run(run_command_no_shell(["nmap", "example.com\nid"]))
        with pytest.raises(PermissionError):
            asyncio.run(run_command_no_shell(["nmap", "(id)"]))


def test_sandbox_run_view_awaits_result_and_enforces_allowlist(monkeypatch):
    from core.sandbox import LocalSandbox, SandboxResult

    async def _fake_sandbox_run(self, command, *, cwd=None, env=None, timeout_s=60.0, max_output_bytes=1_000_000):
        return SandboxResult(ok=True, command=command, stdout="awaited-ok", exit_code=0)

    monkeypatch.setattr(LocalSandbox, "run", _fake_sandbox_run)

    with ASGISyncClient() as client:
        # Disallowed python binary blocked with 403
        r_bad = client.post("/api/sandbox/run", json={"command": ["python", "-c", "import os"]})
        assert r_bad.status_code == 403

        # Allowlisted binary properly awaited (returns SandboxResult dict, not coroutine)
        r_ok = client.post("/api/sandbox/run", json={"command": ["nmap", "--version"]})
        assert r_ok.status_code == 200, r_ok.text
        body = r_ok.json()
        assert body["ok"] is True
        assert body["stdout"] == "awaited-ok"
        assert body["exit_code"] == 0


def test_burp_repeater_blocks_internal_metadata_and_non_http_proxies():
    for bad_proxy in (
        "http://169.254.169.254:80",
        "http://metadata.google.internal:80",
        "http://10.0.0.5:3128",
        "http://192.168.1.1:8080",
        "http://127.0.0.1:6379",
        "socks5://127.0.0.1:1080",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379",
    ):
        ok, _reason = validate_proxy_url(bad_proxy)
        assert ok is False, f"validate_proxy_url failed to reject {bad_proxy}"

    with ASGISyncClient() as client:
        for bad_proxy in (
            "http://169.254.169.254:80",
            "http://127.0.0.1:6379",
            "socks5://127.0.0.1:1080",
            "http://10.0.0.1:3128",
        ):
            resp = client.post(
                "/api/burp/repeater/send",
                json={
                    "url": "https://example.com/",
                    "method": "GET",
                    "scope": ["example.com"],
                    "use_proxy": True,
                    "proxy": bad_proxy,
                },
            )
            assert resp.status_code == 403, f"Repeater failed to block proxy {bad_proxy}: {resp.status_code}"
            assert resp.json().get("status") == "BLOCKED_PROXY"


# ---------------------------------------------------------------------------
# 5. legacy_api_chat_view No Auto-Exec & SettingsSaveView OLLAMA_HOST Validation
# ---------------------------------------------------------------------------


def test_legacy_api_chat_never_auto_executes_bash_blocks(isolated_platform_client, monkeypatch):
    import hunter_backend.apps.copilot_api as copilot_api

    executed_calls: list[str] = []

    async def _should_never_run(cmd, timeout_s=60.0):
        executed_calls.append(str(cmd))
        return {"stdout": "SHOULD NOT RUN", "stderr": "", "returncode": 0}

    async def _fake_ai(msg, provider=None, model=None, system_prompt=None):
        return (
            "Here is a scan:\n```bash\n"
            "nmap -sV example.com\n"
            "python3 -c 'import os'\n"
            "curl https://example.com\n"
            "```"
        )

    monkeypatch.setattr(copilot_api, "run_command_no_shell", _should_never_run)
    monkeypatch.setattr(copilot_api, "call_ai", _fake_ai)

    # 1. Default call: allow_exec=False, authorized=False -> nothing executed or queued
    r_default = isolated_platform_client.post(
        "/api/chat",
        json={"message": "scan example.com", "target": "example.com", "scope": ["example.com"]},
    )
    assert r_default.status_code == 200
    d_def = r_default.json()
    assert d_def["allow_exec"] is False
    assert d_def["authorized"] is False
    assert d_def["executed"] == []
    assert executed_calls == []

    # 2. Even with allow_exec=True & authorized=True, bash blocks are NEVER auto-executed:
    #    forbidden tools (python3, curl) are blocked; allowlisted nmap is queued for HITL approval
    r_req = isolated_platform_client.post(
        "/api/chat",
        json={
            "message": "scan example.com",
            "target": "example.com",
            "scope": ["example.com"],
            "allow_exec": True,
            "authorized": True,
        },
    )
    assert r_req.status_code == 200
    d_req = r_req.json()
    assert d_req["executed"] == []
    assert executed_calls == []
    assert len(d_req["queued_approvals"]) == 1
    assert d_req["queued_approvals"][0]["tool_name"] == "nmap"
    assert d_req["queued_approvals"][0]["status"] == "pending"
    assert len(d_req["blocked"]) == 2


def test_settings_save_validates_ollama_host_and_requires_operator_tier(tmp_path, monkeypatch):
    import hunter_backend.apps.copilot_api as copilot_api

    written_env: dict[str, str] = {}
    monkeypatch.setattr(copilot_api, "write_env_file", lambda updates: written_env.update(updates))

    with ASGISyncClient() as client:
        for bad_host in (
            "http://169.254.169.254/latest",
            "http://metadata.google.internal",
            "file:///etc/passwd",
            "http://evil.attacker.example:11434",
            "http://127.0.0.1:11434/api/evil",
        ):
            r_bad = client.post("/api/settings/save", json={"ollama_host": bad_host})
            assert r_bad.status_code == 400, f"Expected 400 for ollama_host={bad_host!r}, got {r_bad.status_code}"
        assert "OLLAMA_HOST" not in written_env

        r_ok = client.post("/api/settings/save", json={"ollama_host": "http://127.0.0.1:11434"})
        assert r_ok.status_code == 200
        assert written_env["OLLAMA_HOST"] == "http://127.0.0.1:11434"


# ---------------------------------------------------------------------------
# 6. Approvals: proposal_digest Tamper Detection, Display Separation & Identity Binding
# ---------------------------------------------------------------------------


def test_approval_proposal_digest_tamper_rejection_and_display_separation(isolated_platform_client, tmp_path):
    import core.platform_store as ps
    from hunter_backend.runtime import execute_approved_action

    store = ps.get_platform_store()

    eng = isolated_platform_client.post(
        "/api/platform/engagements",
        json={
            "name": "Integrity Test",
            "target": "https://app.example.com",
            "in_scope": ["app.example.com"],
            "set_active": True,
        },
    ).json()["engagement"]
    eid = eng["engagement_id"]

    # Raw execution args with Bearer token are NOT corrupted, while display_command_args IS redacted
    raw_args = "-H Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig app.example.com"
    apr = store.create_approval(
        action_type="RUN_TOOL",
        target="https://app.example.com/api",
        tool_name="nmap",
        command_args=raw_args,
        engagement_id=eid,
        rationale="Header-bearing test",
    )
    assert apr["command_args"] == raw_args
    assert "eyJhbGciOiJIUzI1NiJ9.payload.sig" not in apr["display_command_args"]
    assert (
        "[MASKED" in apr["display_command_args"]
        or "[REDACTED" in apr["display_command_args"]
        or "••••" in apr["display_command_args"]
    )
    assert len(apr["proposal_digest"]) == 64
    assert verify_proposal_digest(apr) is True

    # Tamper with command_args directly in SQLite -> decide endpoint MUST reject with 403
    with store._lock:
        store._conn.execute(
            "UPDATE approvals SET command_args = ? WHERE approval_id = ?",
            ("-sV evil-tampered.example.com", apr["approval_id"]),
        )
        store._conn.commit()

    tampered_row = store.get_approval(apr["approval_id"])
    assert tampered_row is not None
    assert verify_proposal_digest(tampered_row) is False

    r_tamper = isolated_platform_client.post(
        f"/api/platform/approvals/{apr['approval_id']}/decide",
        json={"decision": "approved", "decided_by": "spoofed_admin"},
    )
    assert r_tamper.status_code == 403
    assert r_tamper.json().get("error") == "proposal_digest_mismatch"
    assert store.get_approval(apr["approval_id"])["status"] == "rejected"

    # Direct execute_approved_action rejects tampered digest AND invalid payload kind/mode
    with pytest.raises(PermissionError, match="proposal_digest"):
        asyncio.run(execute_approved_action(tampered_row))

    bad_kind_apr = store.create_approval(
        action_type="platform_run",
        target="https://app.example.com",
        tool_name="",
        command_args="",
        engagement_id=eid,
        payload={"kind": "arbitrary_shell_exec", "mode": "full"},
    )
    with pytest.raises(PermissionError, match="kind"):
        asyncio.run(execute_approved_action(bad_kind_apr))

    bad_mode_apr = store.create_approval(
        action_type="platform_run",
        target="https://app.example.com",
        tool_name="",
        command_args="",
        engagement_id=eid,
        payload={"kind": "pipeline", "mode": "rm -rf /"},
    )
    with pytest.raises(PermissionError, match="mode"):
        asyncio.run(execute_approved_action(bad_mode_apr))

    # Caller-supplied decided_by cannot spoof identity
    clean_apr = store.create_approval(
        action_type="RUN_TOOL",
        target="https://app.example.com",
        tool_name="nmap",
        command_args="app.example.com",
        engagement_id=eid,
    )
    r_rej = isolated_platform_client.post(
        f"/api/platform/approvals/{clean_apr['approval_id']}/decide",
        json={"decision": "rejected", "decided_by": "evil-spoofed-identity"},
    )
    assert r_rej.status_code == 200
    decided_by = r_rej.json()["approval"]["decided_by"]
    assert "evil-spoofed-identity" not in decided_by
    assert "operator" in decided_by


# ---------------------------------------------------------------------------
# 7. BugHunter MCP PolicyEngine Hardening
# ---------------------------------------------------------------------------


def test_bughunter_mcp_blocks_approve_flag_and_scope_mutation(monkeypatch):
    PolicyEngine, DecisionKind = _load_bughunter_mcp_policy_engine()

    monkeypatch.delenv("BBHUNT_MCP_APPROVE", raising=False)
    monkeypatch.setenv("BBHUNT_MCP_APPROVAL_TOKEN", "server-side-secret-token-value")

    engine = PolicyEngine(domains=["example.com", "*.example.com"], auto_approve=False)

    # 1. Passing args["approve"] = True MUST NOT bypass approval gate
    dec_bypass = engine.authorize_tool(
        "bughunter_hunt",
        {"target": "https://app.example.com", "approve": True},
    )
    assert dec_bypass.kind != DecisionKind.ALLOW

    # 2. Passing args["scope_domains"] MUST NOT widen/mutate server-side scope
    dec_scope = engine.authorize_tool(
        "bughunter_hunt",
        {
            "target": "https://evil.attacker.org",
            "scope_domains": ["evil.attacker.org"],
            "approval_token": "server-side-secret-token-value",
        },
    )
    assert dec_scope.kind == DecisionKind.BLOCK
    assert "evil.attacker.org" not in engine._domains

    # 3. Wrong approval_token fails; valid approval_token on in-scope target succeeds
    dec_wrong = engine.authorize_tool(
        "bughunter_hunt",
        {"target": "https://app.example.com", "approval_token": "wrong-token"},
    )
    assert dec_wrong.kind != DecisionKind.ALLOW

    dec_ok = engine.authorize_tool(
        "bughunter_hunt",
        {"target": "https://app.example.com", "approval_token": "server-side-secret-token-value"},
    )
    assert dec_ok.kind == DecisionKind.ALLOW


# ---------------------------------------------------------------------------
# 8. BurpGateway Loopback Bind & Timing-Safe Token Auth
# ---------------------------------------------------------------------------


def test_burp_gateway_auth_and_loopback_enforcement(tmp_path, monkeypatch):
    store = CaptureStore("test_auth", base_dir=tmp_path)

    # Non-loopback bind is rejected by default
    monkeypatch.delenv("HUNTER_BURP_GATEWAY_ALLOW_REMOTE", raising=False)
    with pytest.raises(ValueError, match="non-loopback"):
        BurpGateway(host="0.0.0.0", port=8085, capture_store=store)

    # Configured token enforces X-Hunter-Token / Authorization: Bearer on API routes
    gw = BurpGateway(
        host="127.0.0.1",
        port=8085,
        capture_store=store,
        api_token="burp-gw-secret-token-32bytes-xyz",
    )
    client = TestClient(gw.app)

    # /health stays readable without token
    assert client.get("/health").status_code == 200

    # Protected routes fail closed 401 without token or with wrong token
    assert client.get("/api/tasks").status_code == 401
    assert client.post("/api/scope", json={"host": "example.com"}).status_code == 401
    assert client.get("/api/tasks", headers={"X-Hunter-Token": "wrong"}).status_code == 401
    assert client.get("/api/tasks", headers={"Authorization": "Bearer wrong"}).status_code == 401

    # Valid X-Hunter-Token and Authorization: Bearer both succeed
    assert client.get("/api/tasks", headers={"X-Hunter-Token": "burp-gw-secret-token-32bytes-xyz"}).status_code == 200
    assert (
        client.post(
            "/api/scope",
            json={"host": "example.com"},
            headers={"Authorization": "Bearer burp-gw-secret-token-32bytes-xyz"},
        ).status_code
        == 200
    )


# ---------------------------------------------------------------------------
# 9. BugHunter Brain shell=False, Shell TLS Defaults, Supply Chain & Docs
# ---------------------------------------------------------------------------


def test_bughunter_brain_shell_false_and_env_allowlist(monkeypatch):
    brain_src = (REPO_ROOT / "bughunter" / "brain.py").read_text(encoding="utf-8")
    assert "shell=True" not in brain_src

    spec = importlib.util.spec_from_file_location("bughunter_brain_mod", REPO_ROOT / "bughunter" / "brain.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    brain = mod.Brain.__new__(mod.Brain)
    # Shell metacharacters must be refused before any process launches
    rc, _out, err = brain.run_command("echo hi && whoami", require_confirmation=False)
    assert rc == 2
    assert "shell metacharacter" in err.lower()

    # Subprocess must run with shell=False and MUST NOT inherit secret API keys
    monkeypatch.setenv("OPENAI_API_KEY", "sk-must-never-leak-to-child")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-must-never-leak")
    rc2, out2, err2 = brain.run_command(
        [sys.executable, "-c", "print(__import__('os').environ.get('OPENAI_API_KEY', 'CLEAN'))"],
        require_confirmation=False,
    )
    assert rc2 == 0, err2
    assert out2.strip() == "CLEAN"


def test_shell_scripts_tls_defaults_opencode_supply_chain_and_reconciled_docs():
    # 1. Shell tools must not default to curl -k / -sk / -sIk
    for script_name in ("bypass_403.sh", "secrets_hunter.sh", "takeover_scanner.sh", "vuln_scanner.sh"):
        content = (REPO_ROOT / "bughunter" / "tools" / script_name).read_text(encoding="utf-8")
        assert not re.search(r"\bcurl\s+-[A-Za-z]*k", content), f"{script_name} still passes -k by default"
        assert "HUNTER_LAB_INSECURE_TLS" in content
        assert "--insecure" in content

    # 2. opencode.json portable paths, remote MCPs disabled, pinned versions
    oc_text = (REPO_ROOT / "opencode.json").read_text(encoding="utf-8")
    assert "Agant\\PentestAI-Unified" not in oc_text
    assert "Agant/PentestAI-Unified" not in oc_text
    oc = json.loads(oc_text)
    mcp = oc["mcp"]
    assert mcp["context7"]["enabled"] is False
    assert mcp["gh_grep"]["enabled"] is False
    fs_cmd = " ".join(mcp["filesystem"]["command"])
    assert re.search(r"@modelcontextprotocol/server-filesystem@[0-9]+\.[0-9]+\.[0-9]+", fs_cmd)
    azure_cmd = " ".join(mcp["azure-mcp"]["command"])
    assert "@latest" not in azure_cmd

    # 3. install_agent.ps1 no hardcoded /mnt/e/Agant/PentestAI-Unified
    ps1_text = (REPO_ROOT / "install_agent.ps1").read_text(encoding="utf-8")
    assert "/mnt/e/Agant/PentestAI-Unified" not in ps1_text
    assert "E:\\Agant\\PentestAI-Unified" not in ps1_text

    # 4. Security docs reconciled (refuted claims removed)
    sec_md = (REPO_ROOT / "docs" / "security.md").read_text(encoding="utf-8")
    audit_md = (REPO_ROOT / "docs" / "security_audit.md").read_text(encoding="utf-8")
    for refuted in ("ISO/IEC 27001", "GDPR Article 32", "OWASP ASVS v4.0", "ClaudeThinkingEngine"):
        assert refuted not in sec_md, f"Refuted claim still in docs/security.md: {refuted}"
        assert refuted not in audit_md, f"Refuted claim still in docs/security_audit.md: {refuted}"
