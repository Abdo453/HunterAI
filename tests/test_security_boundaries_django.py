"""Comprehensive security boundary verification for Django 5.2 + Pure ASGI backend.

Tests:
1. Fail-closed web governance (`web_governance_enforced()`) even when CLI `HUNTER_UNRESTRICTED=1`
2. Metadata IP, private CIDR, loopback, scheme, and DNS-rebind SSRF blocking on Repeater & scans
3. Path traversal, Windows ADS (`::$DATA`), trailing-dot, `.env`, `.git`, `.policy_secret`, and Artex subpath blocks
4. `ApiCsrfAndJsonGuardMiddleware`: `no-cors` (`text/plain`, `application/x-www-form-urlencoded`),
   untrusted `Origin`, `Sec-Fetch-Site: cross-site`, CSRF double-submit token, and security headers
5. WebSocket `Origin` enforcement (`4403` reject on untrusted origin, accept on allowed origin)
6. Persisted HMAC policy secret in `.policy_secret` & tamper detection for red-team grants
"""
from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest

from core.security_mode import web_governance_enforced
from hunter_backend.asgi import application
from hunter_backend.secrets_util import get_or_create_policy_secret
from hunter_backend.testing import ASGISyncClient


def test_fail_closed_web_governance_under_unrestricted_cli(monkeypatch):
    import hunter_backend.apps.arsenal_api as arsenal_api

    monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
    monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)
    assert web_governance_enforced() is True

    monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "1")
    assert web_governance_enforced() is False

    async def _fake_run(cmd, timeout_s=60.0):
        return {"command": " ".join(cmd), "stdout": "ok", "stderr": "", "returncode": 0}

    monkeypatch.setattr(arsenal_api, "run_command_no_shell", _fake_run)

    # Explicit opt-in web unrestricted mode still enforces non-overridable metadata SSRF
    # while permitting arbitrary websites, local labs, private ranges, and ?url= query params.
    with ASGISyncClient() as client:
        assert (
            client.post(
                "/api/platform/engagements",
                json={"name": "BadMeta", "target": "http://169.254.169.254/latest"},
            ).status_code
            == 403
        )
        for explicit_tgt in (
            "https://any-site.com",
            "http://target.com/?url=http://169.254.169.254",
            "http://localhost:3001",
            "http://127.0.0.1:8080",
            "http://192.168.1.50",
            "http://10.10.10.5",
            "https://enhanced-target.local",
        ):
            chk = client.post("/api/scope/check", json={"target": explicit_tgt})
            assert chk.status_code == 200, explicit_tgt
            assert chk.json()["allowed"] is True, (explicit_tgt, chk.json())

        assert client.post("/api/run-tool", json={"command": "nmap 192.168.1.50"}).status_code == 200
        assert client.post("/api/run-tool", json={"command": "nmap localhost:3001"}).status_code == 200

        # Explicit opt-in strict governance (HUNTER_WEB_UNRESTRICTED=0) restores fail-closed 403
        monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "0")
        assert web_governance_enforced() is True
        for ep, payload in (
            ("/api/platform/engagements", {"name": "Bad", "target": "http://169.254.169.254/latest"}),
            ("/api/platform/runs/start", {"kind": "pipeline", "target": "https://unscoped.example.org"}),
            ("/api/burp/repeater/send", {"url": "https://unscoped.example.org/api", "method": "GET"}),
            ("/api/run-tool", {"command": "nmap unscoped.example.org"}),
            ("/api/browser/browse", {"url": "https://unscoped.example.org"}),
        ):
            r = client.post(ep, json=payload)
            assert r.status_code == 403, f"Expected 403 fail-closed on {ep}, got {r.status_code}: {r.text}"


def test_ssrf_metadata_private_scheme_and_dns_rebind_blocked(monkeypatch):
    monkeypatch.delenv("HUNTER_ALLOW_LOCALHOST_SCOPE", raising=False)
    monkeypatch.delenv("HUNTER_ALLOW_PRIVATE_LAB_SCOPE", raising=False)
    monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)

    non_overridable_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://2852039166/latest/meta-data/",
        "http://0xa9fea9fe/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.internal/latest/",
        "http://instance-data/",
        "http://100.100.100.200/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://[fe80::1]/",
        "http://0.0.0.0:8000/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "javascript:alert(1)",
    ]
    with ASGISyncClient() as client:
        # Non-overridable Cloud Metadata & unsafe schemes stay strictly 403 even in default mode
        for url in non_overridable_urls:
            r = client.post(
                "/api/burp/repeater/send",
                json={"url": url, "method": "GET", "scope": ["169.254.169.254", "localhost", "127.0.0.1", "10.0.0.1"]},
            )
            assert r.status_code == 403, f"SSRF not blocked for {url}: {r.status_code} {r.text}"

        # Destination host is target.com (in scope); metadata literal inside query param must remain ALLOWED
        q_chk = client.post(
            "/api/scope/check",
            json={"target": "http://target.com/?url=http://169.254.169.254", "in_scope": ["target.com"]},
        )
        assert q_chk.status_code == 200
        assert q_chk.json()["allowed"] is True

        # Raw HTTP Repeater request targeting metadata IP via Host header must also fail 403
        raw_meta = client.post(
            "/api/burp/repeater/send",
            json={
                "raw_request": "GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
                "scope": ["example.com"],
            },
        )
        assert raw_meta.status_code == 403

        # DNS rebinding to metadata IP must stay blocked even if domain is in scope
        def _fake_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
        rebind = client.post(
            "/api/burp/repeater/send",
            json={"url": "https://rebind.example.com/api", "method": "GET", "scope": ["example.com", "*.example.com"]},
        )
        assert rebind.status_code == 403

        # Under explicit governed opt-in (HUNTER_WEB_UNRESTRICTED=0), private/loopback targets are also 403
        monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "0")
        for governed_url in (
            "http://10.0.0.1/admin",
            "http://172.16.10.2/",
            "http://192.168.1.1/",
            "http://127.0.0.1:8000/",
            "http://[::1]:8000/",
            "http://localhost:8000/",
        ):
            rg = client.post(
                "/api/burp/repeater/send",
                json={"url": governed_url, "method": "GET", "scope": ["localhost", "127.0.0.1", "10.0.0.1"]},
            )
            assert rg.status_code == 403, f"Governed SSRF not blocked for {governed_url}: {rg.status_code}"


def test_path_traversal_ads_trailing_dot_and_proxy_subpath_blocked():
    blocked_paths = [
        ".env",
        ".env::$DATA",
        ".policy_secret",
        ".django_secret",
        "authorization_grant.json",
        "authorization_grant.json.",
        "tls.key.",
        "tls.key::$DATA",
        ".git/config",
        "../outside_repo/secret.txt",
        "C:\\Windows\\win.ini",
    ]
    with ASGISyncClient() as client:
        for p in blocked_paths:
            assert client.get("/api/editor/file", params={"path": p}).status_code == 403, p
            assert client.post("/api/editor/file/save", json={"path": p, "content": "x"}).status_code == 403, p
            assert client.post("/api/editor/file/create", json={"path": p, "content": "x"}).status_code == 403, p

        assert client.get("/api/editor/tree", params={"folder": "../../etc"}).status_code == 403
        assert client.get("/api/enhanced/reports/..%5c.env").status_code in (400, 403, 404)
        assert client.get("/api/tool_outputs/secret::$DATA").status_code in (400, 403, 404)
        assert client.get("/api/report/bad..id/md").status_code == 400
        assert client.get("/api/report/sess1/exe").status_code == 400

        # Artex proxy subpath traversal / scheme injection blocked
        for bad_sub in ("../../etc/passwd", "%2e%2e/engagements", "http://169.254.169.254/"):
            rp = client.get(f"/api/platform/artex/{bad_sub}")
            assert rp.status_code in (400, 404), f"Unexpected {rp.status_code} for {bad_sub}"


def test_csrf_nocors_content_type_origin_and_security_headers():
    with ASGISyncClient() as client:
        csrf_r = client.get("/api/csrf")
        assert csrf_r.status_code == 200
        token = csrf_r.json()["csrfToken"]
        assert len(token) >= 16

        # Reject no-cors simple Content-Types
        for ctype in ("text/plain", "application/x-www-form-urlencoded"):
            r_ct = client.post(
                "/api/platform/engagements",
                content=b'{"name":"x","target":"https://example.com"}',
                headers={"Content-Type": ctype},
            )
            assert r_ct.status_code in (403, 415), f"Accepted dangerous Content-Type {ctype}: {r_ct.status_code}"

        # Reject cross-origin and Sec-Fetch-Site: cross-site
        r_origin = client.post(
            "/api/platform/engagements",
            json={"name": "BadOrigin", "target": "https://example.com"},
            headers={"Origin": "https://evil.attacker"},
        )
        assert r_origin.status_code == 403

        r_sfs = client.post(
            "/api/platform/engagements",
            json={"name": "BadSFS", "target": "https://example.com"},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r_sfs.status_code == 403

        # Trusted Origin with mismatched CSRF token fails 403; with matching token succeeds
        r_no_csrf = client.put(
            "/api/platform/context",
            json={"extra": {"test": "csrf"}},
            headers={"Origin": "http://127.0.0.1:3000", "X-CSRFToken": "tampered_invalid_csrf_token"},
        )
        assert r_no_csrf.status_code == 403

        r_ok_csrf = client.put(
            "/api/platform/context",
            json={"extra": {"test": "ok"}},
            headers={"Origin": "http://127.0.0.1:3000", "X-CSRFToken": token},
        )
        assert r_ok_csrf.status_code == 200
        assert r_ok_csrf.headers.get("x-content-type-options") == "nosniff"
        assert r_ok_csrf.headers.get("x-frame-options") == "SAMEORIGIN"
        csp = r_ok_csrf.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "object-src 'none'" in csp
        assert "fonts.googleapis.com" not in csp


def test_websocket_origin_4403_enforcement():
    async def _ws_probe(path: str, origin: str):
        in_q: asyncio.Queue = asyncio.Queue()
        out_q: asyncio.Queue = asyncio.Queue()
        await in_q.put({"type": "websocket.connect"})

        scope = {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "path": path,
            "headers": [(b"origin", origin.encode("utf-8"))],
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

    rejected = asyncio.run(_ws_probe("/ws/platform", "https://evil.attacker"))
    assert rejected["type"] == "websocket.close"
    assert rejected["code"] == 4403

    accepted = asyncio.run(_ws_probe("/ws/platform", "http://127.0.0.1:3000"))
    assert accepted["type"] == "websocket.accept"


def test_hmac_policy_secret_persists_and_detects_tampering(tmp_path, monkeypatch):
    import hunter_backend.apps.arsenal_api as arsenal_api
    import hunter_backend.secrets_util as su

    root_dir = tmp_path / "data" / "root_controller"
    grant_path = root_dir / "grant.json"
    monkeypatch.setattr(su, "BASE_DIR", tmp_path)
    monkeypatch.delenv("HUNTERAI_POLICY_SECRET", raising=False)
    monkeypatch.delenv("HUNTER_POLICY_SECRET", raising=False)
    monkeypatch.setattr(arsenal_api, "GRANT_PATH", grant_path)

    s1 = get_or_create_policy_secret()
    assert len(s1) >= 32
    assert (root_dir / ".policy_secret").is_file()
    s2 = get_or_create_policy_secret()
    assert s1 == s2

    with ASGISyncClient() as client:
        issued = client.post(
            "/api/control/redteam-policy/issue",
            json={"scope": "example.com", "authorized_by": "Security Audit", "days": 1},
        )
        assert issued.status_code == 200
        assert issued.json()["active"] is True

        status_ok = client.get("/api/control/redteam-policy").json()
        assert status_ok["active"] is True
        assert status_ok["valid_signature"] is True

        # Tampering with grant scope breaks HMAC signature verification
        raw = json.loads(grant_path.read_text(encoding="utf-8"))
        raw["authorized_by"] = "TamperedAttacker"
        grant_path.write_text(json.dumps(raw), encoding="utf-8")

        status_bad = client.get("/api/control/redteam-policy").json()
        assert status_bad["active"] is False
        assert status_bad["valid_signature"] is False


def test_approval_decide_unmocked_gateway_and_scope_boundaries(isolated_platform_client, monkeypatch):
    """Un-mocked GovernedToolGateway + PolicyEngine regression coverage for /api/platform/approvals/<id>/decide."""
    import shutil
    import sys
    import core.platform_store as ps

    store = ps.get_platform_store()

    # 1. Explicit engagement for 127.0.0.1 and example.com under opt-in web unrestricted mode
    monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "1")
    eng_resp = isolated_platform_client.post(
        "/api/platform/engagements",
        json={
            "name": "Unmocked Lab",
            "target": "http://127.0.0.1:8080",
            "in_scope": ["127.0.0.1", "example.com"],
            "out_of_scope": ["127.0.0.1:8080/logout", "blocked.example.com"],
            "set_active": True,
        },
    )
    assert eng_resp.status_code == 201, eng_resp.text
    eid = eng_resp.json()["engagement_id"]

    # 1b. Default explicit-target mode allows unscoped/out-of-scope targets, while blocking metadata & shell injection
    py_tool = "python" if shutil.which("python") else ("python3" if shutil.which("python3") else Path(sys.executable).name)
    meta_apr = store.create_approval(
        action_type="RUN_TOOL",
        target="http://169.254.169.254/latest/meta-data/",
        tool_name=py_tool,
        command_args="-V",
        engagement_id=None,
        rationale="Metadata blocked in default mode",
    )
    assert (
        isolated_platform_client.post(
            f"/api/platform/approvals/{meta_apr['approval_id']}/decide",
            json={"decision": "approved"},
        ).status_code
        == 403
    )
    inj_apr = store.create_approval(
        action_type="RUN_TOOL",
        target="https://example.com/api",
        tool_name=py_tool,
        command_args="-V && whoami",
        engagement_id=None,
        rationale="Shell injection blocked in default mode",
    )
    assert (
        isolated_platform_client.post(
            f"/api/platform/approvals/{inj_apr['approval_id']}/decide",
            json={"decision": "approved"},
        ).status_code
        == 403
    )
    default_unscoped_apr = store.create_approval(
        action_type="RUN_TOOL",
        target="https://any-site.com/api",
        tool_name=py_tool,
        command_args="-V",
        engagement_id=None,
        rationale="Explicit target allowed without prior scope by default",
    )
    def_res = isolated_platform_client.post(
        f"/api/platform/approvals/{default_unscoped_apr['approval_id']}/decide",
        json={"decision": "approved"},
    )
    assert def_res.status_code == 200, def_res.text
    assert def_res.json()["execution"]["executed"] is True

    # 2. Under strict web governance (HUNTER_WEB_UNRESTRICTED=0), SSRF metadata, RFC1918, excluded path,
    #    and unscoped approvals fail 403 BEFORE 'approved' is persisted
    monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "0")
    monkeypatch.setenv("HUNTER_ALLOW_LOCALHOST_SCOPE", "1")
    for label, case_eid, tgt, cmd in (
        ("metadata", eid, "http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/"),
        ("rfc1918", eid, "http://10.0.0.1/admin", "http://10.0.0.1/admin"),
        ("excluded_path", eid, "http://127.0.0.1:8080/logout", "http://127.0.0.1:8080/logout"),
        ("out_of_scope", eid, "https://blocked.example.com/api", "https://blocked.example.com/api"),
        ("unscoped", None, "https://example.com/api", "https://example.com/api"),
    ):
        apr = store.create_approval(
            action_type="RUN_TOOL",
            target=tgt,
            tool_name="python",
            command_args=cmd,
            engagement_id=case_eid,
            rationale=f"Negative unmocked check: {label}",
        )
        res = isolated_platform_client.post(
            f"/api/platform/approvals/{apr['approval_id']}/decide",
            json={"decision": "approved"},
        )
        assert res.status_code == 403, f"Expected 403 for {label}, got {res.status_code}: {res.text}"
        persisted = store.get_approval(apr["approval_id"])
        assert persisted is not None
        assert persisted["status"] == "rejected"

    # 3. With HUNTER_ALLOW_LOCALHOST_SCOPE disabled under governed mode, loopback approval fails 403 before approval persists
    monkeypatch.delenv("HUNTER_ALLOW_LOCALHOST_SCOPE", raising=False)
    loop_apr = store.create_approval(
        action_type="RUN_TOOL",
        target="http://127.0.0.1:8080/api/item",
        tool_name="python",
        command_args="-V",
        engagement_id=eid,
        rationale="Loopback without opt-in",
    )
    loop_res = isolated_platform_client.post(
        f"/api/platform/approvals/{loop_apr['approval_id']}/decide",
        json={"decision": "approved"},
    )
    assert loop_res.status_code == 403
    assert store.get_approval(loop_apr["approval_id"])["status"] == "rejected"

    # 4. With HUNTER_ALLOW_LOCALHOST_SCOPE=1, un-mocked GovernedToolGateway executes real command without HTTP 500
    monkeypatch.setenv("HUNTER_ALLOW_LOCALHOST_SCOPE", "1")
    ok_apr = store.create_approval(
        action_type="RUN_TOOL",
        target="http://127.0.0.1:8080/api/item",
        tool_name=py_tool,
        command_args="-V",
        engagement_id=eid,
        rationale="Unmocked scoped command execution",
    )
    ok_res = isolated_platform_client.post(
        f"/api/platform/approvals/{ok_apr['approval_id']}/decide",
        json={"decision": "approved", "note": "Unmocked gateway pass"},
    )
    assert ok_res.status_code == 200, ok_res.text
    body = ok_res.json()
    assert body["decision"] == "approved"
    assert body["approval"]["status"] == "approved"
    assert body["execution"]["blocked"] is False
    assert body["execution"]["executed"] is True
    assert body["execution"]["returncode"] == 0
    assert "python" in (body["execution"]["stdout_excerpt"] + body["execution"]["stderr_excerpt"]).lower()

    # 5. Missing binary on an approved scoped target returns clean 200 (executed=False), never HTTP 500
    missing_apr = store.create_approval(
        action_type="RUN_TOOL",
        target="https://app.example.com",
        tool_name="nonexistent_hunter_probe_bin",
        command_args="app.example.com",
        engagement_id=eid,
        rationale="Missing binary should not 500",
    )
    miss_res = isolated_platform_client.post(
        f"/api/platform/approvals/{missing_apr['approval_id']}/decide",
        json={"decision": "approved"},
    )
    assert miss_res.status_code == 200, miss_res.text
    miss_body = miss_res.json()
    assert miss_body["decision"] == "approved"
    assert miss_body["execution"]["blocked"] is False
    assert miss_body["execution"]["executed"] is False


def _start_local_lab_http_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class _LabHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            return

        def do_GET(self):
            body = b'{"lab":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, port, thread


def test_localhost_lab_override_allows_localhost_while_blocking_metadata(isolated_platform_client, monkeypatch):
    from core.copilot_service import evaluate_action_policy

    monkeypatch.delenv("HUNTER_ALLOW_LOCALHOST_SCOPE", raising=False)
    monkeypatch.delenv("HUNTER_ALLOW_PRIVATE_LAB_SCOPE", raising=False)
    monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "0")

    srv, port, thread = _start_local_lab_http_server()
    try:
        # 1. Default fail-closed rejects localhost even when in scope
        assert (
            isolated_platform_client.post(
                "/api/platform/engagements",
                json={"name": "Blocked Localhost", "target": f"http://localhost:{port}", "in_scope": ["localhost"]},
            ).status_code
            == 403
        )
        assert (
            isolated_platform_client.post(
                "/api/burp/repeater/send",
                json={"url": f"http://localhost:{port}/", "method": "GET", "scope": ["localhost"]},
            ).status_code
            == 403
        )

        # 2. With HUNTER_ALLOW_LOCALHOST_SCOPE=1 + explicit 'localhost' in scope -> allowed
        monkeypatch.setenv("HUNTER_ALLOW_LOCALHOST_SCOPE", "1")
        eng = isolated_platform_client.post(
            "/api/platform/engagements",
            json={
                "name": "Localhost Lab",
                "target": f"http://localhost:{port}",
                "in_scope": ["localhost"],
                "set_active": True,
            },
        )
        assert eng.status_code == 201, eng.text

        run_r = isolated_platform_client.post(
            "/api/platform/runs/start",
            json={"kind": "pipeline", "target": f"http://localhost:{port}", "engagement_id": eng.json()["engagement_id"]},
        )
        assert run_r.status_code == 200, run_r.text
        isolated_platform_client.post(f"/api/platform/runs/{run_r.json()['run_id']}/stop")

        rep_ok = isolated_platform_client.post(
            "/api/burp/repeater/send",
            json={"url": f"http://localhost:{port}/health", "method": "GET", "scope": ["localhost"]},
        )
        assert rep_ok.status_code == 200, rep_ok.text
        assert rep_ok.json()["status_code"] == 200

        chk = isolated_platform_client.post(
            "/api/scope/check",
            json={"target": f"http://localhost:{port}/api", "in_scope": ["localhost"]},
        )
        assert chk.status_code == 200
        assert chk.json()["allowed"] is True

        pol_ok = evaluate_action_policy(
            action_type="CLI_TOOL",
            target=f"http://localhost:{port}",
            tool_name="nmap",
            in_scope=["localhost"],
        )
        assert pol_ok["allowed"] is True

        # Unscoped localhost.localdomain or wildcard '*' must still stay 403
        assert (
            isolated_platform_client.post(
                "/api/burp/repeater/send",
                json={"url": f"http://localhost.localdomain:{port}/", "method": "GET", "scope": ["localhost"]},
            ).status_code
            == 403
        )
        assert (
            isolated_platform_client.post(
                "/api/burp/repeater/send",
                json={"url": f"http://localhost:{port}/", "method": "GET", "scope": ["*"]},
            ).status_code
            == 403
        )

        # 3. Non-overridable metadata/link-local/scheme/shell/rebind remain strictly 403
        non_overridable_urls = [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.internal/latest/",
            "http://instance-data/latest/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://2852039166/latest/meta-data/",
            "http://0xa9fea9fe/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[fe80::1]/",
            "http://0.0.0.0:8000/",
            "http://224.0.0.1/",
            "http://240.0.0.1/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://example.com/archive.tar.gz",
            "javascript:alert(1)",
        ]
        for bad_url in non_overridable_urls:
            r_bad = isolated_platform_client.post(
                "/api/burp/repeater/send",
                json={
                    "url": bad_url,
                    "method": "GET",
                    "scope": [
                        "localhost",
                        "metadata.google.internal",
                        "metadata.internal",
                        "instance-data",
                        "169.254.169.254",
                        "100.100.100.200",
                        "fd00:ec2::254",
                        "0.0.0.0",
                    ],
                },
            )
            assert r_bad.status_code == 403, f"Expected 403 for {bad_url}, got {r_bad.status_code}: {r_bad.text}"

        assert (
            isolated_platform_client.post(
                "/api/run-tool",
                json={"command": "nmap localhost; id", "scope": ["localhost"]},
            ).status_code
            == 403
        )

        # DNS rebind from domain to 127.0.0.1 or 169.254.169.254 must stay 403
        for rebind_ip in ("127.0.0.1", "169.254.169.254"):
            monkeypatch.setattr(
                socket,
                "getaddrinfo",
                lambda host, p, *a, _ip=rebind_ip, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_ip, p))],
            )
            rebind_r = isolated_platform_client.post(
                "/api/burp/repeater/send",
                json={"url": "https://rebind.example.com/api", "method": "GET", "scope": ["example.com", "*.example.com", "localhost"]},
            )
            assert rebind_r.status_code == 403, f"DNS rebind to {rebind_ip} should return 403"
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=3.0)


def test_private_lab_scope_override_explicit_ip_and_cidr(isolated_platform_client, monkeypatch):
    from core.copilot_service import evaluate_action_policy

    monkeypatch.delenv("HUNTER_ALLOW_LOCALHOST_SCOPE", raising=False)
    monkeypatch.delenv("HUNTER_ALLOW_PRIVATE_LAB_SCOPE", raising=False)
    monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "0")

    # 1. Default fail-closed blocks private lab targets even when listed in scope
    assert (
        isolated_platform_client.post(
            "/api/platform/engagements",
            json={"name": "Blocked LAN", "target": "http://192.168.1.50:8080", "in_scope": ["192.168.1.50"]},
        ).status_code
        == 403
    )

    # 2. Enable HUNTER_ALLOW_PRIVATE_LAB_SCOPE=1 -> explicit IP & explicit CIDR allowed; unscoped IP still 403
    monkeypatch.setenv("HUNTER_ALLOW_PRIVATE_LAB_SCOPE", "1")

    eng_ip = isolated_platform_client.post(
        "/api/platform/engagements",
        json={
            "name": "LAN Single Host",
            "target": "http://192.168.1.50:8080",
            "in_scope": ["192.168.1.50"],
            "set_active": True,
        },
    )
    assert eng_ip.status_code == 201, eng_ip.text

    eng_cidr = isolated_platform_client.post(
        "/api/platform/engagements",
        json={
            "name": "VPN Subnet Lab",
            "target": "http://10.10.10.5:3000",
            "in_scope": ["10.10.10.0/24"],
        },
    )
    assert eng_cidr.status_code == 201, eng_cidr.text

    chk_cidr = isolated_platform_client.post(
        "/api/scope/check",
        json={"target": "http://10.10.10.5:3000/api", "in_scope": ["10.10.10.0/24"]},
    )
    assert chk_cidr.status_code == 200
    assert chk_cidr.json()["allowed"] is True

    pol_cidr = evaluate_action_policy(
        action_type="CLI_TOOL",
        target="http://10.10.10.5:3000",
        tool_name="nmap",
        in_scope=["10.10.10.0/24"],
    )
    assert pol_cidr["allowed"] is True

    # Unscoped private IP (192.168.1.99), wildcard '*', supernet '0.0.0.0/0', and loopback stay 403
    for bad_payload in (
        {"name": "Unscoped LAN", "target": "http://192.168.1.99:8080", "in_scope": ["192.168.1.50"]},
        {"name": "Wildcard LAN", "target": "http://192.168.1.50:8080", "in_scope": ["*"]},
        {"name": "Supernet LAN", "target": "http://192.168.1.50:8080", "in_scope": ["0.0.0.0/0"]},
        {"name": "Loopback Not Opted", "target": "http://127.0.0.1:8080", "in_scope": ["127.0.0.1"]},
        {"name": "Meta IP", "target": "http://169.254.169.254/latest", "in_scope": ["169.254.169.254"]},
        {"name": "Alibaba Meta", "target": "http://100.100.100.200/latest", "in_scope": ["100.64.0.0/10", "100.100.100.200"]},
        {"name": "EC2 IPv6 Meta", "target": "http://[fd00:ec2::254]/latest", "in_scope": ["fd00:ec2::254"]},
    ):
        r_bad = isolated_platform_client.post("/api/platform/engagements", json=bad_payload)
        assert r_bad.status_code == 403, f"Expected 403 for {bad_payload}, got {r_bad.status_code}: {r_bad.text}"

    # DNS rebind from domain to private IP stays 403
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, p, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", p))],
    )
    rebind_priv = isolated_platform_client.post(
        "/api/burp/repeater/send",
        json={"url": "https://rebind.example.com/api", "method": "GET", "scope": ["example.com", "192.168.1.50"]},
    )
    assert rebind_priv.status_code == 403


def test_web_unrestricted_mode_allows_public_and_labs_keeps_metadata_403(isolated_platform_client, monkeypatch):
    import hunter_backend.apps.arsenal_api as arsenal_api

    monkeypatch.delenv("HUNTER_ALLOW_LOCALHOST_SCOPE", raising=False)
    monkeypatch.delenv("HUNTER_ALLOW_PRIVATE_LAB_SCOPE", raising=False)
    monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
    monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)
    assert web_governance_enforced() is True
    monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "1")
    assert web_governance_enforced() is False

    async def _fake_run(cmd, timeout_s=60.0):
        return {"command": " ".join(cmd), "stdout": "ok", "stderr": "", "returncode": 0}

    monkeypatch.setattr(arsenal_api, "run_command_no_shell", _fake_run)

    srv, port, thread = _start_local_lab_http_server()
    try:
        # 1. Default explicit-target mode allows arbitrary public websites, .local, localhost,
        #    private lab ranges, and ?url= query payloads even with zero engagement or active restrictive scope
        eng_restrict = isolated_platform_client.post(
            "/api/platform/engagements",
            json={
                "name": "Restrictive Workspace",
                "target": "https://primary.example",
                "in_scope": ["primary.example"],
                "out_of_scope": ["blocked.example.com", "*/logout"],
                "set_active": True,
            },
        )
        assert eng_restrict.status_code == 201

        for tgt in (
            "https://any-site.com",
            "https://enhanced-target.local",
            "http://target.com/?url=http://169.254.169.254",
            "http://localhost:3001",
            f"http://127.0.0.1:{port}",
            "http://192.168.1.50:8080",
            "http://10.10.10.5:3000",
        ):
            run_pub = isolated_platform_client.post(
                "/api/platform/runs/start",
                json={"kind": "pipeline", "target": tgt},
            )
            assert run_pub.status_code == 200, (tgt, run_pub.text)
            isolated_platform_client.post(f"/api/platform/runs/{run_pub.json()['run_id']}/stop")

        rep_loop = isolated_platform_client.post(
            "/api/burp/repeater/send",
            json={"url": f"http://localhost:{port}/lab", "method": "GET"},
        )
        assert rep_loop.status_code == 200, rep_loop.text
        assert rep_loop.json()["status_code"] == 200

        # Explicit out_of_scope on engagement or payload does NOT block explicit target in default mode
        rep_logout = isolated_platform_client.post(
            "/api/burp/repeater/send",
            json={
                "url": f"http://127.0.0.1:{port}/logout",
                "method": "GET",
                "out_of_scope": ["blocked.example.com", "*/logout"],
            },
        )
        assert rep_logout.status_code == 200, rep_logout.text

        eng_priv = isolated_platform_client.post(
            "/api/platform/engagements",
            json={"name": "Unrestricted LAN", "target": "http://192.168.1.50:8080"},
        )
        assert eng_priv.status_code == 201, eng_priv.text

        chk_priv = isolated_platform_client.post(
            "/api/scope/check",
            json={"target": "http://10.10.10.5:3000", "out_of_scope": ["10.10.10.5"]},
        )
        assert chk_priv.status_code == 200
        assert chk_priv.json()["allowed"] is True

        tool_ok = isolated_platform_client.post(
            "/api/run-tool",
            json={"command": "nmap 192.168.1.50"},
        )
        assert tool_ok.status_code == 200, tool_ok.text

        # Explicit HUNTER_WEB_UNRESTRICTED=1 behaves identically
        monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "1")
        assert web_governance_enforced() is False

        # 2. Non-overridable Cloud Metadata, link-local, 0.0.0.0, schemes, shell metachars, and DNS rebind MUST stay 403
        still_blocked = [
            "http://169.254.169.254/latest/meta-data/",
            "http://[::ffff:169.254.169.254]/latest/meta-data/",
            "http://2852039166/latest/meta-data/",
            "http://0xa9fea9fe/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.internal/latest/",
            "http://instance-data/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "http://[fe80::1]/",
            "http://0.0.0.0:8000/",
            "http://224.0.0.1/",
            "http://240.0.0.1/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "ftp://example.com/file",
            "javascript:alert(1)",
        ]
        for bad_url in still_blocked:
            r_rep = isolated_platform_client.post(
                "/api/burp/repeater/send",
                json={"url": bad_url, "method": "GET"},
            )
            assert r_rep.status_code == 403, f"Unrestricted web failed to block {bad_url}: {r_rep.status_code}"

        assert (
            isolated_platform_client.post(
                "/api/run-tool",
                json={"command": "nmap example.com && whoami"},
            ).status_code
            == 403
        )

        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda host, p, *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", p))],
        )
        rebind_meta = isolated_platform_client.post(
            "/api/burp/repeater/send",
            json={"url": "https://rebind.example.com/api", "method": "GET"},
        )
        assert rebind_meta.status_code == 403
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join(timeout=3.0)
