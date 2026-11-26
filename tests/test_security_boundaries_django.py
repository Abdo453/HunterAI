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
    monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
    monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)
    assert web_governance_enforced() is True

    with ASGISyncClient() as client:
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

    blocked_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://2852039166/latest/meta-data/",
        "http://0xa9fea9fe/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://10.0.0.1/admin",
        "http://172.16.10.2/",
        "http://192.168.1.1/",
        "http://127.0.0.1:8000/",
        "http://[::1]:8000/",
        "http://localhost:8000/",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ]
    with ASGISyncClient() as client:
        for url in blocked_urls:
            r = client.post(
                "/api/burp/repeater/send",
                json={"url": url, "method": "GET", "scope": ["169.254.169.254", "localhost", "127.0.0.1", "10.0.0.1"]},
            )
            assert r.status_code == 403, f"SSRF not blocked for {url}: {r.status_code} {r.text}"

        # Raw HTTP Repeater request targeting metadata IP via Host header must also fail 403
        raw_meta = client.post(
            "/api/burp/repeater/send",
            json={
                "raw_request": "GET /latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
                "scope": ["example.com"],
            },
        )
        assert raw_meta.status_code == 403

        # DNS rebinding to loopback/metadata IP must be blocked even if domain is in scope
        def _fake_getaddrinfo(host, port, *args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]

        monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
        rebind = client.post(
            "/api/burp/repeater/send",
            json={"url": "https://rebind.example.com/api", "method": "GET", "scope": ["example.com", "*.example.com"]},
        )
        assert rebind.status_code == 403


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
