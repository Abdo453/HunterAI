"""Comprehensive smoke & security verification for HunterAI Django 5.2 + DRF + ASGI backend."""

from __future__ import annotations

import ast
import asyncio
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, List

import httpx
import pytest
from django.urls import get_resolver

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hunter_backend.settings")
os.environ.setdefault(
    "HUNTERAI_DJANGO_SECRET",
    "pytest-ephemeral-django-secret-key-for-smoke-suite-32b",
)

from hunter_backend.asgi import application  # noqa: E402
from hunter_backend.runtime import shutdown_runtime, startup_runtime  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_smoke_platform_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate PlatformStore DB, data paths, and runtime globals away from live repo state."""
    import core.platform_store as ps
    from core.cost_budget import GLOBAL_COST_CONTROLLER
    from core.run_control import GLOBAL_RUN_CONTROLLER
    import hunter_backend.apps.arsenal_api as arsenal_api
    import hunter_backend.apps.copilot_api as copilot_api
    import hunter_backend.apps.operations_api as ops_api
    import hunter_backend.runtime as rt

    data_dir = tmp_path / "data"
    reports_dir = data_dir / "reports"
    snapshots_dir = data_dir / "snapshots"
    runs_dir = data_dir / "runs"
    tool_outputs_dir = data_dir / "tool_outputs"
    att_dir = tmp_path / "copilot_attachments"
    db_file = data_dir / "platform_state.sqlite3"

    for d in (
        data_dir,
        reports_dir,
        snapshots_dir,
        runs_dir,
        tool_outputs_dir,
        att_dir,
        data_dir / "root_controller",
    ):
        d.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("HUNTER_DATA_DIR", str(data_dir))
    monkeypatch.setenv("HUNTER_PLATFORM_DB_PATH", str(db_file))
    monkeypatch.setenv("PLATFORM_DB_PATH", str(db_file))
    monkeypatch.setenv("HUNTER_COPILOT_ATTACHMENTS_DIR", str(att_dir))

    monkeypatch.setattr("hunter_backend.secrets_util.BASE_DIR", tmp_path)
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

    monkeypatch.setattr(copilot_api, "DATA_DIR", data_dir)
    monkeypatch.setattr(copilot_api, "ATTACHMENTS_DIR", att_dir)

    prev_store = ps._GLOBAL_PLATFORM_STORE
    prev_wired = rt._WIRED
    prev_ctrl_hook = GLOBAL_RUN_CONTROLLER.on_state_change
    prev_runs = dict(GLOBAL_RUN_CONTROLLER._runs)
    prev_budget = GLOBAL_COST_CONTROLLER.budget
    prev_scope_in = list(rt._SCOPE_STATE["in_scope"])
    prev_scope_out = list(rt._SCOPE_STATE["out_of_scope"])
    prev_pipelines = dict(rt._active_pipelines)
    prev_mission_tasks = dict(rt._active_mission_tasks)
    prev_go_client = rt._GO_CLIENT
    prev_main_loop = rt.MAIN_LOOP
    prev_burp_worker = rt._BURP_WORKER_TASK

    ps._GLOBAL_PLATFORM_STORE = None
    rt.EVENT_BUS._history.clear()
    rt._WIRED = False
    GLOBAL_RUN_CONTROLLER.on_state_change = None
    GLOBAL_RUN_CONTROLLER._runs.clear()
    rt._SCOPE_STATE["in_scope"] = []
    rt._SCOPE_STATE["out_of_scope"] = []
    rt._active_pipelines.clear()
    rt._active_mission_tasks.clear()

    try:
        yield db_file
    finally:
        try:
            GLOBAL_RUN_CONTROLLER.stop_all()
        except Exception:
            pass
        GLOBAL_RUN_CONTROLLER._runs.clear()
        GLOBAL_RUN_CONTROLLER._runs.update(prev_runs)
        GLOBAL_RUN_CONTROLLER.on_state_change = prev_ctrl_hook
        GLOBAL_COST_CONTROLLER.budget = prev_budget
        rt._WIRED = prev_wired
        rt._SCOPE_STATE["in_scope"] = prev_scope_in
        rt._SCOPE_STATE["out_of_scope"] = prev_scope_out
        rt._active_pipelines.clear()
        rt._active_pipelines.update(prev_pipelines)
        rt._active_mission_tasks.clear()
        rt._active_mission_tasks.update(prev_mission_tasks)
        rt.MAIN_LOOP = prev_main_loop
        rt._BURP_WORKER_TASK = prev_burp_worker
        rt._GO_CLIENT = prev_go_client
        if ps._GLOBAL_PLATFORM_STORE is not None:
            ps._GLOBAL_PLATFORM_STORE.close()
        ps._GLOBAL_PLATFORM_STORE = prev_store
        rt.EVENT_BUS._history.clear()


def _make_asgi_client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=application)
    return httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000")


async def _run_ws_exchange(
    path: str,
    *,
    headers: List[tuple[bytes, bytes]] | None = None,
    query_string: bytes = b"",
    client_messages: List[Dict[str, Any]] | None = None,
    max_server_frames: int = 3,
) -> List[Dict[str, Any]]:
    """Drive the raw ASGI WebSocket interface directly without external WS servers."""
    incoming: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
    for msg in client_messages or []:
        await incoming.put({"type": "websocket.receive", "text": json.dumps(msg)})
    await incoming.put({"type": "websocket.disconnect", "code": 1000})

    sent: List[Dict[str, Any]] = []
    scope = {
        "type": "websocket",
        "asgi": {"version": "3.0"},
        "path": path,
        "query_string": query_string,
        "headers": headers or [],
    }

    async def receive() -> Dict[str, Any]:
        return await incoming.get()

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    await application(scope, receive, send)
    return sent[:max_server_frames] if max_server_frames and len(sent) > max_server_frames else sent


def test_zero_ui_web_imports_and_route_parity() -> None:
    """Ensure hunter_backend never imports ui.web.* and resolves core routes without trailing slashes."""
    backend_pkg = Path(__file__).resolve().parent.parent / "hunter_backend"
    bad: List[str] = []
    for py in backend_pkg.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module and "ui.web" in node.module:
                bad.append(f"{py}: {node.module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if "ui.web" in alias.name:
                        bad.append(f"{py}: {alias.name}")
    assert bad == []

    resolver = get_resolver()
    patterns = {"/" + str(p.pattern).lstrip("/") for p in resolver.url_patterns}
    for required in (
        "/api/csrf",
        "/api/platform/overview",
        "/api/platform/stream",
        "/api/copilot/chat/stream",
        "/api/hunter/start",
        "/api/scope/check",
        "/api/scope/enforce",
        "/api/engines/run",
        "/api/control/redteam-policy",
        "/api/burp/repeater/send",
        "/opencode",
        "/chat",
    ):
        assert required in patterns


@pytest.mark.asyncio
async def test_asgi_lifespan_startup_and_shutdown() -> None:
    """ASGI lifespan cleanly starts and stops runtime wiring and shared httpx client."""
    in_q: asyncio.Queue[Dict[str, Any]] = asyncio.Queue()
    out: List[Dict[str, Any]] = []
    await in_q.put({"type": "lifespan.startup"})
    await in_q.put({"type": "lifespan.shutdown"})

    await application(
        {"type": "lifespan"},
        in_q.get,
        lambda msg: out.append(msg) or asyncio.sleep(0),
    )
    types = [m["type"] for m in out]
    assert "lifespan.startup.complete" in types
    assert "lifespan.shutdown.complete" in types


@pytest.mark.asyncio
async def test_compat_redirects_and_xss_sanitization() -> None:
    async with _make_asgi_client() as client:
        r_idx = await client.get(
            "/?section=<script>alert(1)</script>",
            headers={"Accept": "text/html"},
            follow_redirects=False,
        )
        assert r_idx.status_code == 302
        assert r_idx.headers["location"] == "http://127.0.0.1:3000/"

        r_sec = await client.get(
            "/?section=operations",
            headers={"Accept": "text/html"},
            follow_redirects=False,
        )
        assert r_sec.status_code == 302
        assert r_sec.headers["location"] == "http://127.0.0.1:3000/?section=operations"

        r_json = await client.get("/", headers={"Accept": "application/json"})
        assert r_json.status_code == 200
        assert r_json.json()["service"] == "hunter-ai-django-asgi"

        assert (await client.get("/opencode", follow_redirects=False)).headers["location"] == "http://127.0.0.1:3000/studio"
        assert (await client.get("/chat", follow_redirects=False)).headers["location"] == "http://127.0.0.1:3000/?copilot=open"
        assert (await client.get("/command", follow_redirects=False)).headers["location"] == "http://127.0.0.1:3000/"


@pytest.mark.asyncio
async def test_cors_csp_and_nocors_csrf_middleware() -> None:
    async with _make_asgi_client() as client:
        # 1. CSRF issuance + CSP headers + HttpOnly=False cookie
        r_csrf = await client.get("/api/csrf", headers={"Origin": "http://127.0.0.1:3000"})
        assert r_csrf.status_code == 200
        token = r_csrf.json()["csrfToken"]
        assert token
        assert "Content-Security-Policy" in r_csrf.headers
        assert r_csrf.headers.get("access-control-allow-origin") == "http://127.0.0.1:3000"

        # 2. Preflight allows last-event-id and x-csrftoken
        r_opt = await client.options(
            "/api/platform/runs/start",
            headers={
                "Origin": "http://127.0.0.1:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "last-event-id, x-csrftoken, content-type",
            },
        )
        assert r_opt.status_code == 200
        allow_hdrs = r_opt.headers.get("access-control-allow-headers", "").lower()
        assert "last-event-id" in allow_hdrs
        assert "x-csrftoken" in allow_hdrs

        # 3. Reject no-cors text/plain & form-urlencoded & untrusted Origin & cross-site
        r_txt = await client.post(
            "/api/platform/engagements",
            content=b'{"target":"example.com"}',
            headers={"Content-Type": "text/plain"},
        )
        assert r_txt.status_code == 403

        r_form = await client.post(
            "/api/platform/engagements",
            content=b"target=example.com",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r_form.status_code == 403

        r_evil = await client.post(
            "/api/platform/engagements",
            json={"target": "example.com"},
            headers={"Origin": "https://evil.example"},
        )
        assert r_evil.status_code == 403

        r_cross = await client.post(
            "/api/platform/engagements",
            json={"target": "example.com"},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert r_cross.status_code == 403

        r_bad_tok = await client.post(
            "/api/platform/engagements",
            json={"target": "example.com"},
            headers={
                "Origin": "http://127.0.0.1:3000",
                "X-CSRFToken": "invalid_token",
            },
        )
        assert r_bad_tok.status_code == 403

        # 4. Valid trusted Origin + JSON + matching X-CSRFToken passes
        r_ok = await client.post(
            "/api/platform/engagements",
            json={"target": "example.com", "name": "Smoke Target"},
            headers={
                "Origin": "http://127.0.0.1:3000",
                "X-CSRFToken": token,
            },
        )
        assert r_ok.status_code == 201


@pytest.mark.asyncio
async def test_platform_crud_engines_422_and_managed_hunter_start() -> None:
    await startup_runtime()
    try:
        async with _make_asgi_client() as client:
            # Create engagement and verify overview/search/context
            r_eng = await client.post(
                "/api/platform/engagements",
                json={"target": "juice-shop.example", "in_scope": ["juice-shop.example"]},
            )
            assert r_eng.status_code == 201
            eid = r_eng.json()["engagement"]["engagement_id"]

            r_ov = await client.get("/api/platform/overview")
            assert r_ov.status_code == 200
            assert r_ov.json()["active_engagement"]["engagement_id"] == eid

            r_search = await client.get("/api/platform/search?q=juice-shop")
            assert r_search.status_code == 200
            assert r_search.json()["total"] >= 1

            # Engines 422 validation parity on empty JSON
            r_eng_err = await client.post("/api/engines/run", json={})
            assert r_eng_err.status_code == 422

            # Budget roundtrip
            r_b = await client.post("/api/budget", json={"per_run_usd": 2.5})
            assert r_b.status_code == 200
            assert (await client.get("/api/budget")).status_code == 200

            # /api/hunter/start wired through register_managed_run + ScopeGuard
            r_hunter = await client.post(
                "/api/hunter/start",
                json={"target": "juice-shop.example", "scope": ["juice-shop.example"]},
            )
            assert r_hunter.status_code == 200
            run_id = r_hunter.json()["run_id"]
            assert run_id.startswith("hunter")
            r_runs = await client.get("/api/platform/runs")
            assert any(r["run_id"] == run_id for r in r_runs.json()["runs"])
    finally:
        await shutdown_runtime()


@pytest.mark.asyncio
async def test_native_async_sse_streams_and_websockets(monkeypatch: pytest.MonkeyPatch) -> None:
    await startup_runtime()
    try:
        async with _make_asgi_client() as client:
            # Platform SSE stream replay
            r_sse = await client.get("/api/platform/stream?once=1&since_seq=0")
            assert r_sse.status_code == 200
            assert "text/event-stream" in r_sse.headers["content-type"]
            assert "event: platform.ready" in r_sse.text

            # Copilot SSE stream
            async def fake_stream_turn(**kwargs: Any):
                yield {"event": "token", "text": "hello "}
                yield {"event": "done", "text": "world"}

            from hunter_backend.apps import copilot_api

            class _FakeCopilot:
                stream_turn = staticmethod(fake_stream_turn)

            monkeypatch.setattr(copilot_api, "get_copilot_service", lambda: _FakeCopilot())
            r_chat_sse = await client.post(
                "/api/copilot/chat/stream",
                json={"message": "audit target"},
            )
            assert r_chat_sse.status_code == 200
            assert "text/event-stream" in r_chat_sse.headers["content-type"]
            assert "hello " in r_chat_sse.text

        # WebSocket Origin rejection (CSWSH defense)
        evil_frames = await _run_ws_exchange(
            "/ws/platform",
            headers=[(b"origin", b"https://evil.example")],
            max_server_frames=5,
        )
        assert evil_frames == [{"type": "websocket.close", "code": 4403}]

        # WebSocket ping/pong & event stream with trusted Origin
        ok_frames = await _run_ws_exchange(
            "/ws/platform",
            headers=[(b"origin", b"http://127.0.0.1:3000")],
            client_messages=[{"action": "ping"}],
            max_server_frames=200,
        )
        assert any(f.get("type") == "websocket.accept" for f in ok_frames)
        texts = [json.loads(f["text"]) for f in ok_frames if f.get("type") == "websocket.send"]
        assert any(t.get("type") == "ready" for t in texts)
        assert any(t.get("type") == "pong" for t in texts)

        # /ws/chat without Origin (CLI/test client)
        chat_frames = await _run_ws_exchange(
            "/ws/chat",
            client_messages=[{"action": "ping"}],
            max_server_frames=10,
        )
        chat_texts = [json.loads(f["text"]) for f in chat_frames if f.get("type") == "websocket.send"]
        assert any(t.get("type") == "pong" for t in chat_texts)
    finally:
        await shutdown_runtime()


@pytest.mark.asyncio
async def test_security_hardening_ssrf_scope_paths_subprocess_and_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hunter_backend import runtime as rt_mod
    from hunter_backend.apps import arsenal_api

    # Isolate policy secret & grant file under tmp_path so repo state stays clean
    monkeypatch.setenv("HUNTERAI_POLICY_SECRET", "")
    monkeypatch.setattr(arsenal_api, "GRANT_PATH", tmp_path / "grant.json")
    monkeypatch.setattr(
        "hunter_backend.secrets_util.BASE_DIR",
        tmp_path,
    )

    async with _make_asgi_client() as client:
        # 1. Non-overridable Cloud Metadata & scheme SSRF remain blocked by default,
        #    while explicit governed mode (HUNTER_WEB_UNRESTRICTED=0) also blocks unscoped/local targets.
        for blocked_url in (
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://[fd00:ec2::254]/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
        ):
            r = await client.post("/api/burp/repeater/send", json={"url": blocked_url})
            assert r.status_code == 403, f"Expected 403 for {blocked_url}, got {r.status_code}"

        monkeypatch.setenv("HUNTER_WEB_UNRESTRICTED", "0")
        for governed_blocked_url in (
            "http://127.0.0.1:8080/admin",
            "http://localhost:8000/api/settings",
            "https://unconfigured.example/test",
        ):
            r_gov = await client.post("/api/burp/repeater/send", json={"url": governed_blocked_url})
            assert r_gov.status_code == 403, f"Expected governed 403 for {governed_blocked_url}, got {r_gov.status_code}"
        monkeypatch.delenv("HUNTER_WEB_UNRESTRICTED", raising=False)

        # 2. Scope collision resolved: canonical /api/scope/check vs Phase G /api/scope/enforce
        r_chk = await client.post(
            "/api/scope/check",
            json={"target": "https://any-site.com"},
        )
        assert r_chk.status_code == 200
        assert r_chk.json()["allowed"] is True

        r_chk_local = await client.post(
            "/api/scope/check",
            json={"target": "http://localhost:3001"},
        )
        assert r_chk_local.status_code == 200
        assert r_chk_local.json()["allowed"] is True

        r_enf = await client.post("/api/scope/enforce", json={"target": "http://192.168.1.50:8080"})
        assert r_enf.status_code == 200
        assert r_enf.json()["allowed"] is True

        # 3. Persisted policy secret (no hardcoded fallback)
        r_issue = await client.post(
            "/api/control/redteam-policy/issue",
            json={"scope": "example.com", "authorized_by": "smoke-test", "days": 1},
        )
        assert r_issue.status_code == 200
        assert r_issue.json()["active"] is True
        secret_file = tmp_path / "data" / "root_controller" / ".policy_secret"
        assert secret_file.is_file()
        assert len(secret_file.read_text(encoding="utf-8").strip()) >= 32

        r_pol = await client.get("/api/control/redteam-policy")
        assert r_pol.status_code == 200
        assert r_pol.json()["valid_signature"] is True

        # 4. Path traversal & ADS rejection on editor / reports / artex proxy
        assert (await client.get("/api/editor/file?path=../.env")).status_code == 403
        assert (await client.get("/api/enhanced/reports/..%5csecret.txt")).status_code in (400, 403)
        assert (await client.get("/api/tool_outputs/foo.txt:Zone.Identifier")).status_code in (400, 403)
        assert (await client.get("/api/platform/artex/..%2fsecrets")).status_code == 400

        # 5. Subprocess shell operator block on /api/run-tool
        r_shell = await client.post("/api/run-tool", json={"command": "echo hi && whoami"})
        assert r_shell.status_code == 403

        # 6. Go Core offline + mocked proxy
        r_health_off = await client.get("/api/platform/artex/health")
        assert r_health_off.status_code == 200
        assert "online" in r_health_off.json()

        mock_transport = httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                json={"mocked": True, "path": req.url.path},
            )
        )
        rt_mod._GO_CLIENT = httpx.AsyncClient(
            base_url="http://127.0.0.1:7071",
            transport=mock_transport,
        )
        r_proxy = await client.get("/api/platform/artex/v1/health")
        assert r_proxy.status_code == 200
        assert r_proxy.json()["mocked"] is True
        assert r_proxy.json()["path"] == "/api/v1/health"
        r_stats = await client.get("/api/platform/artex/stats")
        assert r_stats.status_code == 200
        assert r_stats.json()["path"] == "/api/v1/stats"
        r_health_on = await client.get("/api/platform/artex/health")
        assert r_health_on.status_code == 200
        assert r_health_on.json()["online"] is True
        assert r_health_on.json()["health"]["path"] == "/api/v1/health"
        await rt_mod._GO_CLIENT.aclose()
        rt_mod._GO_CLIENT = None


def test_unified_pentest_cli_parser_and_urls() -> None:
    import pentest

    parser = pentest.build_parser()
    for sub in ("artex", "pro", "unified", "web", "ui", "opencode", "opencode-ui"):
        ns = parser.parse_args([sub, "example.com", "--no-browser", "--dev", "--port", "8010", "--frontend-port", "3010"])
        assert ns.target == "example.com"
        assert ns.dev is True
        assert ns.port == 8010
        assert ns.frontend_port == 3010

    assert (
        pentest._build_unified_dashboard_url("127.0.0.1", 8000, 3000, True, "/", "example.com")
        == "http://127.0.0.1:3000/?target=example.com"
    )
    assert (
        pentest._build_unified_dashboard_url("127.0.0.1", 8000, 3000, True, "/studio")
        == "http://127.0.0.1:3000/studio"
    )


@pytest.mark.asyncio
async def test_whitenoise_serves_static_assets() -> None:
    sample_monaco = Path(__file__).resolve().parent.parent / "frontend" / "public" / "vendor" / "monaco" / "vs" / "loader.js"
    assert sample_monaco.is_file()
    async with _make_asgi_client() as client:
        r_monaco = await client.get("/static/vendor/monaco/vs/loader.js")
        assert r_monaco.status_code == 200
        assert len(r_monaco.content) > 0


def test_pentest_cli_lab_flags_and_env_application(monkeypatch: pytest.MonkeyPatch) -> None:
    import pentest

    env_keys = (
        "HUNTER_WEB_UNRESTRICTED",
        "HUNTER_ALLOW_LOCALHOST_SCOPE",
        "HUNTER_ALLOW_PRIVATE_LAB_SCOPE",
        "ARTEX_ALLOW_LOCAL_SCAN",
    )
    saved_env = {k: os.environ.get(k) for k in env_keys}
    parser = pentest.build_parser()

    try:
        for sub in ("artex", "pro", "unified", "web", "ui", "opencode", "opencode-ui"):
            for k in env_keys:
                os.environ.pop(k, None)

            # Default: fail-closed, no overrides set
            ns_default = parser.parse_args([sub, "example.com", "--no-browser"])
            assert ns_default.allow_local_labs is False
            assert ns_default.unrestricted_web is False
            assert pentest._apply_web_lab_env_flags(ns_default) == {}
            for k in env_keys:
                assert k not in os.environ

            # --allow-local-labs: sets local/private/Artex flags without HUNTER_WEB_UNRESTRICTED
            ns_labs = parser.parse_args([sub, "192.168.1.50", "--allow-local-labs", "--no-browser"])
            assert ns_labs.allow_local_labs is True
            assert ns_labs.unrestricted_web is False
            applied_labs = pentest._apply_web_lab_env_flags(ns_labs)
            assert applied_labs == {
                "HUNTER_ALLOW_LOCALHOST_SCOPE": "1",
                "HUNTER_ALLOW_PRIVATE_LAB_SCOPE": "1",
                "ARTEX_ALLOW_LOCAL_SCAN": "1",
            }
            assert "HUNTER_WEB_UNRESTRICTED" not in os.environ
            assert os.environ["HUNTER_ALLOW_LOCALHOST_SCOPE"] == "1"
            assert os.environ["HUNTER_ALLOW_PRIVATE_LAB_SCOPE"] == "1"
            assert os.environ["ARTEX_ALLOW_LOCAL_SCAN"] == "1"

            for k in env_keys:
                os.environ.pop(k, None)

            # --unrestricted-web: sets HUNTER_WEB_UNRESTRICTED=1 plus local/private/Artex flags
            ns_unr = parser.parse_args([sub, "--unrestricted-web", "--no-browser"])
            assert ns_unr.unrestricted_web is True
            applied_unr = pentest._apply_web_lab_env_flags(ns_unr)
            assert applied_unr == {
                "HUNTER_WEB_UNRESTRICTED": "1",
                "HUNTER_ALLOW_LOCALHOST_SCOPE": "1",
                "HUNTER_ALLOW_PRIVATE_LAB_SCOPE": "1",
                "ARTEX_ALLOW_LOCAL_SCAN": "1",
            }
            for k in env_keys:
                assert os.environ[k] == "1"
    finally:
        for k, prev in saved_env.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


@pytest.mark.asyncio
async def test_smoke_db_isolation_and_engagement_deduplication(tmp_path: Path) -> None:
    """Verify smoke tests hit tmp_path DB and upsert_engagement deduplicates omitted engagement_id."""
    import core.platform_store as ps

    store = ps.get_platform_store()
    assert Path(store.db_path).resolve() != ps.DEFAULT_DB_PATH.resolve()
    assert tmp_path.resolve() in Path(store.db_path).resolve().parents

    first = store.upsert_engagement(
        target="https://Smoke-Dedup.example/",
        name="Smoke   Target",
        in_scope=["smoke-dedup.example"],
        source="local",
        metadata={"pass": 1},
    )
    second = store.upsert_engagement(
        target="https://smoke-dedup.example",
        name="smoke target",
        in_scope=["smoke-dedup.example", "*.smoke-dedup.example"],
        source="LOCAL",
        metadata={"pass": 2},
    )
    assert second["engagement_id"] == first["engagement_id"]
    assert second["in_scope"] == ["smoke-dedup.example", "*.smoke-dedup.example"]
    assert second["metadata"] == {"pass": 2}

    # Different source or name stays distinct
    other_source = store.upsert_engagement(
        target="https://smoke-dedup.example",
        name="Smoke Target",
        source="pipeline",
    )
    assert other_source["engagement_id"] != first["engagement_id"]

    async with _make_asgi_client() as client:
        r1 = await client.post(
            "/api/platform/engagements",
            json={"target": "juice-shop.example", "in_scope": ["juice-shop.example"]},
        )
        r2 = await client.post(
            "/api/platform/engagements",
            json={"target": "juice-shop.example/", "in_scope": ["juice-shop.example"]},
        )
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r2.json()["engagement"]["engagement_id"] == r1.json()["engagement"]["engagement_id"]
        assert len(
            [e for e in store.list_engagements(limit=50) if "juice-shop.example" in e["target"]]
        ) == 1
