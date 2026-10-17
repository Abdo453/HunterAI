"""
Unit Tests for Browser Sensor Skill (skills/browser/browser_sensor/skill.py)
==============================================================================
كل الاختبارات Offline — لا متصفح حقيقي ولا شبكة (Mock للجلسة والحلقة).
"""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from skills.base_skill import SkillContext
from skills.browser.browser_sensor.skill import BrowserSensorSkill


# ════════════════════════════════════════════════════════════════════════════
# Fakes (بدائل خالية من المتصفح والشبكة)
# ════════════════════════════════════════════════════════════════════════════

class FakeSession:
    """بديل لـ StatefulBrowserSession — لا يفتح متصفحاً ولا يُصدر طلبات شبكة."""

    def __init__(self, target_url: str, output_dir: Path, **kwargs: Any):
        self.target_url = target_url
        self.output_dir = output_dir
        self.headless = kwargs.get("headless", True)
        self.proxy = kwargs.get("proxy")
        self.current_url = target_url
        self.cookies: List[Dict[str, Any]] = []
        self.local_storage: Dict[str, str] = {}
        self.network_history: List[SimpleNamespace] = []
        self.discovered_urls: set = {target_url, f"{target_url}/about", f"{target_url}/api/user"}
        self._closed = False

    async def start(self) -> bool:
        return True

    async def close(self) -> None:
        self._closed = True

    async def take_screenshot(self, name: str) -> str | None:
        ss = self.output_dir / "screenshots" / f"{name}.png"
        ss.parent.mkdir(parents=True, exist_ok=True)
        ss.write_bytes(b"\x89PNG fake")
        return str(ss)

    @property
    def is_alive(self) -> bool:
        return not self._closed


class FakeReport:
    """بديل لـ SensorObservationReport."""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.duration_sec = 12.5
        self.pages_visited = 3
        self.states_mapped = 2
        self.api_endpoints_discovered = 2
        self.secrets_discovered = 0
        self.auth_state = "AUTHENTICATED"
        self.stop_reason = "coverage_met"
        self.coverage: Dict[str, Any] = {
            "pages_visited": 3,
            "pages_discovered": 5,
            "pages_pct": 60.0,
            "states_explored": 2,
            "forms_tested": 1,
            "api_observed": 2,
            "overall_percentage": 55.0,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "duration_sec": self.duration_sec,
            "pages_visited": self.pages_visited,
            "states_mapped": self.states_mapped,
            "api_endpoints_discovered": self.api_endpoints_discovered,
            "auth_state": self.auth_state,
            "stop_reason": self.stop_reason,
            "coverage": self.coverage,
        }


class FakeLoop:
    """بديل لـ BrowserBrainLoop.run_loop — يعيد تقريراً مزيفاً فورياً."""

    def __init__(self, target_url: str, session: Any, **kwargs: Any):
        self.target_url = target_url
        self.session = session
        self.kwargs = kwargs

    async def run_loop(self) -> FakeReport:
        return FakeReport(self.target_url)


# ════════════════════════════════════════════════════════════════════════════
# Workspace fake
# ════════════════════════════════════════════════════════════════════════════

class FakeWorkspace:
    """بديل خفيف لـ WorkspaceManager يحفظ الملفات في tmp_path."""

    def __init__(self, root: Path):
        self.root = root
        self.logs: List[str] = []
        self._files: Dict[str, Path] = {}

    def get_workspace_path(self, target: str, session_id: str = "") -> Path:
        safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
        p = self.root / "workspaces" / safe / session_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def write_file(self, target: str, category: str, filename: str, content: str, session_id: str) -> Path:
        p = self.get_workspace_path(target, session_id) / category / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        self._files[f"{category}/{filename}"] = p
        return p

    def append_log(self, target: str, session_id: str, message: str) -> None:
        self.logs.append(message)


def _make_ctx(root: Path, target: str = "https://app.target.com", session_id: str = "sess_browser_sensor") -> SkillContext:
    return SkillContext(
        target=target,
        session_id=session_id,
        workspace=FakeWorkspace(root),
        tool_manager=SimpleNamespace(),
        extra={"max_pages": 5, "time_budget_sec": 30.0, "coverage_threshold": 50.0},
    )


def _sensor_dir(ws: FakeWorkspace, target: str, session_id: str) -> Path:
    return ws.get_workspace_path(target, session_id) / "browser" / "sensor"


# ════════════════════════════════════════════════════════════════════════════
# Tests
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_browser_sensor_instantiation_and_can_handle(tmp_path):
    skill = BrowserSensorSkill(headless=True)
    assert skill.name == "browser_sensor"
    assert skill.category == "browser"
    # مهارة مستوى الهدف — لا تشارك في التوجيه التلقائي للمُعاملات
    assert skill.can_handle("next") == 0.0
    assert skill.can_handle("id") == 0.0


@pytest.mark.asyncio
async def test_browser_sensor_executes_offline_and_writes_artifacts(tmp_path, monkeypatch):
    import skills.browser.browser_sensor.skill as mod

    monkeypatch.setattr(mod, "BrowserBrainLoop", FakeLoop)
    monkeypatch.setattr(mod, "StatefulBrowserSession", FakeSession)

    ctx = _make_ctx(tmp_path)
    skill = BrowserSensorSkill(headless=True)
    result = await skill.execute(ctx)

    assert result.success is True
    assert result.tool_used == "browser_sensor"
    assert result.duration > 0

    # ملفات المخرجات موجودة فعلياً
    sensor_dir = _sensor_dir(ctx.workspace, ctx.target, ctx.session_id)
    assert (sensor_dir / "sensor_report.json").exists()
    assert (sensor_dir / "coverage_metrics.json").exists()
    assert (sensor_dir / "discovered_urls.txt").exists()
    assert (sensor_dir / "api_endpoints.txt").exists()
    assert (sensor_dir / "screenshots" / "final_state.png").exists()

    # تقرير القناة صالح JSON
    report = json.loads((sensor_dir / "sensor_report.json").read_text(encoding="utf-8"))
    assert report["pages_visited"] == 3
    assert report["auth_state"] == "AUTHENTICATED"
    assert report["stop_reason"] == "coverage_met"

    # مخرجات المهارة
    assert "sensor_report.json" in result.output_files
    assert "coverage_metrics.json" in result.output_files
    assert "final_screenshot.png" in result.output_files

    # Findings للسطح السطحي والنقاط النهائية والحالة المصادقة
    titles = [f["title"] for f in result.findings]
    assert any("Browser Surface Mapped" in t for t in titles)
    assert any("Dynamic API Surface" in t for t in titles)
    assert any("Authenticated Browser State" in t for t in titles)

    # لا أخطاء هيكيلة
    assert len(result.structured_errors) == 0

    # next skills مقترحة
    assert "form_intelligence" in result.next_skills
    assert "network_intelligence" in result.next_skills


@pytest.mark.asyncio
async def test_browser_sensor_handles_loop_failure_gracefully(tmp_path, monkeypatch):
    import skills.browser.browser_sensor.skill as mod

    class ExplodingLoop:
        def __init__(self, target_url: str, session: Any, **kwargs: Any):
            self.target_url = target_url
            self.session = session
            self.kwargs = kwargs

        async def run_loop(self):
            raise RuntimeError("Playwright crash simulated")

    monkeypatch.setattr(mod, "BrowserBrainLoop", ExplodingLoop)
    monkeypatch.setattr(mod, "StatefulBrowserSession", FakeSession)

    ctx = _make_ctx(tmp_path)
    skill = BrowserSensorSkill(headless=True)
    result = await skill.execute(ctx)

    assert result.success is False
    assert len(result.structured_errors) == 1
    assert result.structured_errors[0].category == "runtime"
    assert "Playwright crash simulated" in result.structured_errors[0].message


# ════════════════════════════════════════════════════════════════════════════
# Real end-to-end against a local HTTP server (Playwright Chromium)
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_browser_sensor_real_end_to_end(tmp_path):
    """تشغيل حقيقي على خادم محلي عبر متصفح Chromium headless."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        pytest.skip("Playwright not installed")

    import aiohttp
    from aiohttp import web

    html_login = (
        "<html><head><title>Sign In</title></head>"
        "<body><h1>Login</h1>"
        "<form action='/login' method='POST'>"
        "<input type='text' name='user'><input type='password' name='pass'>"
        "<button type='submit'>Sign In</button></form>"
        "<a href='/dashboard'>Dashboard</a>"
        "</body></html>"
    )
    html_dashboard = (
        "<html><head><title>Dashboard</title></head>"
        "<body><h1>Dashboard</h1>"
        "<a href='/api/user/me'>User API</a></body></html>"
    )

    async def handle_root(request):
        return web.Response(text=html_login, content_type="text/html")

    async def handle_login(request):
        return web.Response(text="<html><title>Logged In</title><body>Welcome</body></html>", content_type="text/html")

    async def handle_dashboard(request):
        return web.Response(text=html_dashboard, content_type="text/html")

    async def handle_api_user(request):
        return web.json_response({"id": 1, "username": "hunter"})

    app = web.Application()
    app.router.add_get("/", handle_root)
    app.router.add_post("/login", handle_login)
    app.router.add_get("/dashboard", handle_dashboard)
    app.router.add_get("/api/user/me", handle_api_user)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    target_url = f"http://127.0.0.1:{port}/"

    try:
        ctx = _make_ctx(tmp_path, target=target_url, session_id="sess_browser_e2e")
        # ميزانية زمنية قصيرة للخادم المحلي
        ctx.extra["max_pages"] = 4
        ctx.extra["time_budget_sec"] = 40.0
        ctx.extra["coverage_threshold"] = 40.0

        skill = BrowserSensorSkill(headless=True)
        result = await skill.execute(ctx)

        assert result.success is True, f"skill failed: {[e.message for e in result.structured_errors]}"
        assert result.duration > 0

        sensor_dir = _sensor_dir(ctx.workspace, ctx.target, ctx.session_id)
        assert (sensor_dir / "sensor_report.json").exists()
        report = json.loads((sensor_dir / "sensor_report.json").read_text(encoding="utf-8"))
        assert report["pages_visited"] >= 1
        assert report["auth_state"] in {
            s.value for s in __import__("core.browser.state_detector", fromlist=["SemanticAppState"]).SemanticAppState
        }

        # Findings وُجدت للسطح السطحي (على الأقل finding واحد)
        assert len(result.findings) >= 1, result.findings

        # لقطات الشاشة والملفات 텍ستية
        assert (sensor_dir / "discovered_urls.txt").exists()
        assert (sensor_dir / "api_endpoints.txt").exists()

        ctx.workspace.append_log(ctx.target, ctx.session_id, f"[E2E-DONE] port={port} findings={len(result.findings)}")
    finally:
        await runner.cleanup()

