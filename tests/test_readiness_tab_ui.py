# -*- coding: utf-8 -*-
"""
اختبارات تبويب الجاهزية في الـ Dashboard (Phase 1 UI wiring).
- الـ HTML فيه زرار التبويب + محتوى tab-readiness.
- GET /api/diagnostics/readiness يرجع تقرير shape صحيح (بمُفحص مزيف — offline).
"""
from pathlib import Path

from starlette.testclient import TestClient

from core.readiness import checker as checker_module
from core.readiness.checker import ComponentResult, ComponentStatus, ReadinessReport
from ui.web.app import app


class TestReadinessTabUI:
    def test_index_html_has_readiness_tab_button(self):
        client = TestClient(app)
        r = client.get("/")
        assert r.status_code == 200
        assert "switchTab('readiness'" in r.text
        assert "جاهزية البيئة" in r.text

    def test_index_html_has_readiness_panel(self):
        client = TestClient(app)
        r = client.get("/")
        assert 'id="tab-readiness"' in r.text
        assert 'id="readiness-list"' in r.text
        assert 'id="readiness-state-badge"' in r.text

    def test_app_js_has_readiness_handler(self):
        js_path = Path(__file__).parent.parent / "ui" / "web" / "static" / "app.js"
        js = js_path.read_text(encoding="utf-8")
        assert "function runReadinessScan()" in js
        assert "function maybeRunReadiness()" in js
        assert "renderReadiness(d)" in js
        assert "fetch('/api/diagnostics/readiness')" in js


# ── مُفحص مزيف: نتيجة ثابتة، صفر اتصال حقيقي ─────────────────────────
class _FakeChecker:
    def __init__(self, results=None, **kwargs):
        self._results = results

    async def run_all(self, target="", session_id="", strict=True, components=None):
        report = ReadinessReport(target=target, session_id=session_id, strict=strict)
        report.results = (
            [
                ComponentResult(
                    component="kali_tool", name=_r["name"],
                    status=ComponentStatus(_r["status"]),
                    required=_r.get("required", True),
                    detail=_r.get("detail", "fake probe ok"),
                    probe=f"{_r['name']} --version",
                )
                for _r in self._results
            ]
            if self._results is not None
            else [
                ComponentResult(component="kali_tool", name="nmap",
                                status=ComponentStatus.READY,
                                detail="fake ok", probe="nmap --version"),
            ]
        )
        report.duration_sec = 0.01
        return report


async def _fake_save(report, workspace_root=None):
    return Path("data/readiness/fake_artifact.json")


class TestReadinessEndpoint:
    def _inject(self, monkeypatch, checker_obj):
        """الـ endpoint يستورد من core.readiness package — نعزّل التأثير فيه وأيضاً."""
        import core.readiness as readiness_pkg
        monkeypatch.setattr(checker_module, "ReadinessChecker", lambda **kw: checker_obj)
        monkeypatch.setattr(readiness_pkg, "ReadinessChecker", lambda **kw: checker_obj)
        monkeypatch.setattr(readiness_pkg, "save_readiness_artifact", _fake_save)

    def test_endpoint_uses_injected_fake_all_ready(self, monkeypatch):
        self._inject(monkeypatch, _FakeChecker())
        client = TestClient(app)
        r = client.get("/api/diagnostics/readiness")
        assert r.status_code == 200
        d = r.json()
        assert d["strict_ready"] is True
        assert d["counts"]["READY"] == 1
        assert d["results"][0]["name"] == "nmap"
        assert d["results"][0]["status"] == "READY"
        assert d["results"][0]["probe"] == "nmap --version"
        assert d["artifact_path"] is not None
        assert d["target"] == "dashboard-local"

    def test_endpoint_blocked_items_are_listed_honestly(self, monkeypatch):
        """عنصر مطلوب MISSING → strict_ready False وقائمة blocked مأهولة."""
        self._inject(monkeypatch, _FakeChecker(results=[
            {"name": "ffuf", "status": "MISSING"},
            {"name": "ollama_server", "status": "READY", "required": False},
        ]))
        client = TestClient(app)
        r = client.get("/api/diagnostics/readiness")
        assert r.status_code == 200
        d = r.json()
        assert d["strict_ready"] is False
        assert d["counts"]["MISSING"] == 1
        assert d["counts"]["READY"] == 1
        blocked_names = [b["name"] for b in d["blocked"]]
        assert blocked_names == ["ffuf"]

    def test_endpoint_survives_checker_crash(self, monkeypatch):
        """فحص منفجر لا يسقط السيرفر — يرجع 500 بخطة خطأ مفهومة."""
        class _Bomb:
            async def run_all(self, *a, **kw):
                raise RuntimeError("probe exploded")

        import core.readiness as readiness_pkg
        monkeypatch.setattr(checker_module, "ReadinessChecker", _Bomb)
        monkeypatch.setattr(readiness_pkg, "ReadinessChecker", _Bomb)
        client = TestClient(app)
        r = client.get("/api/diagnostics/readiness")
        assert r.status_code == 500
        assert "probe exploded" in r.json()["error"]
