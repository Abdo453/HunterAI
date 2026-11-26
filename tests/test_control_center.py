"""
HunterAI Control Center — Comprehensive Verification & Contract Test Suite
===========================================================================
Validates end-to-end alignment across:
  - Backend engines (`core/dashboard/agent_manager.py`, `core/dashboard/live_feed.py`)
  - FastAPI routers & WebSocket hub (`ui/web/app.py`, `ui/web/routers/*.py`)
  - Frontend templates, static HTML/CSS/JS (`ui/web/templates/`, `ui/web/static/`)

All tests run in full filesystem and singleton isolation using `tmp_path` and
`monkeypatch`, keeping repository state and `data/` completely clean.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Set

import psutil
import pytest
from fastapi.testclient import TestClient

import core.dashboard.agent_manager as agent_manager_mod
import core.dashboard.live_feed as live_feed_mod
from core.dashboard import (
    AgentManager,
    DashboardMetrics,
    LiveFeedManager,
    get_agent_manager,
    get_live_feed_manager,
)
from ui.web.app import app

REPO_ROOT = Path(__file__).resolve().parents[1]
UI_WEB_DIR = REPO_ROOT / "ui" / "web"
DASHBOARD_CORE_DIR = REPO_ROOT / "core" / "dashboard"


@pytest.fixture(autouse=True)
def isolated_control_center(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Isolate working directory, singletons, and kill-switch state per test."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "data" / "exports").mkdir(parents=True, exist_ok=True)

    fresh_agents = AgentManager()
    fresh_feed = LiveFeedManager(agent_manager=fresh_agents)

    monkeypatch.setattr(agent_manager_mod, "_AGENT_MANAGER_SINGLETON", fresh_agents)
    monkeypatch.setattr(live_feed_mod, "_LIVE_FEED_SINGLETON", fresh_feed)

    yield {"agents": fresh_agents, "feed": fresh_feed, "tmp_path": tmp_path}

    try:
        from core.safety.kill_switch import EmergencyKillSwitch

        EmergencyKillSwitch().reset()
    except Exception:
        pass
    fresh_agents.reset()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


# ── 1. Dashboard Rendering & Static Assets ────────────────────────────────────


class TestDashboardAndStaticAssets:
    REQUIRED_PANELS = (
        "Active Agents",
        "Live Findings",
        "Evidence Court",
        "Scope",
        "MCP",
        "System Health",
        "Terminal",
    )

    def test_get_root_renders_dashboard_with_all_7_panels(self, client: TestClient):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")

        html = resp.text
        for panel in self.REQUIRED_PANELS:
            assert panel in html, f"Missing panel '{panel}' in rendered dashboard.html"

        # Verify SSR #initial-state JSON bootstrap parses cleanly and contains all 7 sections
        match = re.search(
            r'<script\s+id="initial-state"\s+type="application/json">\s*(.*?)\s*</script>',
            html,
            re.DOTALL,
        )
        assert match is not None, "Missing #initial-state JSON bootstrap block"
        initial_state = json.loads(match.group(1))
        for key in ("agents", "findings", "scope", "mcp", "metrics", "court", "terminal"):
            assert key in initial_state

    @pytest.mark.parametrize(
        "asset_path,expected_snippet",
        [
            ("/static/css/dashboard.css", "--bg-base"),
            ("/static/js/websocket.js", "/ws/agents"),
            ("/static/js/charts.js", "HunterCharts"),
            ("/static/js/terminal.js", "HunterTerminal"),
            ("/static/index.html", "HunterAI Control Center"),
        ],
    )
    def test_static_assets_return_200(
        self, client: TestClient, asset_path: str, expected_snippet: str
    ):
        resp = client.get(asset_path)
        assert resp.status_code == 200
        assert expected_snippet in resp.text

    def test_static_index_html_has_all_7_panels(self, client: TestClient):
        resp = client.get("/static/index.html")
        assert resp.status_code == 200
        for panel in self.REQUIRED_PANELS:
            assert panel in resp.text

    def test_preserved_api_status_endpoint(self, client: TestClient):
        resp = client.get("/api/status")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ONLINE"

    def test_dashboard_package_exports_preserved(self):
        assert DashboardMetrics is not None
        assert get_agent_manager() is not None
        assert get_live_feed_manager() is not None


# ── 2. Agent Orchestration ────────────────────────────────────────────────────


class TestAgentOrchestration:
    def test_list_agents_and_lifecycle_transitions(self, client: TestClient):
        resp = client.get("/api/agents")
        assert resp.status_code == 200
        data = resp.json()

        assert data["summary"]["total"] == 4
        assert data["summary"]["idle"] == 4
        assert data["emergency_stopped"] is False
        assert data["paused_all"] is False
        assert isinstance(data["timestamp"], float)

        agent_ids = {a["id"] for a in data["agents"]}
        assert agent_ids == {"brain", "browser", "burp", "code_intel"}

        # Start brain with target & task
        r_start = client.post(
            "/api/agents/brain/start",
            json={"target": "https://example.com", "task": "OODA recon"},
        )
        assert r_start.status_code == 200
        d_start = r_start.json()
        assert d_start["ok"] is True
        assert d_start["status"] == "running"
        assert d_start["status_badge"] == "🟢 Running"
        assert d_start["agent"]["target"] == "https://example.com"
        assert d_start["agent"]["current_task"] == "OODA recon"

        # Start browser without body (matches UI when no active_target is set)
        r_browser = client.post("/api/agents/browser/start")
        assert r_browser.status_code == 200
        assert r_browser.json()["status"] == "running"

        # Pause brain -> idle
        r_pause = client.post("/api/agents/brain/pause")
        assert r_pause.status_code == 200
        assert r_pause.json()["status"] == "idle"
        assert r_pause.json()["status_badge"] == "🟡 Idle"
        assert r_pause.json()["agent"]["current_task"].startswith("Paused")

        # Stop code_intel -> stopped
        r_stop = client.post("/api/agents/code_intel/stop")
        assert r_stop.status_code == 200
        assert r_stop.json()["status"] == "stopped"
        assert r_stop.json()["status_badge"] == "⚫ Stopped"

        # Pause-all pauses running agents (browser) without reviving stopped ones (code_intel)
        r_pause_all = client.post("/api/agents/pause-all")
        assert r_pause_all.status_code == 200
        pa_data = r_pause_all.json()
        assert pa_data["ok"] is True
        assert pa_data["paused_all"] is True
        statuses = {a["id"]: a["status"] for a in pa_data["agents"]}
        assert statuses["browser"] == "idle"
        assert statuses["code_intel"] == "stopped"

        # Restart stopped/error agent -> running
        r_restart = client.post("/api/agents/code_intel/restart")
        assert r_restart.status_code == 200
        assert r_restart.json()["status"] == "running"
        assert r_restart.json()["status_badge"] == "🟢 Running"

    @pytest.mark.parametrize("action", ["start", "pause", "stop", "restart"])
    def test_unknown_agent_returns_404(self, client: TestClient, action: str):
        resp = client.post(f"/api/agents/nonexistent_agent/{action}")
        assert resp.status_code == 404

    def test_classmethod_delegates_and_report_activity(self):
        snap = AgentManager.get_all_status()
        assert snap["summary"]["total"] == 4

        res = get_agent_manager().report_activity(
            "burp", "Proxy interception error", status="error"
        )
        assert res["ok"] is True
        assert res["agent"]["status"] == "error"
        assert res["agent"]["status_badge"] == "🔴 Error"
        assert res["agent"]["error"] == "Proxy interception error"


# ── 3. Findings Stream, Details, Burp Export & False Positives ────────────────


class TestFindingsAndEvidenceCourt:
    def test_findings_stream_detail_burp_export_and_false_positive(
        self, client: TestClient, isolated_control_center: Dict[str, Any]
    ):
        feed: LiveFeedManager = isolated_control_center["feed"]
        tmp_path: Path = isolated_control_center["tmp_path"]

        added = feed.add_finding(
            {
                "id": "FND-SQLI-101",
                "title": "Boolean SQL Injection in /api/orders",
                "severity": "critical",
                "source_agent": "Burp",
                "verdict": "CONFIRMED",
                "target": "https://shop.example.com",
                "endpoint": "https://shop.example.com/api/orders?id=1",
                "evidence": "Response delta confirmed true vs false predicates",
                "payload_used": "1 AND 1=1",
                "raw_request": "GET /api/orders?id=1%20AND%201=1 HTTP/1.1\r\nHost: shop.example.com",
                "raw_response": "HTTP/1.1 200 OK\r\n\r\n{\"orders\": [1]}",
                "remediation": "Use parameterized SQL queries.",
                "cwe": "CWE-89",
            }
        )
        assert added["severity"] == "Critical"
        assert added["verdict"] == "CONFIRMED"

        # Stream list
        r_list = client.get("/api/findings")
        assert r_list.status_code == 200
        list_data = r_list.json()
        assert list_data["total"] == 1
        assert list_data["findings"][0]["id"] == "FND-SQLI-101"
        assert len(list_data["alerts"]) == 1

        # Detail lookup
        r_detail = client.get("/api/findings/FND-SQLI-101")
        assert r_detail.status_code == 200
        detail = r_detail.json()
        assert detail["cwe"] == "CWE-89"
        assert detail["payload_used"] == "1 AND 1=1"
        assert "raw_request" in detail

        assert client.get("/api/findings/FND-MISSING").status_code == 404

        # Burp export (writes inside tmp_path/data/exports/burp_issues)
        r_export = client.post("/api/findings/FND-SQLI-101/export-burp")
        assert r_export.status_code == 200
        exp_data = r_export.json()
        assert exp_data["ok"] is True
        assert exp_data["finding"]["exported_to_burp"] is True
        assert exp_data["exported"]["issue_name"].startswith("[HunterAI]")
        export_path = Path(exp_data["exported"]["export_path"])
        assert export_path.exists()
        assert (tmp_path / export_path).exists() if not export_path.is_absolute() else True

        assert client.post("/api/findings/FND-MISSING/export-burp").status_code == 404

        # Mark False Positive -> updates finding + Evidence Court counts & feed
        r_fp = client.post(
            "/api/findings/FND-SQLI-101/false-positive",
            json={"reason": "WAF synthetic 200 response"},
        )
        assert r_fp.status_code == 200
        fp_data = r_fp.json()
        assert fp_data["ok"] is True
        assert fp_data["verdict"] == "FALSE_POSITIVE"
        assert fp_data["false_positive"] is True

        r_court = client.get("/api/court/status")
        assert r_court.status_code == 200
        court = r_court.json()
        assert court["false_positives_rejected"] == 1
        assert len(court["feed"]) == 1
        assert court["feed"][0]["id"] == "FND-SQLI-101"
        assert court["feed"][0]["verdict"] == "FALSE_POSITIVE"
        assert "WAF synthetic 200 response" in court["feed"][0]["summary"]

        # Marking same finding FP again must not double-increment rejected counter
        client.post("/api/findings/FND-SQLI-101/false-positive", json={"reason": "Repeat"})
        assert client.get("/api/court/status").json()["false_positives_rejected"] == 1

        assert client.post("/api/findings/FND-MISSING/false-positive").status_code == 404

    def test_court_claim_lifecycle_counters(
        self, client: TestClient, isolated_control_center: Dict[str, Any]
    ):
        feed: LiveFeedManager = isolated_control_center["feed"]
        feed.add_court_event("CLM-1", "XSS candidate on /search", "PENDING")
        feed.add_court_event("CLM-2", "IDOR candidate on /users/2", "VERIFYING")
        assert client.get("/api/court/status").json()["pending_claims"] == 1
        assert client.get("/api/court/status").json()["under_verification"] == 1

        feed.add_court_event("CLM-1", "XSS nonce executed", "CONFIRMED")
        court = client.get("/api/court/status").json()
        assert court["pending_claims"] == 0
        assert court["confirmed_last_hour"] == 1


# ── 4. Scope Management & Lock Enforcement (HTTP 423) ─────────────────────────


class TestScopeManagement:
    def test_scope_crud_lock_423_and_check(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ):
        # Initial scope
        r_init = client.get("/api/scope")
        assert r_init.status_code == 200
        assert r_init.json()["locked"] is False
        assert len(r_init.json()["firewall_rules"]) >= 1

        # Update via POST /api/scope
        r_upd = client.post(
            "/api/scope",
            json={
                "targets": ["https://app.example.com", "*.example.com"],
                "excluded_domains": ["logout.example.com"],
                "active_target": "https://app.example.com",
            },
        )
        assert r_upd.status_code == 200
        assert r_upd.json()["ok"] is True
        assert "https://app.example.com" in r_upd.json()["targets"]
        assert "*.example.com" in r_upd.json()["targets"]
        assert r_upd.json()["excluded_domains"] == ["logout.example.com"]

        # Add target
        r_add = client.post("/api/scope/targets", json={"url": "https://api.example.com"})
        assert r_add.status_code == 200
        assert "https://api.example.com" in r_add.json()["targets"]

        # Remove target (query param & JSON body)
        r_del_q = client.delete("/api/scope/targets", params={"url": "https://api.example.com"})
        assert r_del_q.status_code == 200
        assert "https://api.example.com" not in r_del_q.json()["targets"]

        client.post("/api/scope/targets", json={"target": "https://temp.example.com"})
        r_del_b = client.request(
            "DELETE", "/api/scope/targets", json={"target": "https://temp.example.com"}
        )
        assert r_del_b.status_code == 200
        assert "https://temp.example.com" not in r_del_b.json()["targets"]

        # Lock scope -> all mutations must return 423 Locked
        r_lock = client.post("/api/scope/lock", json={"locked": True})
        assert r_lock.status_code == 200
        assert r_lock.json()["locked"] is True

        assert client.post("/api/scope", json={"targets": ["https://evil.com"]}).status_code == 423
        assert client.put("/api/scope", json={"active_target": "https://evil.com"}).status_code == 423
        assert client.post("/api/scope/targets", json={"url": "https://new.example.com"}).status_code == 423
        assert client.delete("/api/scope/targets", params={"url": "https://app.example.com"}).status_code == 423

        # Scope remain unchanged while locked
        assert "https://app.example.com" in client.get("/api/scope").json()["targets"]

        # Unlock via toggle (empty body)
        r_unlock = client.post("/api/scope/lock")
        assert r_unlock.status_code == 200
        assert r_unlock.json()["locked"] is False

        # Scope checks in both governed and unrestricted modes
        for mode in ("0", "1"):
            monkeypatch.setenv("HUNTER_UNRESTRICTED", mode)
            ok_in = client.post("/api/scope/check", json={"target": "https://sub.example.com/v1"})
            assert ok_in.status_code == 200
            assert ok_in.json()["allowed"] is True

            bad_out = client.post("/api/scope/check", json={"target": "https://evil.org"})
            assert bad_out.status_code == 200
            assert bad_out.json()["allowed"] is False

            bad_excl = client.post("/api/scope/check", json={"target": "https://logout.example.com"})
            assert bad_excl.status_code == 200
            assert bad_excl.json()["allowed"] is False

            bad_loop = client.post("/api/scope/check", json={"target": "http://127.0.0.1:8080"})
            assert bad_loop.status_code == 200
            assert bad_loop.json()["allowed"] is False


# ── 5. Emergency Controls ─────────────────────────────────────────────────────


class TestEmergencyControls:
    def test_emergency_pause_stop_export_and_clear(
        self, client: TestClient, isolated_control_center: Dict[str, Any]
    ):
        feed: LiveFeedManager = isolated_control_center["feed"]
        tmp_path: Path = isolated_control_center["tmp_path"]

        client.post("/api/agents/brain/start", json={"target": "https://example.com"})
        client.post("/api/agents/browser/start")
        feed.add_finding({"id": "FND-EMG-1", "title": "XSS", "severity": "High"})
        feed.add_court_event("CLM-EMG-1", "XSS claim", "CONFIRMED")

        # Pause all
        r_pause = client.post("/api/emergency/pause-all")
        assert r_pause.status_code == 200
        assert r_pause.json()["paused_all"] is True
        assert all(
            a["status"] == "idle"
            for a in client.get("/api/agents").json()["agents"]
        )

        # Stop all
        r_stop = client.post("/api/emergency/stop-all")
        assert r_stop.status_code == 200
        assert r_stop.json()["emergency_stopped"] is True
        agents_snap = client.get("/api/agents").json()
        assert agents_snap["emergency_stopped"] is True
        assert all(a["status"] == "stopped" for a in agents_snap["agents"])

        # Export evidence (both GET used by UI and POST)
        for method in ("GET", "POST"):
            r_exp = client.request(method, "/api/emergency/export-evidence")
            assert r_exp.status_code == 200
            exp = r_exp.json()
            assert exp["ok"] is True
            assert exp["findings_count"] == 1
            assert exp["filename"].endswith(".json")
            assert "bundle" in exp
            assert set(["exported_at", "scope", "agents", "findings", "court", "mcp", "metrics"]).issubset(
                exp["bundle"].keys()
            )
            bundle_path = Path(exp["export_path"])
            assert bundle_path.exists()
            assert tmp_path in bundle_path.resolve().parents

        # Clear data
        r_clr = client.post("/api/emergency/clear-data")
        assert r_clr.status_code == 200
        assert r_clr.json()["cleared"] is True
        assert client.get("/api/findings").json()["total"] == 0
        assert client.get("/api/court/status").json()["confirmed_last_hour"] == 0
        assert client.get("/api/court/status").json()["feed"] == []
        assert client.get("/api/terminal/state").json()["output"] == []


# ── 6. MCP Server Monitoring ──────────────────────────────────────────────────


class TestMcpMonitoring:
    def test_mcp_status_retry_configure_and_404(
        self, client: TestClient, isolated_control_center: Dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ):
        feed: LiveFeedManager = isolated_control_center["feed"]
        tmp_path: Path = isolated_control_center["tmp_path"]

        # Create isolated opencode.json with connected, failed, and disabled servers
        opencode_cfg = {
            "mcp": {
                "local-ok": {
                    "type": "local",
                    "command": ["python", "-V"],
                    "enabled": True,
                    "timeout": 30000,
                },
                "local-missing-bin": {
                    "type": "local",
                    "command": ["definitely_nonexistent_mcp_binary_xyz"],
                    "enabled": True,
                },
                "local-missing-env": {
                    "type": "local",
                    "command": ["python", "-V"],
                    "environment": {"API_KEY": "{env:MISSING_TEST_MCP_TOKEN}"},
                    "enabled": True,
                },
                "remote-ok": {
                    "type": "remote",
                    "url": "https://mcp.example.com/sse",
                    "enabled": True,
                },
                "disabled-srv": {
                    "type": "local",
                    "command": ["python", "-V"],
                    "enabled": False,
                },
            }
        }
        cfg_file = tmp_path / "opencode.json"
        cfg_file.write_text(json.dumps(opencode_cfg), encoding="utf-8")
        monkeypatch.setattr(feed, "_opencode_path", cfg_file)
        monkeypatch.delenv("MISSING_TEST_MCP_TOKEN", raising=False)

        t0 = time.perf_counter()
        r_status = client.get("/api/mcp/status")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        assert r_status.status_code == 200
        assert elapsed_ms < 500.0

        st = r_status.json()
        assert st["configured"] == 5
        assert st["connected"] == 2
        assert st["failed"] == 2
        assert st["disabled"] == 1

        by_id = {s["id"]: s for s in st["servers"]}
        assert by_id["local-ok"]["status"] == "connected"
        assert by_id["local-missing-bin"]["status"] == "failed"
        assert "not found" in (by_id["local-missing-bin"]["error"] or "")
        assert by_id["local-missing-env"]["status"] == "failed"
        assert "MISSING_TEST_MCP_TOKEN" in (by_id["local-missing-env"]["error"] or "")
        assert by_id["disabled-srv"]["status"] == "disabled"

        # Supply missing env var and retry all failed servers
        monkeypatch.setenv("MISSING_TEST_MCP_TOKEN", "secret-ok")
        r_retry = client.post("/api/mcp/retry", json={})
        assert r_retry.status_code == 200
        ret = r_retry.json()
        assert ret["ok"] is True
        assert set(ret["retried"]) == {"local-missing-bin", "local-missing-env"}
        assert ret["connected"] == 3
        assert ret["failed"] == 1

        # Configure failed server to valid command & enable disabled server
        r_cfg = client.post(
            "/api/mcp/configure",
            json={
                "server_id": "local-missing-bin",
                "enabled": True,
                "timeout": 45000,
                "command_or_url": "python -V",
            },
        )
        assert r_cfg.status_code == 200
        cfg_res = r_cfg.json()
        assert cfg_res["ok"] is True
        assert cfg_res["server"]["status"] == "connected"
        assert cfg_res["server"]["timeout"] == 45000
        assert cfg_res["failed"] == 0

        # Unknown server -> 404
        assert client.post("/api/mcp/retry", json={"server_id": "does-not-exist"}).status_code == 404
        assert (
            client.post(
                "/api/mcp/configure",
                json={"server_id": "does-not-exist", "enabled": True},
            ).status_code
            == 404
        )


# ── 7. System Health Metrics, Court & Interactive Terminal ────────────────────


class TestMetricsAndTerminal:
    def test_system_metrics_and_threshold_alerts(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ):
        r_metrics = client.get("/api/metrics/system")
        assert r_metrics.status_code == 200
        m = r_metrics.json()
        for key in (
            "timestamp",
            "cpu_percent",
            "ram_percent",
            "disk_io_mb_s",
            "net_throughput_kb_s",
            "disk_free_gb",
            "alerts",
            "history",
        ):
            assert key in m

        # Simulate CPU > 80% for >= 30s, RAM > 90%, Disk < 1GB free
        fake_now = [1000.0]
        monkeypatch.setattr(live_feed_mod.time, "time", lambda: fake_now[0])
        monkeypatch.setattr(psutil, "cpu_percent", lambda interval=None: 88.5)
        monkeypatch.setattr(
            psutil,
            "virtual_memory",
            lambda: SimpleNamespace(percent=94.2, used=15 * 1024**3, total=16 * 1024**3),
        )
        monkeypatch.setattr(
            psutil,
            "disk_usage",
            lambda _path: SimpleNamespace(percent=99.1, free=500 * 1024**2, total=100 * 1024**3),
        )

        # First sample starts CPU high timer; RAM & Disk alerts fire immediately
        m1 = client.get("/api/metrics/system").json()
        assert "🔴 RAM > 90%" in m1["alerts"]
        assert "🟡 Disk < 1GB free" in m1["alerts"]
        assert "🟡 CPU > 80% for 30s" not in m1["alerts"]

        # Advance time 31 seconds -> CPU alert fires too
        fake_now[0] += 31.0
        m2 = client.get("/api/metrics/system").json()
        assert "🟡 CPU > 80% for 30s" in m2["alerts"]
        assert "🔴 RAM > 90%" in m2["alerts"]
        assert "🟡 Disk < 1GB free" in m2["alerts"]

    def test_terminal_rest_commands_and_state(self, client: TestClient):
        r_state = client.get("/api/terminal/state")
        assert r_state.status_code == 200
        st = r_state.json()
        assert st["prompt"] == "hunterai>"
        assert "help" in st["commands"]
        assert "status" in st["commands"]

        for cmd, expected_substr in [
            ("help", "Available commands:"),
            ("status", "[Agents]"),
            ("scope add https://example.com", "Added target: https://example.com"),
            ("scope lock", "LOCKED"),
            ("scan --target https://example.com --mode recon", "[Agent-Brain] Started recon scan"),
            ("agent pause brain", "[Agent-Brain] pause"),
            ("mcp status", "[MCP]"),
            ("court status", "[Court]"),
            ("emergency stop", "ALL AGENTS STOPPED"),
        ]:
            resp = client.post("/api/terminal/command", json={"command": cmd})
            assert resp.status_code == 200
            body = resp.json()
            assert body["ok"] is True, f"Command {cmd!r} failed: {body}"
            assert expected_substr in body["output"]

        r_bad = client.post("/api/terminal/command", json={"command": "nonexistentcmd"})
        assert r_bad.status_code == 200
        assert r_bad.json()["ok"] is False

        r_clr = client.post("/api/terminal/command", json={"command": "clear"})
        assert r_clr.status_code == 200
        assert r_clr.json()["cleared"] is True
        assert client.get("/api/terminal/state").json()["output"] == []


# ── 8. All 5 WebSocket Streams ────────────────────────────────────────────────


class TestWebSockets:
    def test_ws_agents_findings_metrics_court_streams(
        self, client: TestClient, isolated_control_center: Dict[str, Any]
    ):
        feed: LiveFeedManager = isolated_control_center["feed"]
        feed.add_finding({"id": "FND-WS-1", "title": "WS Test Finding", "severity": "High"})
        feed.add_court_event("FND-WS-1", "WS Test Claim", "VERIFYING")

        with client.websocket_connect("/ws/agents") as ws:
            msg = ws.receive_json()
            assert "agents" in msg and "summary" in msg
            ws.send_text("refresh")
            msg2 = ws.receive_json()
            assert msg2["summary"]["total"] == 4

        with client.websocket_connect("/ws/findings") as ws:
            msg = ws.receive_json()
            assert msg["total"] == 1
            assert msg["findings"][0]["id"] == "FND-WS-1"

        with client.websocket_connect("/ws/metrics") as ws:
            msg = ws.receive_json()
            assert "cpu_percent" in msg and "ram_percent" in msg and "history" in msg

        with client.websocket_connect("/ws/court") as ws:
            msg = ws.receive_json()
            assert msg["under_verification"] == 1
            assert msg["feed"][0]["id"] == "FND-WS-1"

    def test_ws_terminal_command_roundtrip(self, client: TestClient):
        with client.websocket_connect("/ws/terminal") as ws:
            init_msg = ws.receive_json()
            assert init_msg["type"] == "state"
            assert init_msg["prompt"] == "hunterai>"

            ws.send_json({"type": "ping"})
            assert ws.receive_json() == {"type": "pong"}

            ws.send_json({"command": "status"})
            out_msg = ws.receive_json()
            assert out_msg["type"] == "output"
            assert out_msg["ok"] is True
            assert out_msg["command"] == "status"
            assert "[Agents]" in out_msg["output"]

            ws.send_text("help")
            help_msg = ws.receive_json()
            assert help_msg["type"] == "output"
            assert "Available commands:" in help_msg["output"]


# ── 9. JS / HTML / Router / Backend Contract Consistency ──────────────────────


class TestJsHtmlApiContractConsistency:
    def test_all_js_element_ids_exist_in_templates_and_static_html(self):
        dash_html = (UI_WEB_DIR / "templates" / "dashboard.html").read_text(encoding="utf-8")
        index_html = (UI_WEB_DIR / "static" / "index.html").read_text(encoding="utf-8")

        dash_ids = set(re.findall(r'id="([^"]+)"', dash_html))
        index_ids = set(re.findall(r'id="([^"]+)"', index_html))

        for js_path in sorted((UI_WEB_DIR / "static" / "js").glob("*.js")):
            txt = js_path.read_text(encoding="utf-8")
            expected: Set[str] = set()
            expected |= set(re.findall(r'getElementById\(["\']([^"\']+)["\']\)', txt))
            expected |= set(re.findall(r'(?:canvasId|valueId):\s*["\']([^"\']+)["\']', txt))
            expected |= set(re.findall(r'(?:openModal|closeModal)\(["\']([^"\']+)["\']\)', txt))
            for arr in re.findall(r'\[([^\]]+)\]\.forEach', txt):
                expected |= set(re.findall(r'["\']([^"\']+)["\']', arr))
            for bid in re.findall(r'bindClick\(["\']([^"\']+)["\']', txt):
                expected.add(bid)
            for sid in re.findall(r'set(?:Val|Num)\(["\']([^"\']+)["\']', txt):
                expected.add(sid)

            assert not (expected - dash_ids), (
                f"{js_path.name} references IDs missing from dashboard.html: {sorted(expected - dash_ids)}"
            )
            # `initial-state` is Jinja-only and guarded by `if (!el) return;` in static index.html
            assert not ((expected - {"initial-state"}) - index_ids), (
                f"{js_path.name} references IDs missing from index.html: "
                f"{sorted((expected - {'initial-state'}) - index_ids)}"
            )

    def test_all_js_rest_and_ws_endpoints_match_fastapi_routes(self):
        openapi_paths = app.openapi().get("paths", {})
        ws_paths = {
            getattr(route, "path", "")
            for route in app.routes
            if getattr(route, "path", "").startswith("/ws")
        }

        expected_rest = [
            ("GET", "/api/agents"),
            ("POST", "/api/agents/{agent_id}/start"),
            ("POST", "/api/agents/{agent_id}/pause"),
            ("POST", "/api/agents/{agent_id}/stop"),
            ("POST", "/api/agents/{agent_id}/restart"),
            ("GET", "/api/findings"),
            ("GET", "/api/findings/{finding_id}"),
            ("POST", "/api/findings/{finding_id}/export-burp"),
            ("POST", "/api/findings/{finding_id}/false-positive"),
            ("GET", "/api/court/status"),
            ("GET", "/api/metrics/system"),
            ("GET", "/api/scope"),
            ("POST", "/api/scope"),
            ("POST", "/api/scope/lock"),
            ("POST", "/api/scope/check"),
            ("GET", "/api/mcp/status"),
            ("POST", "/api/mcp/retry"),
            ("POST", "/api/mcp/configure"),
            ("POST", "/api/emergency/stop-all"),
            ("POST", "/api/emergency/pause-all"),
            ("POST", "/api/emergency/clear-data"),
            ("GET", "/api/emergency/export-evidence"),
            ("GET", "/api/terminal/state"),
            ("POST", "/api/terminal/command"),
        ]
        for method, path in expected_rest:
            assert path in openapi_paths, f"Missing route {path} in FastAPI app"
            assert method.lower() in openapi_paths[path], (
                f"Method {method} missing for route {path}"
            )

        js_ws_paths: Set[str] = set()
        for js_path in (UI_WEB_DIR / "static" / "js").glob("*.js"):
            txt = js_path.read_text(encoding="utf-8")
            js_ws_paths |= set(
                re.findall(r'connectChannel\([^,]+,\s*["\']([^"\']+)["\']', txt)
            )
        assert js_ws_paths == {"/ws/agents", "/ws/findings", "/ws/metrics", "/ws/court", "/ws/terminal"}
        assert js_ws_paths.issubset(ws_paths)

    def test_json_response_fields_match_js_expectations(
        self, client: TestClient, isolated_control_center: Dict[str, Any]
    ):
        feed: LiveFeedManager = isolated_control_center["feed"]
        feed.add_finding({"id": "FND-CON-1", "title": "Contract Probe", "severity": "Medium"})

        agents_payload = client.get("/api/agents").json()
        assert {"agents", "summary", "emergency_stopped", "timestamp"}.issubset(agents_payload)
        assert {"id", "name", "role", "status", "status_badge", "current_task", "cpu_percent", "memory_mb", "last_action_iso"}.issubset(
            agents_payload["agents"][0]
        )

        findings_payload = client.get("/api/findings").json()
        assert {"findings", "total", "alerts"}.issubset(findings_payload)
        assert {"id", "title", "severity", "source_agent", "verdict", "endpoint", "timestamp_iso", "exported_to_burp", "false_positive"}.issubset(
            findings_payload["findings"][0]
        )

        court_payload = client.get("/api/court/status").json()
        assert {"pending_claims", "under_verification", "confirmed_last_hour", "false_positives_rejected", "feed"}.issubset(
            court_payload
        )

        scope_payload = client.get("/api/scope").json()
        assert {"targets", "active_target", "excluded_domains", "firewall_rules", "locked"}.issubset(
            scope_payload
        )

        mcp_payload = client.get("/api/mcp/status").json()
        assert {"configured", "connected", "failed", "disabled", "servers"}.issubset(mcp_payload)
        if mcp_payload["servers"]:
            assert {"id", "name", "type", "status", "enabled", "error", "command_or_url", "timeout", "last_checked_iso"}.issubset(
                mcp_payload["servers"][0]
            )

        metrics_payload = client.get("/api/metrics/system").json()
        assert {"cpu_percent", "ram_percent", "disk_io_mb_s", "net_throughput_kb_s", "disk_free_gb", "alerts", "history"}.issubset(
            metrics_payload
        )

        terminal_payload = client.get("/api/terminal/state").json()
        assert {"prompt", "output", "history", "commands"}.issubset(terminal_payload)

    def test_no_external_cdns_or_hardcoded_windows_paths_in_control_center(self):
        cdn_patterns = ("cdn.", "unpkg.com", "jsdelivr", "googleapis", "cloudflare")
        cc_ui_files = {
            UI_WEB_DIR / "app.py",
            UI_WEB_DIR / "legacy_routes.py",
            UI_WEB_DIR / "templates" / "dashboard.html",
            UI_WEB_DIR / "static" / "dashboard.css",
            UI_WEB_DIR / "static" / "dashboard.js",
            UI_WEB_DIR / "static" / "index.html",
        }
        cc_ui_dirs = {UI_WEB_DIR / "api", UI_WEB_DIR / "ws"}

        for root in (DASHBOARD_CORE_DIR, UI_WEB_DIR):
            for file_path in root.rglob("*"):
                if not file_path.is_file() or "__pycache__" in file_path.parts:
                    continue
                if file_path.suffix not in (".py", ".html", ".css", ".js"):
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                assert "E:\\Agant" not in content and "E:/Agant" not in content, (
                    f"Hardcoded path found in {file_path}"
                )
                is_cc_file = (
                    DASHBOARD_CORE_DIR in file_path.parents
                    or file_path in cc_ui_files
                    or any(d in file_path.parents for d in cc_ui_dirs)
                )
                if not is_cc_file:
                    continue
                low = content.lower()
                for cdn in cdn_patterns:
                    assert cdn not in low, f"External CDN reference '{cdn}' found in {file_path}"
