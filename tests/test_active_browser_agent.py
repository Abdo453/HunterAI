"""
Tests for Active Browser Agent (Playwright Autonomous Interaction).
Verifies active DOM exploration, form canary probing, network API interception,
and integration with OmniHunter assessment loop and Web UI.
"""
import pytest
from fastapi.testclient import TestClient

from core.browser.active_browser_agent import (
    ActiveBrowserAgent,
    ActiveBrowserReport,
    run_browser_exploration_sync,
)
from core.engine.omni_hunter_engine import AssessmentConfig, OmniHunterEngine
from ui.web.app import app


# ── 1. Active Browser Agent Unit Tests ────────────────────────────────────────

def test_active_browser_agent_fallback():
    """Verify fallback exploration provides structured actions and intercepted APIs."""
    agent = ActiveBrowserAgent(headless=True)
    report = agent._fallback_exploration("https://test.local", "Test fallback trigger")

    assert isinstance(report, ActiveBrowserReport)
    assert report.success is True
    assert len(report.pages_visited) >= 2
    assert len(report.actions_performed) >= 2
    assert len(report.intercepted_api_endpoints) >= 1
    assert "sessionid" in report.captured_tokens_and_cookies["cookies"]


def test_run_browser_exploration_sync_hermetic():
    """Verify the isolated sync runner safely returns structured report."""
    report = run_browser_exploration_sync(
        target_url="https://hermetic.test.local",
        headless=True,
        timeout_secs=5.0,
    )
    assert isinstance(report, ActiveBrowserReport)
    assert report.target_url == "https://hermetic.test.local"


# ── 2. OmniHunter Integration with Active Browser ────────────────────────────

def test_omni_hunter_web_phase_with_browser_enabled():
    """Verify OmniHunter incorporates browser discovered endpoints into surface."""
    config = AssessmentConfig(
        target_url="https://browser.test.corp",
        scope_domains=["browser.test.corp"],
        coverage_threshold=0.99,
        max_cycles=3,
        force_tool_fallback=True,
        enable_browser=True,
        authorized_by="Unit Test Operator",
    )
    engine = OmniHunterEngine(config)
    assert engine.config.enable_browser is True

    # Run assessment
    result = engine.run()
    assert result.phase_reached is not None
    # Verify endpoints populated in surface
    assert len(engine.surface["endpoints"]) > 0


# ── 3. Web UI /api/browser/browse API Endpoint Test ──────────────────────────

def test_api_browser_browse_endpoint():
    """Verify FastAPI /api/browser/browse triggers active exploration."""
    with TestClient(app) as client:
        payload = {
            "url": "https://api.test.local",
            "visible": False,
            "canary": "test_canary_payload",
        }
        resp = client.post("/api/browser/browse", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "target_url" in data
        assert "actions_performed" in data
        assert "intercepted_api_endpoints" in data
