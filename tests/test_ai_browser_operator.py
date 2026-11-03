"""
Tests for AI Browser Operator (Autonomous LLM-driven browser perception & action loop).
Hermetic offline tests verifying DOM affordance parsing, AI reasoning parser,
heuristic fallback decisions, sync runners, and Web UI integration.
"""
import pytest
from fastapi.testclient import TestClient

from core.browser.ai_browser_operator import (
    AIBrowserOperator,
    DOMAffordance,
    AICognitiveStep,
    run_ai_browser_session_sync,
)
from core.browser.active_browser_agent import ActiveBrowserReport
from ui.web.app import app


# ── 1. Data Structure & Parser Tests ──────────────────────────────────────────

def test_dom_affordance_representation():
    """Verify DOMAffordance captures key interactive attributes and formats clean summary."""
    affordance = DOMAffordance(
        index=1,
        tag="input",
        element_type="text",
        name_or_id="search_query",
        text_content="Search vuln db...",
        selector="input[name='search_query']",
    )
    summary = affordance.to_summary()
    assert "[#1]" in summary
    assert "<input" in summary
    assert "name='search_query'" in summary
    assert "text='Search vuln db...'" in summary
    assert "input[name='search_query']" in summary


def test_ai_cognitive_step_model():
    """Verify AICognitiveStep fields and timestamps."""
    step = AICognitiveStep(
        step_num=1,
        url="https://target.corp/login",
        thought="Test canary payload in username field to detect SQLi reflection.",
        action_type="fill",
        target_selector="input#username",
        value_used="' OR '1'='1",
    )
    assert step.step_num == 1
    assert step.action_type == "fill"
    assert step.value_used == "' OR '1'='1"
    assert step.timestamp > 0


def test_extract_json_from_ai_response():
    """Verify parsing AI output with markdown code blocks, raw JSON, and handling malformed strings."""
    operator = AIBrowserOperator()

    # Raw JSON
    raw_json = '{"thought": "Navigate to search", "action": "click", "element_index": 3, "value": ""}'
    parsed1 = operator._extract_json_from_ai_response(raw_json)
    assert parsed1 is not None
    assert parsed1["action"] == "click"
    assert parsed1["element_index"] == 3

    # Markdown fenced JSON
    fenced_json = """Based on the DOM, here is my tactical decision:
```json
{
  "thought": "Injecting canary string to probe reflection",
  "action": "fill",
  "element_index": 1,
  "value": "hunter_probe_1337"
}
```
Done."""
    parsed2 = operator._extract_json_from_ai_response(fenced_json)
    assert parsed2 is not None
    assert parsed2["action"] == "fill"
    assert parsed2["value"] == "hunter_probe_1337"

    # Malformed text
    malformed = "I do not know what to do here."
    parsed3 = operator._extract_json_from_ai_response(malformed)
    assert parsed3 is None


# ── 2. Heuristic AI Fallback Decision Tests ────────────────────────────────────

def test_heuristic_ai_decision_prioritizes_inputs():
    """Verify heuristic selects input affordance first with a canary probe."""
    operator = AIBrowserOperator()
    summary = "[#1] <input name='q'> (Selector: input[name='q'])\n[#2] <button text='Search'>"

    decision = operator._heuristic_ai_decision(summary, step_num=1)
    assert decision["action"] == "fill"
    assert decision["element_index"] == 1
    assert "hunter_probe" in decision["value"]


def test_heuristic_ai_decision_clicks_button():
    """Verify heuristic clicks available buttons once inputs are handled."""
    operator = AIBrowserOperator()
    summary = "[#1] <button text='Submit Search'> (Selector: button#submit)"

    decision = operator._heuristic_ai_decision(summary, step_num=3)
    assert decision["action"] == "click"
    assert decision["element_index"] == 2 or decision["element_index"] == 1


# ── 3. Synthetic Exploration & Sync Runner Tests ──────────────────────────────

def test_synthetic_ai_exploration():
    """Verify synthetic fallback returns full structured ActiveBrowserReport with AI thoughts."""
    operator = AIBrowserOperator()
    events = []
    operator.on_event = lambda ev: events.append(ev)

    report = operator._synthetic_ai_exploration("https://test.corp/login", "Audit auth form")
    assert isinstance(report, ActiveBrowserReport)
    assert report.success is True
    assert len(report.actions_performed) >= 2
    assert len(report.intercepted_api_endpoints) >= 1
    assert any("ai_thought" in act for act in report.actions_performed)
    assert len(events) > 0


def test_run_ai_browser_session_sync():
    """Verify isolated sync runner completes hermetically without blocking."""
    report = run_ai_browser_session_sync(
        target_url="https://hermetic-ai.test.corp",
        objective="Verify non-blocking execution",
        headless=True,
        timeout_secs=5.0,
    )
    assert isinstance(report, ActiveBrowserReport)
    assert report.success is True
    assert len(report.actions_performed) > 0


# ── 4. Web UI API Integration Test ─────────────────────────────────────────────

def test_web_ui_browser_ai_endpoint():
    """Verify POST /api/browser/browse routes to AI Operator when use_ai is True."""
    client = TestClient(app)
    response = client.post(
        "/api/browser/browse",
        json={
            "url": "https://test.corp",
            "use_ai": True,
            "visible": False,
            "objective": "Test AI browser web endpoint",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "target_url" in data
    assert "actions_performed" in data
    assert len(data["actions_performed"]) > 0
