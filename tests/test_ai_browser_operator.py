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


# ── 5. Elite Browser Capabilities Tests (DOM Taint, Shadow DOM, State Graph, IDOR) ────

def test_dom_affordance_shadow_dom():
    """Verify affordance captures and displays shadow DOM membership."""
    aff = DOMAffordance(
        index=2,
        tag="button",
        element_type="submit",
        name_or_id="auth-btn",
        text_content="Sign In With Web3",
        selector="button#auth-btn",
        in_shadow=True,
    )
    summary = aff.to_summary()
    assert "[ShadowDOM]" in summary
    assert "Sign In With Web3" in summary
    assert aff.in_shadow is True


def test_dom_hash_and_state_graph_integration():
    """Verify structural DOM hashing and state graph tracking."""
    operator = AIBrowserOperator()
    affordances = [
        DOMAffordance(index=1, tag="input", element_type="text", name_or_id="q", text_content="", selector="input[name='q']"),
        DOMAffordance(index=2, tag="button", element_type="submit", name_or_id="btn", text_content="Search", selector="button#btn"),
    ]
    hash1 = operator._compute_dom_hash(affordances, "Search Page")
    hash2 = operator._compute_dom_hash(affordances, "Search Page")
    assert hash1 == hash2
    assert len(hash1) == 16

    # Changing title or elements changes state hash
    hash3 = operator._compute_dom_hash(affordances, "Admin Dashboard")
    assert hash1 != hash3


def test_loop_detection_and_unvisited_affordance_selection():
    """Verify operator avoids repetitive cycles by selecting unexplored affordances."""
    from core.browser.state_graph import ApplicationStateGraph

    operator = AIBrowserOperator()
    operator.state_graph = ApplicationStateGraph("target.corp")
    state = operator.state_graph.register_state(
        url="https://target.corp/app",
        dom_hash="abc123state",
        title="App Dashboard",
    )

    affordances = [
        DOMAffordance(index=1, tag="button", element_type="button", name_or_id="tab1", text_content="Tab 1", selector="button#tab1"),
        DOMAffordance(index=2, tag="button", element_type="button", name_or_id="tab2", text_content="Tab 2", selector="button#tab2"),
    ]

    # Simulate loop on tab1
    operator.state_graph.record_transition(state.state_id, state.state_id, "click on button#tab1")
    operator.state_graph.record_transition(state.state_id, state.state_id, "click on button#tab1")

    assert operator.state_graph.is_loop(state.state_id, "click on button#tab1", max_repeats=2) is True

    # Find alternative affordance
    alt = operator._find_unvisited_affordance(affordances, state.state_id)
    assert alt is not None
    assert alt.selector == "button#tab2"


def test_synthetic_exploration_includes_advanced_telemetry():
    """Verify report contains DOM XSS candidates, State Graph summary, WebSockets, and DOM mutations."""
    operator = AIBrowserOperator(session_storage_file="data/sessions/test_state.json")
    report = operator._synthetic_ai_exploration("https://elite-target.corp", "Autonomous hunt")

    assert report.state_graph_summary is not None
    assert report.state_graph_summary["total_states"] >= 2
    assert len(report.dom_xss_candidates) > 0
    assert report.dom_xss_candidates[0]["sink"] == "Element.innerHTML"
    assert len(report.intercepted_websockets) > 0
    assert "wss://" in report.intercepted_websockets[0]["url"]
    assert len(report.dom_mutations) > 0
    assert report.dom_mutations[0]["diff"]["has_changes"] is True
    assert operator.session_storage_file == "data/sessions/test_state.json"

