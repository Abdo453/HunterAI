"""
Unit Tests for HunterAI Browser Sensor & Exploration Architecture
=================================================================
Verifies:
1. BrowserEventBus (publish/subscribe, typed routing, history)
2. ExplorationMemory (seen, clicked, failed, changed, new surface, duplicates, blocks)
3. CoverageEngine (multi-dimensional metrics, weighted overall, CLI table formatting)
4. StateDetector (semantic state classification: GUEST, LOGIN, AUTHENTICATED, ADMIN, UPLOAD, ERROR)
5. DOMAnalyzer (forms, buttons, links, structural hashing)
6. InteractionPlanner (information gain calculation and ranking)
7. ExplorationQueue (priority heap and frontier deduplication)
8. BrowserBrainLoop (sensor observation coordination)
"""
import asyncio
import json
import pytest
from pathlib import Path

from core.browser.action_discovery import ActionCandidate, ActionCategory
from core.browser.browser_brain_loop import BrowserBrainLoop, SensorObservationReport
from core.browser.browser_event_bus import BrowserEvent, BrowserEventBus, BrowserEventType
from core.browser.coverage_engine import CoverageEngine, ExplorationCoverageMetrics
from core.browser.dom_analyzer import DOMAnalyzer
from core.browser.exploration_memory import ExplorationMemory
from core.browser.exploration_queue import ExplorationQueue
from core.browser.interaction_planner import InteractionPlanner
from core.browser.session import StatefulBrowserSession
from core.browser.state_detector import SemanticAppState, StateDetector


@pytest.mark.asyncio
async def test_browser_event_bus():
    bus = BrowserEventBus()
    received_events = []

    async def on_page(event: BrowserEvent):
        received_events.append(event)

    bus.subscribe(BrowserEventType.PAGE_LOADED, on_page)

    ev1 = BrowserEvent(
        event_type=BrowserEventType.PAGE_LOADED,
        source_url="https://app.target.com/login",
        data={"title": "Sign In"}
    )
    ev2 = BrowserEvent(
        event_type=BrowserEventType.BUTTON_DISCOVERED,
        source_url="https://app.target.com/login",
        data={"selector": "#login_btn"}
    )

    await bus.publish(ev1)
    await bus.publish(ev2)

    assert len(received_events) == 1
    assert received_events[0].source_url == "https://app.target.com/login"
    assert bus.count_events(BrowserEventType.PAGE_LOADED) == 1
    assert bus.count_events(BrowserEventType.BUTTON_DISCOVERED) == 1
    assert len(bus.get_history()) == 2


def test_exploration_memory(tmp_path):
    mem = ExplorationMemory("app.target.com")

    mem.record_seen_url("https://app.target.com/home")
    mem.record_seen_state("state_home_123")

    rec1 = mem.record_action(
        selector="#submit-btn",
        action_type="click",
        url="https://app.target.com/home",
        success=True,
        new_surface_generated=True,
        dom_diff_summary={"added_elements": ["#new-modal"]}
    )

    mem.record_duplicate("https://app.target.com/home?page=1")
    mem.record_blocked("https://google-analytics.com/ga.js", "scope_firewall")

    assert mem.has_clicked("#submit-btn", "https://app.target.com/home") is True
    assert mem.has_clicked("#other-btn", "https://app.target.com/home") is False

    summary = mem.to_dict()
    assert summary["stats"]["seen_urls"] == 1
    assert summary["stats"]["seen_states"] == 1
    assert summary["stats"]["new_surface_actions"] == 1
    assert summary["stats"]["firewalled_blocked"] == 1

    out_file = tmp_path / "memory.json"
    mem.save_json(out_file)
    assert out_file.exists()


def test_coverage_engine():
    cov = CoverageEngine("https://app.target.com")

    cov.register_page_discovered("https://app.target.com/")
    cov.register_page_discovered("https://app.target.com/about")
    cov.register_page_visited("https://app.target.com/")

    cov.register_state("state_1", explored=True)
    cov.register_state("state_2", explored=False)

    cov.register_form("form_login", tested=True)
    cov.register_action("button:#btn1", executed=True)
    cov.register_api("https://app.target.com/api/v1/user", observed=True)
    cov.register_js("https://app.target.com/bundle.js", analyzed=True)
    cov.register_auth_state("AUTHENTICATED")

    metrics = cov.calculate_coverage()
    assert metrics.pages_visited == 1
    assert metrics.pages_discovered == 2
    assert metrics.pages_pct == 50.0
    assert metrics.forms_tested == 1
    assert metrics.forms_pct == 100.0
    assert metrics.overall_percentage > 0.0

    table = cov.format_coverage_table()
    assert "Exploration Coverage" in table
    assert "Pages" in table
    assert "States" in table
    assert "Forms" in table
    assert "Overall:" in table


def test_state_detector():
    login_html = "<html><head><title>Login</title></head><body><form action='/login'><input type='text' name='user'><input type='password' name='pass'><button>Sign In</button></form></body></html>"
    state = StateDetector.detect_state("https://target.com/auth/login", login_html)
    assert state == SemanticAppState.LOGIN_PAGE

    auth_html = "<html><head><title>User Account</title></head><body><p>Welcome, admin! <a href='/logout'>Log Out</a></p></body></html>"
    state = StateDetector.detect_state("https://target.com/account", auth_html)
    assert state == SemanticAppState.AUTHENTICATED

    dash_state = StateDetector.detect_state("https://target.com/dashboard", auth_html)
    assert dash_state == SemanticAppState.DASHBOARD

    admin_html = "<html><head><title>Administration Console</title></head><body><h1>Admin Panel</h1></body></html>"
    state = StateDetector.detect_state("https://target.com/admin/settings", admin_html)
    assert state == SemanticAppState.ADMIN_PORTAL

    upload_html = "<html><body><form enctype='multipart/form-data'><input type='file' name='avatar'></form></body></html>"
    state = StateDetector.detect_state("https://target.com/profile/edit", upload_html)
    assert state == SemanticAppState.UPLOAD_SURFACE

    err_html = "<html><body><h1>404 Not Found</h1></body></html>"
    state = StateDetector.detect_state("https://target.com/missing", err_html)
    assert state == SemanticAppState.ERROR_PAGE


def test_dom_analyzer():
    sample_html = """
    <html>
    <head><title>Test Store</title></head>
    <body>
        <a href="/products">Shop</a>
        <form action="/search" method="POST">
            <input type="text" name="q" value="camera" />
            <input type="hidden" name="csrf" value="token123" />
            <button type="submit" id="search-btn">Search</button>
        </form>
        <button id="modal-trigger">Open Modal</button>
    </body>
    </html>
    """
    res = DOMAnalyzer.analyze(sample_html, "https://store.target.com")
    assert len(res["forms"]) == 1
    form = res["forms"][0]
    assert form["method"] == "POST"
    assert len(form["fields"]) == 2
    assert form["fields"][0]["name"] == "q"

    assert len(res["links"]) == 1
    assert res["links"][0]["href"] == "https://store.target.com/products"
    assert res["structural_hash"] != "empty"


def test_interaction_planner_information_gain():
    action_auth = ActionCandidate(
        action_id="btn_auth",
        element_type="button",
        category=ActionCategory.AUTH,
        score=9.0,
        selector="#login-submit",
        label="Log In"
    )
    action_nav = ActionCandidate(
        action_id="link_about",
        element_type="a",
        category=ActionCategory.NAVIGATION,
        score=4.0,
        selector="a#about",
        label="About Us"
    )
    action_loop = ActionCandidate(
        action_id="btn_loop",
        element_type="button",
        category=ActionCategory.API_TRIGGER,
        score=7.0,
        selector="#cyclic-btn",
        label="Repeat"
    )

    def mock_has_clicked(sel):
        return sel == "a#about"

    def mock_is_loop(state_id, action_id):
        return action_id == "btn_loop"

    ig_auth = InteractionPlanner.calculate_information_gain(action_auth, mock_has_clicked, mock_is_loop, "state_1")
    ig_nav = InteractionPlanner.calculate_information_gain(action_nav, mock_has_clicked, mock_is_loop, "state_1")
    ig_loop = InteractionPlanner.calculate_information_gain(action_loop, mock_has_clicked, mock_is_loop, "state_1")

    assert ig_auth > 0.0
    assert ig_nav == 0.0  # already clicked -> novelty 0
    assert ig_loop == 0.0  # is loop -> penalty 1.0

    ranked = InteractionPlanner.rank_actions([action_auth, action_nav, action_loop], mock_has_clicked, mock_is_loop, "state_1")
    assert len(ranked) == 1
    assert ranked[0].action_id == "btn_auth"


def test_exploration_queue():
    q = ExplorationQueue()
    assert q.is_empty() is True

    q.enqueue("https://target.com/low", priority=0.3)
    q.enqueue("https://target.com/high", priority=0.9)
    q.enqueue("https://target.com/mid", priority=0.6)

    # Duplicate should not be re-enqueued
    assert q.enqueue("https://target.com/low", priority=0.8) is False

    assert len(q) == 3
    first = q.pop()
    assert first.url == "https://target.com/high"
    second = q.pop()
    assert second.url == "https://target.com/mid"
    third = q.pop()
    assert third.url == "https://target.com/low"
    assert q.is_empty() is True


@pytest.mark.asyncio
async def test_browser_brain_loop_coordination(tmp_path):
    session = StatefulBrowserSession(
        target_url="https://example.com",
        output_dir=tmp_path / "brain_loop_test",
        headless=True
    )
    loop = BrowserBrainLoop(
        target_url="https://example.com",
        session=session,
        max_pages=2,
        time_budget_sec=10.0,
        coverage_threshold=50.0
    )

    report = await loop.run_loop()
    assert isinstance(report, SensorObservationReport)
    assert report.target_url == "https://example.com"
    assert "overall_percentage" in report.coverage
    assert (tmp_path / "brain_loop_test" / "exploration_memory.json").exists()

    await session.close()
