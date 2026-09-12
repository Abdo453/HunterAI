"""
Unit Tests for Human-like Stateful Browser Exploration Subsystem:
1. DOMDiffEngine (structural hashing, mutation detection, element diffing)
2. ApplicationStateGraph (state registration, URL normalization, loop detection)
3. ActionDiscovery (priority scoring, element ranking, scope firewalling)
4. RequestDeduplicator (fingerprint hashing, duplicate request suppression)
5. HumanLikeExplorationEngine (end-to-end loop, manifest, stop reasons, bidirectional feedback)
"""
import pytest
from pathlib import Path

from core.browser.dom_diff import DOMDiffEngine, DOMDiffResult
from core.browser.state_graph import ApplicationStateGraph, AppState, StateTransition
from core.browser.action_discovery import ActionDiscovery, ActionCategory, ActionCandidate, RequestDeduplicator
from core.browser.session import StatefulBrowserSession
from core.browser.explorer import HumanLikeExplorationEngine, StopReason, ExplorationManifest


def test_dom_diff_engine():
    html_before = """
    <html>
        <body>
            <h1>Welcome</h1>
            <a href="/login">Login</a>
        </body>
    </html>
    """
    html_after = """
    <html>
        <body>
            <h1>Welcome</h1>
            <a href="/login">Login</a>
            <div id="auth-modal" class="modal">
                <form id="login-form" action="/api/v1/auth" method="POST">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <button type="submit" id="submit-btn">Sign In</button>
                </form>
            </div>
        </body>
    </html>
    """

    hash_before = DOMDiffEngine.compute_structural_hash(html_before)
    hash_after = DOMDiffEngine.compute_structural_hash(html_after)
    assert hash_before != hash_after

    diff = DOMDiffEngine.diff(html_before, html_after)
    assert diff.has_changes is True
    assert len(diff.new_forms) >= 1
    assert "username" in diff.new_inputs
    assert len(diff.new_buttons) >= 1
    assert len(diff.new_modals) >= 1


def test_state_graph_and_url_normalization(tmp_path):
    graph = ApplicationStateGraph(target_host="example.com")

    # URL normalization
    url1 = "https://example.com/items?page=1&sort=desc&utm_source=twitter"
    url2 = "https://example.com/items?page=2&sort=desc&utm_campaign=ad"

    norm1 = graph.normalize_url(url1)
    norm2 = graph.normalize_url(url2)
    assert norm1 == norm2
    assert "%7BPAGE%7D" in norm1 or "{PAGE}" in norm1
    assert "utm_source" not in norm1

    # State registration
    state1 = graph.register_state(url1, dom_hash="hash_a1", title="Items Page", auth_status="GUEST")
    state2 = graph.register_state(url2, dom_hash="hash_a1", title="Items Page", auth_status="GUEST")
    assert state1.state_id == state2.state_id

    # Transition recording and loop detection
    trans = graph.record_transition(
        from_state_id=state1.state_id,
        to_state_id="state_detail_01",
        trigger_action="click:item_link",
        network_requests=[{"url": "https://example.com/api/item/1", "method": "GET"}]
    )
    assert trans.from_state_id == state1.state_id

    # Loop detection
    graph.record_transition(state1.state_id, "state_detail_01", "click:item_link")
    assert graph.is_loop(state1.state_id, "click:item_link", max_repeats=2) is True
    assert graph.is_loop(state1.state_id, "click:other_link", max_repeats=2) is False

    # Save JSON
    export_file = tmp_path / "state_graph.json"
    graph.save_json(export_file)
    assert export_file.exists()


def test_action_discovery_and_priority_scoring():
    base_host = "target.com"
    html = """
    <html>
        <body>
            <a href="/login">User Login</a>
            <a href="/about">About Us</a>
            <a href="/logo.png">Logo</a>
            <a href="https://play.google.com/store/apps/details?id=app">Download App</a>
            <a href="https://googletagmanager.com/gtm.js">GTM</a>
            <form id="search-form" action="/search" method="GET">
                <input type="text" name="q" placeholder="Search products" />
                <button type="submit" id="search-btn">Search</button>
            </form>
            <button id="load-more">Load More API</button>
        </body>
    </html>
    """

    actions = ActionDiscovery.discover_actions_from_html(html, "https://target.com", base_host)
    assert len(actions) >= 4

    # Verification: External links must be strictly excluded by ThirdPartyDependencyFirewall
    for a in actions:
        assert "play.google.com" not in a.target_url
        assert "googletagmanager.com" not in a.target_url

    # Priority verification: Auth & Input must outrank standard navigation
    scores = {a.category: a.score for a in actions}
    assert scores.get(ActionCategory.AUTH, 0.0) > scores.get(ActionCategory.NAVIGATION, 0.0)
    assert scores.get(ActionCategory.USER_INPUT, 0.0) > scores.get(ActionCategory.STATIC, 0.0)


def test_request_deduplication():
    dedup = RequestDeduplicator()

    # First request: not duplicate
    assert dedup.is_duplicate("GET", "https://example.com/api/user?id=1") is False

    # Second request: not duplicate if max_occurrences is 2
    assert dedup.is_duplicate("GET", "https://example.com/api/user?id=1", max_occurrences=2) is False

    # Third identical request: detected as duplicate (React re-render noise)
    assert dedup.is_duplicate("GET", "https://example.com/api/user?id=1", max_occurrences=2) is True

    # Different parameter: distinct request
    assert dedup.is_duplicate("GET", "https://example.com/api/user?id=2", max_occurrences=2) is False


@pytest.mark.asyncio
async def test_human_like_exploration_engine(tmp_path):
    session = StatefulBrowserSession(
        target_url="https://example.com",
        output_dir=tmp_path / "browser_test",
        headless=True
    )
    explorer = HumanLikeExplorationEngine(
        session=session,
        max_pages=3,
        max_depth=1,
        time_budget_sec=10.0
    )

    result = await explorer.explore()
    assert "manifest" in result
    assert "lessons" in result
    assert "state_graph" in result

    manifest = result["manifest"]
    assert manifest["stop_reason"] in (
        StopReason.COMPLETED.value,
        StopReason.PAGE_LIMIT.value,
        StopReason.NO_NEW_SURFACE.value,
        StopReason.TIME_LIMIT.value,
        StopReason.COVERAGE_MET.value,
    )
    assert manifest["external_domains_blocked"] is True
    assert "coverage" in result
    assert "memory" in result

    # Test bidirectional feedback
    feedback_res = await explorer.explore_endpoint("/api/v2/products")
    assert feedback_res["status"] in ("EXPLORED", "BLOCKED_BY_FIREWALL")

    await session.close()