"""
Tests for FIX 1: Connect Browser Sensor to BurpLiveEventStream.

Verifies:
1. StatefulBrowserSession, ActiveBrowserAgent, and BrowserBrainLoop accept `event_stream`
   and resolve runtime type hints without circular imports.
2. StatefulBrowserSession._extract_api_endpoints() and live request interception emit
   deduplicated `browser_endpoint_discovered` events to BurpLiveEventStream.
3. ActiveBrowserAgent emits `browser_endpoint_discovered` events from intercepted APIs,
   DOM/JS extraction, and live Playwright traffic.
4. BrowserBrainLoop propagates `event_stream` to StatefulBrowserSession and emits endpoints.
"""
from __future__ import annotations

import functools
import http.server
import threading
import typing
from types import SimpleNamespace

import pytest

from core.browser.active_browser_agent import PLAYWRIGHT_READY, ActiveBrowserAgent
from core.browser.browser_brain_loop import BrowserBrainLoop
from core.browser.session import InterceptedRequest, StatefulBrowserSession
from core.burp_gateway.event_stream import BurpLiveEventStream, StreamEvent


class _MiniAppHandler(http.server.BaseHTTPRequestHandler):
    """Minimal local HTTP server for deterministic browser sensor tests."""

    html_body: str = ""

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/api/"):
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        payload = self.html_body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        return


def _start_local_server(html_body: str) -> tuple[http.server.ThreadingHTTPServer, str]:
    class Handler(_MiniAppHandler):
        pass

    Handler.html_body = html_body
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def test_event_stream_parameters_and_type_hints(tmp_path):
    """Ensure constructors accept event_stream and typing.get_type_hints resolves cleanly."""
    stream = BurpLiveEventStream()

    session = StatefulBrowserSession(
        target_url="https://target.local",
        output_dir=tmp_path / "session",
        event_stream=stream,
    )
    assert session.event_stream is stream

    agent = ActiveBrowserAgent(
        headless=True,
        screenshots_dir=str(tmp_path / "shots"),
        event_stream=stream,
    )
    assert agent.event_stream is stream

    loop = BrowserBrainLoop(
        target_url="https://target.local",
        session=session,
        event_stream=stream,
    )
    assert loop.event_stream is stream

    # Verify type hints resolve cleanly (no NameError / circular import)
    assert "event_stream" in typing.get_type_hints(StatefulBrowserSession.__init__)
    assert "event_stream" in typing.get_type_hints(ActiveBrowserAgent.__init__)
    assert "event_stream" in typing.get_type_hints(BrowserBrainLoop.__init__)


def test_stateful_browser_session_extract_api_endpoints_emits_and_deduplicates(tmp_path):
    """_extract_api_endpoints extracts DOM + network endpoints, emits StreamEvents, and deduplicates."""
    stream = BurpLiveEventStream()
    received: list[StreamEvent] = []
    stream.add_sync_listener(received.append)

    session = StatefulBrowserSession(
        target_url="https://target.local",
        output_dir=tmp_path / "session",
        event_stream=stream,
    )
    session.dom_snapshots["https://target.local/app"] = """
    <html>
      <body>
        <form action="/api/v1/login" method="post">
          <input type="text" name="username" />
        </form>
        <script>
          fetch('/api/v1/profile');
          fetch("/api/v2/orders", { method: "POST" });
          axios.delete("/api/v1/session");
          const gql = "/graphql";
          const logo = "/static/logo.png";
          const tracker = "https://google-analytics.com/api/collect";
        </script>
      </body>
    </html>
    """
    session.network_history.append(
        InterceptedRequest(
            url="https://target.local/rest/items",
            method="PUT",
            resource_type="xhr",
        )
    )

    extracted = session._extract_api_endpoints()
    by_url = {(ep["method"], ep["url"]): ep for ep in extracted}

    assert ("POST", "https://target.local/api/v1/login") in by_url
    assert ("GET", "https://target.local/api/v1/profile") in by_url
    assert ("POST", "https://target.local/api/v2/orders") in by_url
    assert ("DELETE", "https://target.local/api/v1/session") in by_url
    assert ("GET", "https://target.local/graphql") in by_url
    assert ("PUT", "https://target.local/rest/items") in by_url
    assert all("/static/logo.png" not in ep["url"] for ep in extracted)
    assert all("google-analytics.com" not in ep["url"] for ep in extracted)

    assert len(received) == 6
    for evt in received:
        assert isinstance(evt, StreamEvent)
        assert evt.event_type == "browser_endpoint_discovered"
        assert evt.data["type"] == "browser_endpoint_discovered"
        assert evt.data["source"] == "browser"
        assert evt.data["url"].startswith("https://target.local/")
        assert evt.data["method"] in {"GET", "POST", "PUT", "DELETE"}

    # Repeated call must not emit duplicate events
    session._extract_api_endpoints()
    assert len(received) == 6


def test_stateful_browser_session_live_request_hook_emits_and_filters_static(tmp_path):
    """_handle_pw_request emits API/XHR requests live and skips static assets."""
    stream = BurpLiveEventStream()
    session = StatefulBrowserSession(
        target_url="https://target.local",
        output_dir=tmp_path / "session",
        event_stream=stream,
    )

    api_req = SimpleNamespace(
        url="https://target.local/api/v1/users?active=true",
        method="GET",
        resource_type="xhr",
        headers={"accept": "application/json"},
        post_data=None,
    )
    img_req = SimpleNamespace(
        url="https://target.local/assets/banner.png",
        method="GET",
        resource_type="image",
        headers={},
        post_data=None,
    )

    session._handle_pw_request(api_req)
    session._handle_pw_request(img_req)

    events = stream.get_recent_events()
    assert len(events) == 1
    assert events[0].event_type == "browser_endpoint_discovered"
    assert events[0].data["url"] == "https://target.local/api/v1/users?active=true"
    assert events[0].data["method"] == "GET"
    assert events[0].data["source"] == "browser"

    # Subsequent batch extraction must not duplicate already-emitted live request
    session._extract_api_endpoints()
    assert len(stream.get_recent_events()) == 1


@pytest.mark.asyncio
async def test_stateful_browser_session_navigate_emits_events(tmp_path, monkeypatch):
    """navigate() extracts API endpoints from fetched HTML and emits to BurpLiveEventStream."""
    monkeypatch.setenv("DISABLE_PLAYWRIGHT", "1")
    html = """
    <html><body>
      <form action="/api/v1/search" method="POST"><input name="q" /></form>
      <script>fetch("/api/v1/status");</script>
    </body></html>
    """
    server, base_url = _start_local_server(html)
    try:
        stream = BurpLiveEventStream()
        session = StatefulBrowserSession(
            target_url=base_url,
            output_dir=tmp_path / "nav_session",
            event_stream=stream,
        )
        await session.start()
        try:
            body, status, _ = await session.navigate(base_url)
            assert status == 200
            assert body is not None
        finally:
            await session.close()

        events = stream.get_recent_events()
        emitted = {(e.data["method"], e.data["url"]) for e in events if e.event_type == "browser_endpoint_discovered"}
        assert ("POST", f"{base_url}/api/v1/search") in emitted
        assert ("GET", f"{base_url}/api/v1/status") in emitted
    finally:
        server.shutdown()
        server.server_close()


def test_active_browser_agent_extract_api_endpoints_emits(tmp_path):
    """ActiveBrowserAgent accepts event_stream and emits deduplicated endpoint events."""
    stream = BurpLiveEventStream()
    agent = ActiveBrowserAgent(
        headless=True,
        screenshots_dir=str(tmp_path / "shots"),
        event_stream=stream,
    )
    agent._intercepted_apis.append({
        "method": "POST",
        "url": "https://target.local/api/v1/checkout",
        "resource_type": "fetch",
        "headers": {},
    })

    extracted = agent._extract_api_endpoints(
        html='<script>fetch("/api/v1/me");</script>',
        base_url="https://target.local",
    )
    pairs = {(e["method"], e["url"]) for e in extracted}
    assert ("POST", "https://target.local/api/v1/checkout") in pairs
    assert ("GET", "https://target.local/api/v1/me") in pairs

    events = stream.get_recent_events()
    assert len(events) == 2
    for evt in events:
        assert evt.event_type == "browser_endpoint_discovered"
        assert evt.data["type"] == "browser_endpoint_discovered"
        assert evt.data["source"] == "browser"

    # Deduplicated on repeat call
    agent._extract_api_endpoints()
    assert len(stream.get_recent_events()) == 2


@pytest.mark.asyncio
@pytest.mark.skipif(not PLAYWRIGHT_READY, reason="Playwright not available")
async def test_active_browser_agent_live_playwright_emits(tmp_path, monkeypatch):
    """ActiveBrowserAgent emits live XHR/fetch and DOM API endpoints during explore_and_interact."""
    import core.browser.active_browser_agent as aba_mod

    monkeypatch.setattr(aba_mod, "save_intercepted_api", lambda *a, **kw: None)
    monkeypatch.setattr(aba_mod, "push_to_vector_memory", lambda *a, **kw: None)

    html = """
    <html><head><title>Live Sensor Test</title></head>
    <body>
      <script>
        fetch('/api/v1/live-ping');
        const hiddenApi = '/api/v1/hidden-route';
      </script>
    </body></html>
    """
    server, base_url = _start_local_server(html)
    try:
        stream = BurpLiveEventStream()
        agent = ActiveBrowserAgent(
            headless=True,
            max_actions=2,
            timeout_secs=15.0,
            screenshots_dir=str(tmp_path / "live_shots"),
            event_stream=stream,
        )
        report = await agent.explore_and_interact(base_url)
        assert report.success is True

        events = stream.get_recent_events()
        urls = {e.data["url"] for e in events if e.event_type == "browser_endpoint_discovered"}
        assert f"{base_url}/api/v1/live-ping" in urls
        assert f"{base_url}/api/v1/hidden-route" in urls
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.asyncio
async def test_browser_brain_loop_propagates_event_stream(tmp_path, monkeypatch):
    """BrowserBrainLoop creates/wires StatefulBrowserSession with event_stream without duplicates."""
    monkeypatch.setenv("DISABLE_PLAYWRIGHT", "1")
    monkeypatch.chdir(tmp_path)

    html = """
    <html><body>
      <form action="/api/v1/auth" method="POST"><input name="token" /></form>
      <script>const ep = "/api/v1/catalog";</script>
    </body></html>
    """
    server, base_url = _start_local_server(html)
    try:
        stream = BurpLiveEventStream()
        loop = BrowserBrainLoop(
            target_url=base_url,
            max_pages=1,
            time_budget_sec=5.0,
            event_stream=stream,
        )
        assert loop.session.event_stream is stream

        await loop.run_loop()
        await loop.session.close()

        events = stream.get_recent_events()
        pairs = [(e.data["method"], e.data["url"]) for e in events if e.event_type == "browser_endpoint_discovered"]
        assert ("POST", f"{base_url}/api/v1/auth") in pairs
        assert ("GET", f"{base_url}/api/v1/catalog") in pairs
        # Ensure POST endpoint wasn't re-emitted as a duplicate GET by run_loop
        assert ("GET", f"{base_url}/api/v1/auth") not in pairs
    finally:
        server.shutdown()
        server.server_close()
