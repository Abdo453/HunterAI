"""LEDGER-021 (M3b): Claude-like chat UI + unified model picker.

The new ``/chat`` page is served by the existing FastAPI app, its static assets
resolve, and the model picker consumes the unified catalog using the
``api:<provider>:<model>`` / ``local:<model>`` id convention.
"""
from __future__ import annotations

from starlette.testclient import TestClient

from ui.web.app import app


def _client() -> TestClient:
    return TestClient(app)


def test_chat_page_is_served():
    c = _client()
    r_redir = c.get("/chat", follow_redirects=False)
    assert r_redir.status_code == 302
    assert r_redir.headers.get("location") == "/?section=chat"

    r = c.get("/?section=chat")
    assert r.status_code == 200
    assert 'id="sec-chat"' in r.text
    assert 'window._defaultSection="chat"' in r.text
    assert 'id="secChatCopilotMount"' in r.text
    assert "/static/copilot-drawer.js" in r.text
    assert "/static/platform-client.js" in r.text


def test_chat_static_assets_are_served():
    c = _client()
    assert c.get("/static/chat.css").status_code == 200
    assert c.get("/static/chat.js").status_code == 200


def test_catalog_uses_unified_id_convention():
    d = _client().get("/api/models/catalog").json()
    assert "policy" in d
    assert isinstance(d["choices"], list)
    for ch in d["choices"]:
        if ch["kind"] == "cloud":
            assert ch["id"].startswith("api:")
            assert ch["id"].count(":") == 2          # api:<provider>:<model>
        else:
            assert ch["id"].startswith("local:")


def test_root_page_still_works():
    assert _client().get("/").status_code == 200
