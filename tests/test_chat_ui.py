"""Unified Copilot drawer UI + model picker catalog contract tests (Django + Next.js)."""
from __future__ import annotations

from pathlib import Path

from hunter_backend.testing import ASGISyncClient

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _client() -> ASGISyncClient:
    return ASGISyncClient()


def test_chat_page_is_served():
    with _client() as c:
        r_redir = c.get("/chat", follow_redirects=False)
        assert r_redir.status_code == 302
        assert r_redir.headers.get("location", "").endswith("/?copilot=open")

        r_json = c.get("/chat", params={"format": "json"})
        assert r_json.status_code == 200
        assert "/?copilot=open" in r_json.json()["redirect_to"]

    drawer_tsx = (_REPO_ROOT / "frontend" / "components" / "CopilotDrawer.tsx").read_text(encoding="utf-8")
    assert "/api/models/catalog" in drawer_tsx
    assert "/api/copilot/chat/stream" in drawer_tsx


def test_chat_static_assets_are_served():
    with _client() as c:
        r_cat = c.get("/api/models/catalog")
        assert r_cat.status_code == 200
        # Unified Next.js vendor assets exist for Studio/UI
        assert (_REPO_ROOT / "frontend" / "public" / "vendor" / "monaco" / "vs" / "loader.min.js").is_file()


def test_catalog_uses_unified_id_convention():
    with _client() as c:
        d = c.get("/api/models/catalog").json()
    assert "policy" in d
    assert isinstance(d["choices"], list)
    for ch in d["choices"]:
        if ch["kind"] == "cloud":
            assert ch["id"].startswith("api:")
            assert ch["id"].count(":") == 2  # api:<provider>:<model>
        else:
            assert ch["id"].startswith("local:")


def test_root_page_still_works():
    with _client() as c:
        r = c.get("/", follow_redirects=False)
        assert r.status_code == 302
        r_json = c.get("/?format=json")
        assert r_json.status_code == 200
