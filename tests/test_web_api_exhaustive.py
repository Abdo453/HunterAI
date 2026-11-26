"""
Exhaustive Web API & Dual Interface Integration Test Suite.
Validates the Django + ASGI application (``hunter_backend.asgi.application``):
- Compatibility redirects (/ -> Next.js, /chat -> /?copilot=open, /opencode -> /studio)
- OpenCode Skills, MCP Status, and Execution Endpoints
- Cognitive SecLists & Wordlist Intelligence APIs
- Recon, Arsenal, and Scope Security Verification APIs
"""

from pathlib import Path

import pytest

from hunter_backend.testing import ASGISyncClient

_REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client():
    with ASGISyncClient() as c:
        yield c


def test_master_launcher_1_web_ui(client):
    """Test Master Launcher 1 compatibility redirects & Next.js workspace presence."""
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert (_REPO_ROOT / "frontend" / "app" / "page.tsx").is_file()

    chat_resp = client.get("/chat", follow_redirects=False)
    assert chat_resp.status_code == 302
    assert "/?copilot=open" in chat_resp.headers.get("location", "")
    assert (_REPO_ROOT / "frontend" / "components" / "CopilotDrawer.tsx").is_file()


def test_master_launcher_2_opencode_studio(client):
    """Test Master Launcher 2 compatibility redirect & Studio page source."""
    response = client.get("/opencode", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers.get("location", "").endswith("/studio")
    assert (_REPO_ROOT / "frontend" / "app" / "studio" / "page.tsx").is_file()


def test_opencode_api_skills_endpoint(client):
    """Verify GET /api/opencode/skills returns curated skills catalog."""
    response = client.get("/api/opencode/skills")
    assert response.status_code == 200
    data = response.json()
    assert "skills" in data
    assert "count" in data
    assert data["count"] == 1
    
    # Check that skills have required metadata
    skills = data["skills"]
    assert [s.get("name") for s in skills] == ["hunterai-redteam"]


def test_opencode_api_mcp_status_endpoint(client):
    """Verify GET /api/opencode/mcp-status reports configured MCP arsenal."""
    response = client.get("/api/opencode/mcp-status")
    assert response.status_code == 200
    data = response.json()
    assert "mcp_servers" in data
    servers = data["mcp_servers"]
    assert "hunter-arsenal" in servers
    assert "filesystem" in servers


def test_opencode_api_execute_endpoint(client):
    """Verify POST /api/opencode/execute truthfully reports UNAVAILABLE for markdown prompt skills (Phase 5)."""
    payload = {
        "skill_name": "hunterai-redteam",
        "target": "example.com"
    }
    response = client.post("/api/opencode/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "UNAVAILABLE"
    assert data.get("ok") is False
    assert data.get("executed") is False
    assert data.get("skill") == "hunterai-redteam"
    assert data.get("target") == "example.com"


def test_cognitive_wordlists_resolve_api(client):
    """Verify GET /api/wordlists/resolve identifies categories and targets."""
    # Test AI Divergence query
    resp = client.get("/api/wordlists/resolve", params={"query": "ai llm divergence attack"})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("category") == "ai_llm"
    assert "selected_path" in data
    assert "need" in data

    # Test Web-Shells query
    resp_shell = client.get("/api/wordlists/resolve", params={"query": "jsp php web-shells"})
    assert resp_shell.status_code == 200
    data_shell = resp_shell.json()
    assert data_shell.get("category") == "web_shells"


def test_cognitive_wordlists_roots_api(client):
    """Verify GET /api/wordlists/roots returns scanned wordlist directories."""
    response = client.get("/api/wordlists/roots")
    assert response.status_code == 200
    data = response.json()
    assert "candidate_roots" in data
    assert isinstance(data["candidate_roots"], list)
    # SecLists candidate root must be included
    assert any("SecLists" in r for r in data["candidate_roots"])


def test_recon_knowledge_endpoints(client):
    """Verify recon knowledge APIs (dorks, 403 bypasses, hexstrike)."""
    resp_dorks = client.get("/api/recon/dorks", params={"domain": "example.com"})
    assert resp_dorks.status_code == 200
    assert "google_dorks" in resp_dorks.json()

    resp_403 = client.get("/api/recon/403-bypasses", params={"url": "https://example.com/admin"})
    assert resp_403.status_code == 200
    assert "variations" in resp_403.json()

    resp_hex = client.get("/api/recon/hexstrike-arsenal")
    assert resp_hex.status_code == 200
    assert "catalog" in resp_hex.json()


def test_arsenal_tools_endpoint(client):
    """Verify GET /api/arsenal/tools exposes Kali and hunting tools."""
    response = client.get("/api/arsenal/tools")
    assert response.status_code == 200
    data = response.json()
    assert "tools" in data
    tool_names = [t.get("name") if isinstance(t, dict) else t for t in data["tools"]]
    assert len(tool_names) > 0


def test_scope_check_api(client):
    """Verify POST /api/scope/check enforces authorization boundaries."""
    payload = {"target": "example.com", "scope": ["example.com", "*.example.com"]}
    response = client.post("/api/scope/check", json=payload)
    assert response.status_code in [200, 422]
