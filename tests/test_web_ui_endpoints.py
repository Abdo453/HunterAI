"""
Tests for Modern Cyber Web UI & OmniHunter API Endpoints.
Verifies FastAPI routing, HTML rendering, Arsenal API, Cognitive Deliberation API, and OmniHunter launcher.
"""
import pytest
from fastapi.testclient import TestClient

from ui.web.app import app


@pytest.fixture(scope="module")
def client():
    """Provides a synchronous TestClient for testing web endpoints."""
    with TestClient(app) as test_client:
        yield test_client


# ── 1. HTML Rendering Tests ──────────────────────────────────────────────────

def test_index_page_renders_5_pillars(client):
    """Verify that the home page renders the 5-pillar modern command center HTML."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert "HunterAI" in html
    assert "مركز قيادة OmniHunter الذاتي" in html
    assert "مرآة التفكير المعرفي (CoT)" in html
    assert "ترسانة كالي ومصفوفة MCP" in html
    assert "شات وتوجيه الوكلاء" in html
    assert "محكمة الأدلة والـ PoC" in html


# ── 2. Universal Kali Arsenal API Tests ───────────────────────────────────────

def test_api_arsenal_tools_list(client):
    """Verify listing all tools from the Kali arsenal catalog."""
    response = client.get("/api/arsenal/tools")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert data["total"] >= 50
    assert "installed" in data
    assert len(data["tools"]) == data["total"]

    # Test category filter
    resp_recon = client.get("/api/arsenal/tools?category=recon")
    assert resp_recon.status_code == 200
    data_recon = resp_recon.json()
    assert data_recon["total"] >= 5
    assert all(t["category"] == "recon" for t in data_recon["tools"])


def test_api_arsenal_tool_detail(client):
    """Verify retrieving agent persona and MCP schema for an individual tool."""
    response = client.get("/api/arsenal/tool/subfinder")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "subfinder"
    assert "system_prompt" in data
    assert "OPERATIONAL INVARIANTS" in data["system_prompt"]
    assert "mcp_schema" in data
    assert data["mcp_schema"]["name"] == "kali_subfinder"


def test_api_arsenal_run_tool(client):
    """Verify interactive execution of a tool via DynamicToolAgent."""
    payload = {
        "tool": "katana",
        "target": "http://example.com",
        "force_fallback": True,
        "thinking": True,
    }
    response = client.post("/api/arsenal/run", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["tool"] == "katana"
    assert data["success"] is True
    assert data["used_fallback"] is True
    assert "cognitive_deliberation" in data["structured_data"]


# ── 3. Cognitive Deliberation API Tests ───────────────────────────────────────

def test_api_cognitive_deliberate(client):
    """Verify strategic multi-hypothesis deliberation via API."""
    payload = {
        "target": "api.testcorp.internal",
        "objective": "Audit authentication token handling for IDOR leaks",
        "stakes": "high",
    }
    response = client.post("/api/cognitive/deliberate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "deliberation_id" in data
    assert len(data["hypotheses"]) >= 2
    assert "formatted_trace" in data
    assert "COGNITIVE REASONING ENGINE" in data["formatted_trace"]


# ── 4. OmniHunter Autonomous Mission Launcher API Tests ─────────────────────

def test_api_omni_mission_lifecycle(client):
    """Verify launch and status polling for an OmniHunter mission."""
    payload = {
        "target": "https://mission.target.local",
        "scope": ["mission.target.local"],
        "authorized": True,
        "enable_oob": True,
        "force_fallback": True,
        "threshold": 0.99,
        "max_cycles": 2,
    }
    resp_launch = client.post("/api/omni/launch", json=payload)
    assert resp_launch.status_code == 200
    launch_data = resp_launch.json()
    assert launch_data["status"] == "LAUNCHED"
    eng_id = launch_data["engagement_id"]

    # Poll status
    resp_status = client.get(f"/api/omni/status/{eng_id}")
    assert resp_status.status_code == 200
    status_data = resp_status.json()
    assert status_data["engagement_id"] == eng_id
    assert "current_phase" in status_data

    # Findings query
    resp_findings = client.get(f"/api/omni/findings/{eng_id}")
    assert resp_findings.status_code == 200
    findings_data = resp_findings.json()
    assert "findings" in findings_data


# ── 5. Enhanced Web Control Center API Tests ─────────────────────────────────

def test_api_enhanced_launch_all_and_status(client):
    """Verify master launch-all and status polling endpoint."""
    payload = {
        "target": "https://enhanced-target.local",
        "platform": "hackerone",
        "proxy": "http://127.0.0.1:8080",
        "force_fallback": True,
        "max_cycles": 2,
    }
    resp = client.post("/api/enhanced/omni/launch-all", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "LAUNCHED"
    mission_id = data["mission_id"]

    resp_st = client.get(f"/api/enhanced/omni/status/{mission_id}")
    assert resp_st.status_code == 200
    st_data = resp_st.json()
    assert st_data["mission_id"] == mission_id
    assert "current_phase" in st_data


def test_api_enhanced_burp_inspect(client):
    """Verify Burp log inspector API with pasted XML payload."""
    xml_sample = """<?xml version="1.0"?>
    <items>
      <item>
        <url>https://test.com/api/user?id=10</url>
        <method>GET</method>
        <status>200</status>
        <response base64="false">HTTP/1.1 200 OK\r\n\r\n{"secret": "AKIA1122334455667788"}</response>
      </item>
    </items>"""
    payload = {
        "source": "live",
        "content_text": xml_sample,
        "target": "https://test.com",
    }
    resp = client.post("/api/enhanced/burp/inspect", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["success"] is True
    assert data["total_findings"] >= 1
    assert any("AWS Access Key" in f["title"] for f in data["findings"])


def test_api_enhanced_browser_explore(client):
    """Verify AI browser exploration API."""
    payload = {
        "target_url": "https://browser-test.local",
        "max_pages": 1,
        "headless": True,
    }
    resp = client.post("/api/enhanced/browser/explore", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "target" in data
    assert "actions_performed" in data


def test_api_enhanced_arsenal_synthesize(client):
    """Verify dynamic AI command synthesis API with WAF and proxy."""
    payload = {
        "tool_name": "nuclei",
        "target": "https://synth-test.local",
        "waf_name": "Cloudflare",
        "proxy": "http://127.0.0.1:8080",
    }
    resp = client.post("/api/enhanced/arsenal/synthesize", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "synthesized_command" in data
    assert "nuclei" in data["synthesized_command"]
    assert "-proxy" in data["synthesized_command"]
    assert data["waf_evasion_applied"] is True


def test_api_enhanced_skills_catalog(client):
    """Verify skills catalog aggregation API."""
    resp = client.get("/api/enhanced/skills/catalog")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 100
    assert "stats" in data


def test_api_enhanced_elite_run(client):
    """Verify direct elite exploit skill execution API."""
    payload = {
        "skill_name": "http_smuggling",
        "target_url": "https://elite-test.local",
    }
    resp = client.post("/api/enhanced/skills/elite-run", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["skill_name"] == "http_smuggling"
    assert "verified" in data


def test_api_enhanced_reports_and_snapshots(client):
    """Verify reports and snapshots listing APIs."""
    resp_rep = client.get("/api/enhanced/reports")
    assert resp_rep.status_code == 200
    assert "reports" in resp_rep.json()

    resp_snap = client.get("/api/enhanced/snapshots")
    assert resp_snap.status_code == 200
    assert "snapshots" in resp_snap.json()
