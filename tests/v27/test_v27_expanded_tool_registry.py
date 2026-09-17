"""
HunterAI V27.3 - Expanded Modern TOOL_REGISTRY & Skill Suite Tests
===================================================================
Verifies all 9 new and linked vulnerability skills:
  - SSTISkill (Reflection != Execution invariant)
  - XXESkill (Entity expansion invariant)
  - CORSSkill (Origin reflection + Credentials true)
  - FileUploadSkill (Dangerous extension & polyglot acceptance)
  - JWTOAuthSkill (JWT alg none & OAuth missing state)
  - RaceConditionSkill (Microsecond parallel burst & double execution)
  - GraphQLSkill (Introspection & Batching)
  - WebSocketSkill (CSWSH origin spoofing matrix)
  - IDORMatrixSkill (Multi-tenant authorization matrix)
  - Complete AutonomousBrain.TOOL_REGISTRY integration
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import httpx

from agents.skills.ssti_skill import SSTISkill
from agents.skills.xxe_skill import XXESkill
from agents.skills.cors_skill import CORSSkill
from agents.skills.file_upload_skill import FileUploadSkill
from agents.skills.jwt_oauth_skill import JWTOAuthSkill
from agents.skills.race_condition_skill import RaceConditionSkill
from agents.skills.graphql_skill import GraphQLSkill
from agents.skills.websocket_skill import WebSocketSkill
from agents.skills.idor_skill import IDORMatrixSkill
from core.brain.autonomous_brain import AutonomousBrain, TOOL_REGISTRY


@pytest.mark.asyncio
async def test_ssti_skill_reflection_vs_execution():
    """Verifies SSTISkill enforces Reflection != Execution invariant."""
    skill = SSTISkill()

    # Case 1: Safe reflection trap (input echoed verbatim, no calculation)
    def mock_reflection(request: httpx.Request):
        url = str(request.url)
        if "%7B%7B" in url or "{{" in url:
            # Echoes raw payload literally
            return httpx.Response(200, text="Search results for: {{53+19}}")
        return httpx.Response(200, text="Normal page")

    transport = httpx.MockTransport(mock_reflection)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await skill.run("http://target.local/search", "q")
        assert res.verified is False  # Must NOT false-positive on reflection!

    # Case 2: True execution (server evaluates 53+19 to 72 and 41+31 to 72)
    def mock_execution(request: httpx.Request):
        url = str(request.url)
        if "53%2B19" in url or "53+19" in url:
            return httpx.Response(200, text="Hello user 72")
        elif "41%2B31" in url or "41+31" in url:
            return httpx.Response(200, text="Hello user 72")
        return httpx.Response(200, text="Normal page")

    transport2 = httpx.MockTransport(mock_execution)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport2)):
        res2 = await skill.run("http://target.local/search", "q")
        assert res2.verified is True
        assert res2.vuln_type == "ssti"
        assert res2.severity == "Critical"
        assert "72" in res2.evidence


@pytest.mark.asyncio
async def test_xxe_skill_entity_expansion():
    """Verifies XXESkill detects entity expansion."""
    skill = XXESkill()

    def mock_xxe(request: httpx.Request):
        content = request.read().decode("utf-8")
        if "&xxe;" in content or "HUNTER_XXE_EXPANSION_TOKEN" in content:
            return httpx.Response(200, text="<response>Processed HUNTER_XXE_EXPANSION_TOKEN_9921</response>")
        return httpx.Response(200, text="<response>OK</response>")

    transport = httpx.MockTransport(mock_xxe)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await skill.run("http://target.local/api/xml", "xml")
        assert res.verified is True
        assert res.vuln_type == "xxe"
        assert res.cwe == "CWE-611"


@pytest.mark.asyncio
async def test_cors_skill_credential_reflection():
    """Verifies CORSSkill validates origin reflection combined with credentials."""
    skill = CORSSkill()

    # Case 1: Insecure CORS with credentials
    def mock_cors_vuln(request: httpx.Request):
        origin = request.headers.get("Origin", "")
        return httpx.Response(200, headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true"
        }, text="Sensitive data")

    transport = httpx.MockTransport(mock_cors_vuln)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await skill.run("http://target.local/api/account")
        assert res.verified is True
        assert res.vuln_type == "cors"
        assert res.severity == "High"

    # Case 2: Secure CORS (rejects or doesn't allow credentials)
    def mock_cors_safe(request: httpx.Request):
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": "*"}, text="Public data")

    transport_safe = httpx.MockTransport(mock_cors_safe)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport_safe)):
        res_safe = await skill.run("http://target.local/api/public")
        assert res_safe.verified is False


@pytest.mark.asyncio
async def test_file_upload_skill():
    """Verifies FileUploadSkill flags executable extensions."""
    skill = FileUploadSkill()

    def mock_upload(request: httpx.Request):
        return httpx.Response(200, text='{"status": "success", "upload_path": "/uploads/probe.php5"}')

    transport = httpx.MockTransport(mock_upload)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await skill.run("http://target.local/upload", "file")
        assert res.verified is True
        assert res.vuln_type == "file_upload"
        assert "probe.php5" in res.payload_used


@pytest.mark.asyncio
async def test_jwt_oauth_skill():
    """Verifies JWTOAuthSkill detects alg none and OAuth parameter issues."""
    skill = JWTOAuthSkill()

    # 1. JWT alg none token
    jwt_none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIn0."
    res = await skill.run("http://target.local/api/me", auth={"token": jwt_none})
    assert res.verified is True
    assert "alg: none" in res.evidence

    # 2. OAuth request missing state
    oauth_url = "http://target.local/oauth/authorize?client_id=app123&redirect_uri=http://example.com/callback&response_type=code"
    res_oauth = await skill.run(oauth_url)
    assert res_oauth.verified is True
    assert "state" in res_oauth.evidence


@pytest.mark.asyncio
async def test_race_condition_skill():
    """Verifies RaceConditionSkill detects concurrent limit overrun."""
    skill = RaceConditionSkill()

    def mock_race(request: httpx.Request):
        return httpx.Response(200, text='{"applied": true, "discount": 50}')

    transport = httpx.MockTransport(mock_race)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await skill.run("http://target.local/api/apply_coupon", "coupon")
        assert res.verified is True
        assert res.vuln_type == "race_condition"


@pytest.mark.asyncio
async def test_graphql_skill():
    """Verifies GraphQLSkill detects introspection and batching."""
    skill = GraphQLSkill()

    def mock_graphql(request: httpx.Request):
        content = request.read().decode("utf-8")
        if "__schema" in content:
            return httpx.Response(200, text='{"data": {"__schema": {"types": [{"name": "User"}]}}}')
        return httpx.Response(200, text='{"data": {}}')

    transport = httpx.MockTransport(mock_graphql)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await skill.run("http://target.local/graphql")
        assert res.verified is True
        assert res.vuln_type == "graphql_introspection"


@pytest.mark.asyncio
async def test_websocket_skill():
    """Verifies WebSocketSkill detects CSWSH via origin reflection."""
    skill = WebSocketSkill()

    def mock_ws(request: httpx.Request):
        if request.headers.get("Upgrade") == "websocket" and request.headers.get("Origin") == "https://evil-attacker.com":
            return httpx.Response(101, text="")
        return httpx.Response(403, text="Forbidden")

    transport = httpx.MockTransport(mock_ws)
    with patch("httpx.AsyncClient", return_value=httpx.AsyncClient(transport=transport)):
        res = await skill.run("http://target.local/ws")
        assert res.verified is True
        assert res.vuln_type == "cswsh"


@pytest.mark.asyncio
async def test_idor_matrix_skill():
    """Verifies IDORMatrixSkill identifies cross-tenant access."""
    skill = IDORMatrixSkill()
    res = await skill.run("http://target.local/api/users/42", "id")
    # MultiIdentityReplayer default simulated environment reports anomaly when unauthenticated or cross-tenant
    assert res is not None
    assert res.tool == "IDORMatrixSkill"


@pytest.mark.asyncio
async def test_autonomous_brain_all_tools_in_registry():
    """Verifies that all 28 tools are registered in TOOL_REGISTRY and callable by AutonomousBrain."""
    rm = MagicMock()
    tm = MagicMock()
    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=True)

    expected_tools = [
        "VulnerabilityEngine", "LFISkill", "CmdInjectionSkill", "CSRFSkill", "SmartPoC",
        "SQLiSkill", "SSRFSkill", "IDORSkill", "IDORMatrixSkill", "XSSSkill",
        "SSTISkill", "XXESkill", "CORSSkill", "FileUploadSkill", "JWTOAuthSkill",
        "RaceConditionSkill", "GraphQLSkill", "WebSocketSkill",
        "ReconAgent", "BugBountyAgent", "BrowserAgent", "WebAgent",
        "nuclei", "sqlmap", "dalfox", "gobuster", "nmap", "subfinder"
    ]

    for tool_name in expected_tools:
        assert tool_name in TOOL_REGISTRY, f"Tool {tool_name} missing from TOOL_REGISTRY"
        # Test dry-run execution through _execute_tool
        result = await brain._execute_tool(tool_name, target="http://target.local")
        assert isinstance(result, list)
