"""
Hermetic Test Suite for Dual Unified Launchers (Web UI & OpenCode Modes)
========================================================================
Validates:
1. CLI argument parsing for `pentest web`, `pentest ui`, `pentest opencode`, `pentest opencode-ui`
2. Support for `--web` and `--opencode` flags in `pentest all` and `pentest run`
3. Web application routes (`/opencode`, `/api/opencode/skills`, `/api/opencode/mcp-status`, `/api/opencode/execute`)
4. OpenCode manifest (217 skills across 5 packs) and MCP config integrity
"""

import json
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from pentest import build_parser
from ui.web.app import app


@pytest.fixture
def test_client():
    return TestClient(app)


def test_cli_argument_parsing():
    """Validates subparsers and flag routing for web and opencode modes."""
    parser = build_parser()

    # 1. web subcommand
    args_web = parser.parse_args(["web", "target.com", "--port", "9000", "--no-browser"])
    assert args_web.command == "web"
    assert args_web.target == "target.com"
    assert args_web.port == 9000
    assert args_web.no_browser is True

    # 2. ui alias
    args_ui = parser.parse_args(["ui", "app.target.com"])
    assert args_ui.command == "ui"
    assert args_ui.target == "app.target.com"

    # 3. opencode subcommand
    args_oc = parser.parse_args(["opencode", "sec.target.com", "--port", "8080", "--no-browser"])
    assert args_oc.command == "opencode"
    assert args_oc.target == "sec.target.com"
    assert args_oc.port == 8080
    assert args_oc.no_browser is True

    # 4. opencode-ui alias
    args_oc_ui = parser.parse_args(["opencode-ui"])
    assert args_oc_ui.command == "opencode-ui"
    assert args_oc_ui.target is None

    # 5. all with --web and --opencode flags
    args_all_web = parser.parse_args(["all", "target.com", "--web"])
    assert args_all_web.command == "all"
    assert args_all_web.web is True
    assert args_all_web.opencode is False

    args_all_oc = parser.parse_args(["run", "target.com", "--opencode"])
    assert args_all_oc.command == "run"
    assert args_all_oc.opencode is True
    assert args_all_oc.web is False


def test_opencode_web_routes(test_client):
    """Verifies that OpenCode Studio page and API endpoints return valid data."""
    # 1. GET /opencode HTML page
    res_page = test_client.get("/opencode")
    assert res_page.status_code == 200
    assert "OpenCode Studio" in res_page.text
    assert "skills-count-badge" in res_page.text

    # 2. GET /api/opencode/skills
    res_skills = test_client.get("/api/opencode/skills")
    assert res_skills.status_code == 200
    data_skills = res_skills.json()
    assert data_skills["count"] == 217
    assert len(data_skills["skills"]) == 217
    assert "library_inventory" in data_skills

    # 3. GET /api/opencode/mcp-status
    res_mcp = test_client.get("/api/opencode/mcp-status")
    assert res_mcp.status_code == 200
    data_mcp = res_mcp.json()
    assert data_mcp["status"] == "online"
    assert "hunter-arsenal" in data_mcp["mcp_servers"]
    assert "filesystem" in data_mcp["mcp_servers"]


def test_opencode_execute_endpoint(test_client):
    """Verifies POST /api/opencode/execute with validation and execution."""
    # 1. Missing target/skill returns 400
    res_bad = test_client.post("/api/opencode/execute", json={})
    assert res_bad.status_code == 400

    # 2. CORS skill execution via ABHToolBridge
    res_cors = test_client.post("/api/opencode/execute", json={
        "skill_name": "abh-cors-audit",
        "target": "https://example.com"
    })
    assert res_cors.status_code == 200
    data_cors = res_cors.json()
    assert data_cors["status"] == "ok"
    assert "job_id" in data_cors
    assert "CORS" in data_cors["output"]

    # 3. General skill execution
    res_gen = test_client.post("/api/opencode/execute", json={
        "skill_name": "acs-reconnaissance",
        "target": "target.com"
    })
    assert res_gen.status_code == 200
    data_gen = res_gen.json()
    assert data_gen["status"] == "ok"
    assert "target.com" in data_gen["output"]


def test_manifest_and_mcp_config_integrity():
    """Verifies the integrity of OpenCode manifest and config files."""
    repo_root = Path(__file__).resolve().parents[1]

    # Check MANIFEST.json
    manifest_file = repo_root / ".opencode" / "skills" / "MANIFEST.json"
    assert manifest_file.exists()
    mdata = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert mdata["count"] == 217
    assert len(mdata["skills"]) == 217

    # Verify all 5 packs exist
    packs = {s["pack"] for s in mdata["skills"]}
    assert "agentic-bug-hunter" in packs
    assert "anthropic-cyber" in packs
    assert "trailofbits" in packs
    assert "briiirussell" in packs
    assert "anthropics-official" in packs

    # Check opencode.json
    opencode_cfg = repo_root / "opencode.json"
    assert opencode_cfg.exists()
    cdata = json.loads(opencode_cfg.read_text(encoding="utf-8"))
    assert "mcp" in cdata
    assert "hunter-arsenal" in cdata["mcp"]
