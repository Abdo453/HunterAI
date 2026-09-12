"""
Unit & Integration Tests for Playwright Browser Intelligence Subsystem:
- Playwright Engine DOM & Network Interception
- Browser Recon Skill
- Network Intelligence Skill
- Form Intelligence Skill
- Behavior Analysis Skill
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

import pytest

from core.browser.playwright_engine import (
    PlaywrightEngine,
    BrowserInspectionResult,
    FormRecord,
    FormFieldRecord,
    NetworkRequestRecord
)
from core.skill_registry import SkillRegistry
from core.workspace_manager import WorkspaceManager
from skills.base_skill import SkillContext
from tools.tool_manager import ToolManager


@pytest.fixture
def temp_workspace():
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def test_browser_skills_discovery():
    registry = SkillRegistry()
    registry.discover(force=True)

    all_names = registry.list_names()
    assert "browser_recon" in all_names
    assert "network_intelligence" in all_names
    assert "form_intelligence" in all_names
    assert "behavior_analysis" in all_names

    # Test instantiation
    b_recon = registry.instantiate("browser_recon")
    assert b_recon is not None
    assert b_recon.category == "browser"

    net_intel = registry.instantiate("network_intelligence")
    assert net_intel is not None
    assert net_intel.category == "browser"

    form_intel = registry.instantiate("form_intelligence")
    assert form_intel is not None

    behav = registry.instantiate("behavior_analysis")
    assert behav is not None


def test_browser_inspection_data_structures():
    req = NetworkRequestRecord(
        url="https://example.com/api/v1/user",
        method="POST",
        resource_type="xhr",
        headers={"Content-Type": "application/json"},
        post_data='{"username": "test"}',
        response_status=200,
        response_snippet='{"success": true}'
    )
    assert req.method == "POST"
    assert req.resource_type == "xhr"

    form = FormRecord(
        action="https://example.com/login",
        method="POST",
        form_id="login-form",
        fields=[
            FormFieldRecord(name="user", field_type="text", required=True),
            FormFieldRecord(name="pass", field_type="password", required=True),
        ],
        purpose_guess="login"
    )
    assert form.purpose_guess == "login"
    assert len(form.fields) == 2


@pytest.mark.asyncio
async def test_playwright_engine_mock_inspection(temp_workspace):
    engine = PlaywrightEngine(headless=True, timeout_seconds=10.0)

    # Test with a data: URI to verify DOM parsing without external internet dependency
    html_content = """
    <html>
        <head><title>Test App</title></head>
        <body>
            <a href="https://example.com/dashboard">Dashboard</a>
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Username" required />
                <input type="password" name="password" placeholder="Password" required />
                <button type="submit">Sign In</button>
            </form>
            <button class="tab-btn">Load More</button>
        </body>
    </html>
    """
    import base64
    b64_html = base64.b64encode(html_content.encode("utf-8")).decode("utf-8")
    data_url = f"data:text/html;base64,{b64_html}"

    ss_path = temp_workspace / "screenshot.png"
    result = await engine.inspect_url(data_url, screenshot_destination=ss_path, simulate_interactions=True)

    assert result.title == "Test App"
    assert len(result.links) >= 1
    assert any("dashboard" in l for l in result.links)
    assert len(result.forms) >= 1
    assert result.forms[0].purpose_guess == "login"
    assert ss_path.exists()
