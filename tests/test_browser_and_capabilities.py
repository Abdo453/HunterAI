"""
Test Suite for Browser Abstraction, Clean Markdown Extraction, and Capability System:
- CapabilityManager & Token-based Permissions
- MarkdownExtractor (Crawl4AI style clean extraction)
- CognitiveBrowserInterface (Stagehand style observe/act/extract/api_request)
- ComputerSkill (OS & Workspace capabilities)
- ToolManifestRegistry (Dynamic Capability Discovery)
"""
from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path

import pytest

from core.browser.browser_interface import CognitiveBrowserInterface
from core.browser.markdown_extractor import MarkdownExtractor
from core.capabilities.capability_manager import Capability, CapabilityManager, CapabilityToken
from core.capabilities.computer_skill import ComputerSkill
from core.tool_manifest import ToolManifest, ToolManifestRegistry


@pytest.fixture
def temp_workspace():
    tmp = tempfile.mkdtemp()
    yield Path(tmp)
    shutil.rmtree(tmp, ignore_errors=True)


def test_capability_manager_and_tokens(temp_workspace):
    mgr = CapabilityManager(workspace_root=temp_workspace)

    # 1. Create limited token (only filesystem.read)
    token_read_only = mgr.create_skill_token("reader_skill", ["filesystem.read"])
    assert mgr.check_permission(token_read_only, Capability.FILESYSTEM_READ) is True
    assert mgr.check_permission(token_read_only, Capability.FILESYSTEM_WRITE) is False
    assert mgr.check_permission(token_read_only, Capability.PROCESS_RUN) is False

    # 2. Test sandbox enclosure
    inside_path = temp_workspace / "valid.txt"
    outside_path = Path("C:/Windows/System32/drivers/etc/hosts") if temp_workspace.drive else Path("/etc/passwd")

    assert mgr.verify_sandbox_path(inside_path, token_read_only) is True
    assert mgr.verify_sandbox_path(outside_path, token_read_only) is False


def test_markdown_extractor():
    sample_html = """
    <html>
        <head><title>Admin Control Panel</title><meta name="description" content="Management portal"></head>
        <body>
            <nav><a href="/home">Home</a></nav>
            <h1>Dashboard</h1>
            <p>Welcome to the secure administrative portal.</p>
            <form action="/admin/users" method="POST" id="user-mgmt">
                <input type="text" name="user_id" placeholder="User ID" required />
                <input type="text" name="role" value="analyst" />
                <button type="submit">Update Role</button>
            </form>
            <pre>DEBUG_TOKEN = "xyz123"</pre>
            <script>console.log("tracking");</script>
        </body>
    </html>
    """

    extracted = MarkdownExtractor.extract_from_html(sample_html, base_url="https://admin.target.com")
    assert extracted.title == "Admin Control Panel"
    assert "Dashboard" in extracted.clean_markdown
    assert "console.log" not in extracted.clean_markdown  # script removed
    assert "DEBUG_TOKEN" in extracted.code_blocks[0]
    assert "user_id" in extracted.forms_markdown
    assert "https://admin.target.com/home" in extracted.links


@pytest.mark.asyncio
async def test_cognitive_browser_interface():
    interface = CognitiveBrowserInterface(headless=True)

    # 1. Test extract method
    html = "<html><head><title>API Store</title></head><body><h1>Products</h1><p>Active items</p></body></html>"
    content = await interface.extract(html_text=html)
    assert content.title == "API Store"
    assert "Products" in content.clean_markdown

    # 2. Test act method (mock action)
    action_res = await interface.act("click", "#submit-btn", "test_val")
    assert action_res.success is True
    assert "Executed click" in action_res.result_message


@pytest.mark.asyncio
async def test_computer_skill_governance(temp_workspace):
    mgr = CapabilityManager(workspace_root=temp_workspace)
    token = mgr.create_skill_token(
        "full_worker",
        ["filesystem.read", "filesystem.write", "process.run", "network.http"]
    )
    computer = ComputerSkill(mgr, token)

    # 1. Filesystem write and read
    test_file = temp_workspace / "test.txt"
    write_ok = computer.write_file(test_file, "HunterAI Cognitive Engine")
    assert write_ok is True
    assert test_file.exists()

    content = computer.read_file(test_file)
    assert content == "HunterAI Cognitive Engine"

    # 2. Process execution (python echo)
    proc_res = await computer.run_process(["python", "-c", "print('Engine Online')"], cwd=temp_workspace)
    assert proc_res["success"] is True
    assert "Engine Online" in proc_res["stdout"]


def test_tool_manifest_discovery():
    registry = ToolManifestRegistry()

    # Discover content discovery tools
    fuzzers = registry.find_tools_by_capability("content_discovery")
    assert len(fuzzers) >= 1
    assert any(f.name == "ffuf" for f in fuzzers)

    # Discover subdomain enumeration tools
    sub_tools = registry.find_tools_by_capability("subdomain_enumeration")
    assert len(sub_tools) >= 1
    assert any(s.name == "subfinder" for s in sub_tools)

    # Discover browser tools
    browser_tools = registry.find_tools_by_capability("browser_interaction")
    assert len(browser_tools) >= 1
    assert any(b.name == "playwright_browser" for b in browser_tools)
