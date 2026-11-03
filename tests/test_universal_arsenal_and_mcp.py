"""
Tests for Universal Kali Arsenal, Dynamic Tool Agents, and Universal MCP Bridge.
Ensures hermetic execution, 14-category coverage, MCP specification compliance, and persona integrity.
"""
import json
import pytest

from core.arsenal.kali_catalog import (
    KALI_TOOL_CATALOG,
    ToolCategory,
    ToolDefinition,
    get_tool_definition,
    get_tools_by_category,
    search_tools_for_objective,
)
from core.arsenal.tool_agent_factory import (
    DynamicToolAgent,
    ToolAgentFactory,
    ToolSkillDescriptor,
)
from core.arsenal.universal_mcp_bridge import (
    MCPServerRunner,
    UniversalMCPBridge,
)
from core.engine.real_tool_adapter import RealToolAdapter


# ── 1. Catalog Tests ─────────────────────────────────────────────────────────

def test_kali_catalog_coverage():
    """Verify that catalog contains tools across all 14 core categories."""
    assert len(KALI_TOOL_CATALOG) >= 50, f"Expected 50+ tools, got {len(KALI_TOOL_CATALOG)}"

    categories_present = {tool.category for tool in KALI_TOOL_CATALOG.values()}
    # Verify major categories are represented
    for expected_cat in [
        ToolCategory.RECON,
        ToolCategory.PORT_SCAN,
        ToolCategory.WEB_CRAWL,
        ToolCategory.FUZZING,
        ToolCategory.PARAMETERS,
        ToolCategory.VULN_SCAN,
        ToolCategory.EXPLOITATION,
        ToolCategory.AUTH_TESTING,
        ToolCategory.SECRETS,
        ToolCategory.SSL_TLS,
        ToolCategory.CLOUD,
        ToolCategory.WAF_BYPASS,
        ToolCategory.REVERSE_ENG,
    ]:
        assert expected_cat in categories_present, f"Missing category: {expected_cat}"


def test_tool_definition_lookup_and_search():
    """Verify lookup and search functions in the catalog."""
    sub = get_tool_definition("subfinder")
    assert sub is not None
    assert sub.binary_name == "subfinder"
    assert sub.category == ToolCategory.RECON

    sqlmap = get_tool_definition("sqlmap")
    assert sqlmap is not None
    assert sqlmap.risk_level == "critical"

    # Search by tag or keyword
    cloud_tools = search_tools_for_objective("cloud")
    assert len(cloud_tools) >= 2

    recon_tools = get_tools_by_category(ToolCategory.RECON)
    assert len(recon_tools) >= 5


# ── 2. Tool Agent Factory & Dynamic Agent Tests ──────────────────────────────

def test_dynamic_tool_agent_generation():
    """Verify ToolAgentFactory produces structured personas, prompts, and skills."""
    adapter = RealToolAdapter(force_fallback=True)
    factory = ToolAgentFactory(adapter=adapter)

    agent = factory.get_agent("nmap")
    assert agent is not None
    assert "nmap" in agent.name
    assert "Port_Scan" in agent.role or "Port Scan" in agent.role or "port_scan" in agent.role.lower()

    # System prompt check
    assert "OPERATIONAL INVARIANTS" in agent.system_prompt
    assert "Zero Unauthorized Drift" in agent.system_prompt
    assert "Evidence First" in agent.system_prompt

    # Skill descriptor check
    assert agent.skill.skill_id == "kali_nmap"
    assert agent.skill.category == "port_scan"
    assert "target" in agent.skill.input_schema["properties"]


def test_dynamic_tool_agent_execution_fallback():
    """Verify safe hermetic fallback execution across tool categories."""
    adapter = RealToolAdapter(force_fallback=True)
    factory = ToolAgentFactory(adapter=adapter)

    # 1. Recon tool fallback
    subfinder_agent = factory.get_agent("subfinder")
    res_recon = subfinder_agent.execute(target="example.com")
    assert res_recon.success
    assert res_recon.used_fallback
    assert "subdomains" in res_recon.structured_data
    assert len(res_recon.structured_data["subdomains"]) > 0

    # 2. Port scan tool fallback
    nmap_agent = factory.get_agent("nmap")
    res_port = nmap_agent.execute(target="example.com")
    assert res_port.success
    assert res_port.used_fallback
    assert "open_ports" in res_port.structured_data

    # 3. Web crawl fallback
    crawl_agent = factory.get_agent("katana")
    res_crawl = crawl_agent.execute(target="example.com")
    assert res_crawl.success
    assert "crawled_urls" in res_crawl.structured_data

    # 4. Fuzzing fallback
    fuzz_agent = factory.get_agent("ffuf")
    res_fuzz = fuzz_agent.execute(target="example.com")
    assert res_fuzz.success
    assert "endpoints" in res_fuzz.structured_data


def test_factory_list_arsenal_status():
    """Verify listing arsenal status."""
    factory = ToolAgentFactory()
    status = factory.list_arsenal_status()
    assert len(status) == len(KALI_TOOL_CATALOG)
    first = status[0]
    assert "name" in first
    assert "installed" in first
    assert "package" in first


# ── 3. Universal MCP Bridge & Server Runner Tests ────────────────────────────

def test_mcp_bridge_tool_definitions():
    """Verify MCP bridge exposes dispatcher and individual tools."""
    adapter = RealToolAdapter(force_fallback=True)
    factory = ToolAgentFactory(adapter=adapter)
    bridge = UniversalMCPBridge(factory=factory)

    defs = bridge.get_tool_definitions()
    tool_names = [d["name"] for d in defs]

    assert "kali_dispatch_tool" in tool_names
    assert "kali_subfinder" in tool_names
    assert "kali_nmap" in tool_names
    assert "kali_sqlmap" in tool_names
    assert "kali_nuclei" in tool_names

    # Schema validation
    for d in defs:
        assert "name" in d
        assert "description" in d
        assert "inputSchema" in d
        assert d["inputSchema"]["type"] == "object"


def test_mcp_bridge_tool_call_execution():
    """Verify handling of direct tool calls and dispatch tool calls."""
    adapter = RealToolAdapter(force_fallback=True)
    factory = ToolAgentFactory(adapter=adapter)
    bridge = UniversalMCPBridge(factory=factory)

    # 1. Direct tool call with kali_ prefix
    res1 = bridge.handle_tool_call("kali_subfinder", {"target": "test.target.com"})
    assert res1["success"]
    assert res1["tool"] == "subfinder"
    assert res1["used_fallback"]

    # 2. Universal dispatcher tool call
    res2 = bridge.handle_tool_call(
        "kali_dispatch_tool",
        {"tool_name": "nmap", "target": "192.168.1.1"}
    )
    assert res2["success"]
    assert res2["tool"] == "nmap"
    assert res2["category"] == "port_scan"

    # 3. Invalid tool call error handling
    res3 = bridge.handle_tool_call("kali_nonexistent_tool_xyz", {"target": "test.com"})
    assert "error" in res3


def test_mcp_server_json_rpc_runner():
    """Verify standard MCP JSON-RPC 2.0 lifecycle."""
    adapter = RealToolAdapter(force_fallback=True)
    factory = ToolAgentFactory(adapter=adapter)
    bridge = UniversalMCPBridge(factory=factory)
    runner = MCPServerRunner(bridge=bridge)

    # 1. Ping
    ping_resp = runner.process_rpc_request(json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "ping"
    }))
    p_data = json.loads(ping_resp)
    assert p_data["id"] == 1
    assert "result" in p_data

    # 2. Initialize
    init_resp = runner.process_rpc_request(json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}
    }))
    i_data = json.loads(init_resp)
    assert i_data["result"]["serverInfo"]["name"] == "hunter-ai-kali-arsenal-mcp"

    # 3. Tools List
    list_resp = runner.process_rpc_request(json.dumps({
        "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}
    }))
    l_data = json.loads(list_resp)
    assert len(l_data["result"]["tools"]) >= 50

    # 4. Tool Call
    call_resp = runner.process_rpc_request(json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "kali_nuclei",
            "arguments": {"target": "http://test.local"}
        }
    }))
    c_data = json.loads(call_resp)
    assert c_data["id"] == 4
    assert not c_data["result"].get("isError", True)
    content_text = c_data["result"]["content"][0]["text"]
    assert "nuclei" in content_text
