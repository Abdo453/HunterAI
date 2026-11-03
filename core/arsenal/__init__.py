"""
HunterAI Universal Arsenal & MCP Framework
==========================================
Exports the Kali Linux Tool Catalog, Dynamic Tool Agents, and Universal MCP Bridge.
"""
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

__all__ = [
    "KALI_TOOL_CATALOG",
    "ToolCategory",
    "ToolDefinition",
    "get_tool_definition",
    "get_tools_by_category",
    "search_tools_for_objective",
    "DynamicToolAgent",
    "ToolAgentFactory",
    "ToolSkillDescriptor",
    "UniversalMCPBridge",
    "MCPServerRunner",
]
