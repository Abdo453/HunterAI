# MCP (Model Context Protocol) Client Setup — Phase E

## Overview

HunterAI implements a native MCP client using only the Python standard library (zero external dependencies), communicating over **stdio** transport (a local subprocess over stdin/stdout) using **JSON-RPC 2.0**.

The client integrates with the unified tool registry (`core/tool_registry.py`) and coordinator (`core/coordinator.py`), exposing MCP server tools as governed executable tools subject to permission and scope checks.

## Files

| File | Role |
|---|---|
| `core/mcp_config.py` | MCP server configuration schema (Pydantic) |
| `core/mcp_client.py` | MCP client (stdio, `initialize`, `tools/list`, `tools/call`, cancellation, reconnection) |
| `core/mcp_manager.py` (inside `mcp_client`) | `MCPClientManager` for managing multiple namespaced servers |
| `config/mcp.example.json` | Example configuration (no real secrets) |
| `tests/test_mcp_client.py` | Unit tests (mocked, no external systems) |

## Architecture

```
MCP Server Config  →  MCPClientManager  →  MCPClient (per server)
                                                    ↓
                                          tools/list  (tool discovery)
                                                    ↓
                                          tools/call  (tool execution with scope + approval)
                                                    ↓
                                          Audit Log + ToolRegistry
```

## Setup (Local)

1. Install the desired MCP server, for example the local filesystem server:
   ```bash
   npm install -g @modelcontextprotocol/server-filesystem
   ```
2. Edit `config/mcp.example.json` and configure `command` and `args` for the server.
3. For authentication, store the token in an environment variable and reference it via `auth_token_env` (never write raw tokens into config files):
   ```json
   { "auth_token_env": "GITHUB_PERSONAL_ACCESS_TOKEN" }
   ```
   Then:
   ```bash
   export GITHUB_PERSONAL_ACCESS_TOKEN=ghp_...
   ```
4. Load the configuration in your application:
   ```python
   from core.mcp_config import load_mcp_config_from_file
   from core.mcp_client import MCPClientManager

   config = load_mcp_config_from_file("config/mcp.example.json")
   manager = MCPClientManager(config.servers)
   await manager.connect_all()
   ```

## Security

- Outputs from MCP servers are treated as untrusted data and never evaluated as code.
- High-risk tools (`risk_level: high/critical`) require human approval via `ToolRegistry.approval_handler`.
- Network-backed servers are validated against scope policy (`ScopeEnforcer`) before any invocation.
- No raw secrets are stored in configuration files or logs.

## Limitations

- Network transport (HTTP/SSE) is documented in the configuration schema, while production implementation is deferred until the official `mcp` SDK is adopted.
- Unit tests use mocks; test against a live server in an isolated environment.
