# Coding Agent Adapters Setup — Phase E

## Overview

HunterAI provides a generic CLI interface for coding agents (Codex CLI / Claude Code / Cursor Agent / OpenCode / ...) integrated with the coordinator and tool registry. Each agent operates strictly within an authorized workspace, and high-impact edits require diff review and human approval.

## Files

| File | Role |
|---|---|
| `core/coding_agent_adapter.py` | Abstract `CodingAgentAdapter` interface + `CLICodingAgentAdapter` implementation + `CodingAgentRegistry` |
| `tests/test_coding_agent_adapter.py` | Unit tests (mocked subprocess, no external systems) |
| `docs/mcp-setup.md` | MCP client setup (related) |

## Capabilities Matrix

| Agent | Executable | Read Files | Search | Inspect Dependencies | Propose Diff | Apply Diff | Run Tests | Cancel |
|---|---|---|---|---|---|---|---|---|
| Claude Code | `claude` | ✅ | ✅ | – | ✅ | ✅ | ✅ | ✅ |
| Codex CLI | `codex` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OpenCode | `opencode` | ✅ | ✅ | – | ✅ | – | – | ✅ |

> Capabilities are reported dynamically by each agent; unsupported capabilities are never assumed.

## Usage

Default agents are registered automatically when importing `core/coding_agent_adapter`:

```python
from core.coding_agent_adapter import GLOBAL_CODING_AGENT_REGISTRY

agents = GLOBAL_CODING_AGENT_REGISTRY.list_agents()
for a in agents:
    print(a.agent_id, a.display_name, a.executable)
```

To register a custom agent:

```python
from core.coding_agent_adapter import (
    CLICodingAgentAdapter, CodingAgentCapabilities, AgentCapability,
    GLOBAL_CODING_AGENT_REGISTRY,
)

agent = CLICodingAgentAdapter(
    agent_id="my-agent",
    executable="my-cli",
    args_template=["run", "{prompt}"],
    capabilities=CodingAgentCapabilities(
        agent_id="my-agent", display_name="My Agent",
        executable="my-cli",
        supports_file_read=True,
        supports_patch_suggestion=True,
        supports_cancellation=True,
    ),
    auth_check_cmd=["my-cli", "--version"],
)
GLOBAL_CODING_AGENT_REGISTRY.register(agent)
```

## Security

- **Authorized workspace only**: Every request runs within the specified `workspace`; access outside it is blocked (no path traversal).
- **No secrets exposed**: API keys, SSH keys, and tokens are never passed to the agent.
- **Diff review**: Edits that produce a diff are flagged with `needs_human_review = True` and require human approval via `ToolRegistry.approval_handler` before applying.
- **Cancellation**: Supported wherever the underlying agent supports it; timeouts are enforced.

## Coordinator Integration

The coding agent registry is injected into `core/coordinator.py` as a task `executor`, allowing the planner to assign coding tasks to specific agents with status and event tracking.

## External Requirements

- Agent executables (`claude` / `codex` / `opencode`) must be installed in `PATH` or configured with an explicit path.
- Authentication for each agent is managed independently (sign in through the agent's own CLI).
