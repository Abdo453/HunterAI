"""Root controller: the single owner of the agent hierarchy.

Responsibilities:

* hold the tree (spawn, delegate, re-task, terminate, replace);
* hold the shared memory every agent reads and writes;
* hold the permission policy and apply it before any tool runs;
* dispatch tool calls through the repository's own tool registry, so the
  registry's schema validation, scope check, risk policy, timeout handling,
  output redaction, and audit trail all stay in force.

Nothing here executes a tool by itself.  The controller decides *whether* an
action is permitted; the registry decides *how* it runs.

Python 3.11.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.root_controller.hierarchy import (
    AgentHierarchy,
    AgentNode,
    AgentStatus,
    HierarchyError,
)
from core.root_controller.permissions import PermissionPolicy
from core.root_controller.shared_memory import Namespace, SharedMemory

__all__ = ["RootController"]


class _GrantScopeEnforcer:
    """Scope check backed by the signed grant's own matcher."""

    def __init__(self, grant: Any) -> None:
        self._scope = list(grant.scope)

    def enforce_target(self, target: str) -> tuple[bool, str]:
        for entry in self._scope:
            if entry.matches(target):
                return True, f"matched scope entry {entry.kind}:{entry.value}"
        return False, "no scope entry matches the target"


class RootController:
    """Owns the hierarchy, the shared memory, and the dispatch gate."""

    def __init__(
        self,
        *,
        hierarchy: Optional[AgentHierarchy] = None,
        memory: Optional[SharedMemory] = None,
        policy: Optional[PermissionPolicy] = None,
        registry: Optional[Any] = None,
        rules_path: Optional[str] = None,
        prompt_path: Optional[str] = None,
    ) -> None:
        self.hierarchy = hierarchy or AgentHierarchy()
        self.memory = memory or SharedMemory()
        self.policy = policy or PermissionPolicy()
        self.registry = registry
        self.rules_path = Path(rules_path) if rules_path else None
        self.prompt_path = Path(prompt_path) if prompt_path else None

    # -- tree operations ---------------------------------------------------
    def spawn(
        self,
        role: str,
        objective: str = "",
        *,
        parent_id: str = "root",
        capabilities: Optional[Iterable[str]] = None,
        tool_ids: Optional[Iterable[str]] = None,
        model: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        by: str = "root",
    ) -> AgentNode:
        """Create a child agent under ``parent_id`` (default: the root)."""
        if not self.hierarchy.may_command(by, parent_id):
            raise HierarchyError(
                f"agent '{by}' may not spawn under '{parent_id}': not an ancestor"
            )
        node = self.hierarchy.add_child(
            parent_id,
            role,
            objective,
            capabilities=capabilities,
            tool_ids=tool_ids,
            model=model,
            metadata=metadata,
        )
        self.memory.record_event(
            "agent_spawned",
            {
                "agent_id": node.agent_id,
                "role": node.role,
                "parent_id": node.parent_id,
                "depth": node.depth,
                "capabilities": node.capabilities,
                "objective": node.objective,
            },
            agent_id=by,
        )
        return node

    def delegate(
        self,
        parent_id: str,
        role: str,
        objective: str = "",
        **kwargs: Any,
    ) -> AgentNode:
        """Spawn under an arbitrary parent (a child delegating further)."""
        kwargs.setdefault("by", parent_id)
        return self.spawn(role, objective, parent_id=parent_id, **kwargs)

    def grant_capability(
        self, agent_id: str, capability: str, *, reason: str = "", by: str = "root"
    ) -> AgentNode:
        """Widen an agent's capability set.  Root-only, always audited."""
        if by != "root" and not self.hierarchy.may_command(by, agent_id):
            raise HierarchyError(
                f"agent '{by}' may not grant capabilities to '{agent_id}'"
            )
        node = self.hierarchy.grant_capability(agent_id, capability)
        self.memory.record_event(
            "capability_granted",
            {
                "agent_id": agent_id,
                "capability": capability,
                "reason": reason,
                "granted_by": by,
                "capabilities": node.capabilities,
            },
            agent_id=by,
        )
        return node

    def revoke_capability(
        self, agent_id: str, capability: str, *, reason: str = "", by: str = "root"
    ) -> AgentNode:
        if by != "root" and not self.hierarchy.may_command(by, agent_id):
            raise HierarchyError(
                f"agent '{by}' may not revoke capabilities from '{agent_id}'"
            )
        node = self.hierarchy.revoke_capability(agent_id, capability)
        self.memory.record_event(
            "capability_revoked",
            {
                "agent_id": agent_id,
                "capability": capability,
                "reason": reason,
                "granted_by": by,
            },
            agent_id=by,
        )
        return node

    def retask(
        self, agent_id: str, objective: str, *, by: str = "root"
    ) -> AgentNode:
        if not self.hierarchy.may_command(by, agent_id):
            raise HierarchyError(f"agent '{by}' may not re-task '{agent_id}'")
        node = self.hierarchy.retask(agent_id, objective)
        self.memory.record_event(
            "agent_retasked",
            {"agent_id": agent_id, "objective": objective, "by": by},
            agent_id=by,
        )
        return node

    def terminate(
        self, agent_id: str, reason: str = "", *, by: str = "root"
    ) -> List[str]:
        """Kill an agent and its subtree."""
        if not self.hierarchy.may_command(by, agent_id):
            raise HierarchyError(f"agent '{by}' may not terminate '{agent_id}'")
        killed = self.hierarchy.kill(agent_id, reason)
        self.memory.record_event(
            "agent_terminated",
            {"agent_id": agent_id, "reason": reason, "killed": killed, "by": by},
            agent_id=by,
        )
        return killed

    def replace(self, agent_id: str, role: str, *, by: str = "root") -> AgentNode:
        """Replace an agent with a fresh node that inherits its remit."""
        if not self.hierarchy.may_command(by, agent_id):
            raise HierarchyError(f"agent '{by}' may not replace '{agent_id}'")
        node = self.hierarchy.replace(agent_id, role)
        self.memory.record_event(
            "agent_replaced",
            {"old_agent_id": agent_id, "agent_id": node.agent_id, "role": role, "by": by},
            agent_id=by,
        )
        return node

    def complete(self, agent_id: str, *, by: str = "root") -> AgentNode:
        if not self.hierarchy.may_command(by, agent_id):
            raise HierarchyError(f"agent '{by}' may not close '{agent_id}'")
        node = self.hierarchy.set_status(agent_id, AgentStatus.COMPLETED)
        self.memory.record_event(
            "agent_completed", {"agent_id": agent_id, "by": by}, agent_id=by
        )
        return node

    # -- dispatch ----------------------------------------------------------
    def auth_context(self, agent: AgentNode) -> Any:
        """Build the tool-registry auth context for one agent."""
        from core.tool_registry import AuthContext  # local import: heavy module

        return AuthContext(
            worker_id=agent.agent_id,
            worker_role=agent.role,
            granted_permissions=list(agent.capabilities),
            in_scope_targets=self.policy.scope_targets(),
            out_of_scope_targets=(),
            approve_high_risk=self.policy.profile.value == "red_team",
            scope_enforcer=self.scope_enforcer(),
        )

    def scope_enforcer(self) -> Optional[Any]:
        """Adapter that lets the registry use the grant's own scope matcher.

        The registry's built-in check only understands host suffixes; the
        grant understands domains, hosts, CIDRs, and URL prefixes.  Binding
        the grant matcher here keeps the two layers from disagreeing.
        """
        if self.policy.engine is None:
            return None
        return _GrantScopeEnforcer(self.policy.engine.grant)

    async def run_tool(
        self,
        agent_id: str,
        tool_id: str,
        arguments: Dict[str, Any],
        *,
        target: str,
        action_class: str = "read_only",
        risk_level: str = "low",
        operation: str = "",
    ) -> Any:
        """Permission-check, then dispatch one tool call for one agent."""
        from core.tool_registry import ToolError, ToolResult  # local import

        agent = self.hierarchy.get(agent_id)
        decision = self.policy.check(
            agent,
            target,
            action_class,
            tool_id=tool_id,
            risk_level=risk_level,
            operation=operation,
            mutates_state=action_class in ("proof_write", "exploit_proof"),
        )
        if not decision.allowed:
            self.memory.record_event(
                "tool_denied",
                {
                    "agent_id": agent_id,
                    "tool_id": tool_id,
                    "target": target,
                    "action_class": action_class,
                    "reason": decision.reason,
                    "audit_id": decision.audit_id,
                },
                agent_id=agent_id,
            )
            return ToolResult(
                ok=False,
                tool_id=tool_id,
                error=decision.reason,
                error_category="POLICY_DENIED",
                metadata={"decision": decision.to_dict()},
            )

        if self.registry is None:
            return ToolResult(
                ok=False,
                tool_id=tool_id,
                error="no tool registry is bound to this controller",
                error_category="CONFIGURATION",
            )

        try:
            result = await self.registry.call_tool(
                tool_id, arguments, self.auth_context(agent)
            )
        except ToolError as exc:
            return ToolResult(
                ok=False,
                tool_id=tool_id,
                error=str(exc),
                error_category=getattr(exc, "category", "TOOL_ERROR"),
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed result
            return ToolResult(
                ok=False,
                tool_id=tool_id,
                error=str(exc),
                error_category="EXECUTION_ERROR",
            )

        self.memory.record_event(
            "tool_executed",
            {
                "agent_id": agent_id,
                "tool_id": tool_id,
                "target": target,
                "action_class": action_class,
                "ok": bool(getattr(result, "ok", False)),
                "audit_id": getattr(result, "audit_event_id", None),
            },
            agent_id=agent_id,
        )
        return result

    def run_tool_sync(self, agent_id: str, tool_id: str, arguments: Dict[str, Any], **kwargs: Any) -> Any:
        """Blocking wrapper around :meth:`run_tool`."""
        return asyncio.run(self.run_tool(agent_id, tool_id, arguments, **kwargs))

    # -- memory helpers ----------------------------------------------------
    def record_lead(
        self,
        agent_id: str,
        title: str,
        detail: Any = "",
        *,
        tags: Iterable[str] = (),
        target: str = "",
    ) -> Dict[str, Any]:
        """Log a lead on the shared board."""
        payload = {"title": title, "detail": detail, "target": target, "at": time.time()}
        return self.memory.write(
            Namespace.LEAD, title, payload, agent_id=agent_id, tags=tags
        )

    def record_evidence(
        self, agent_id: str, key: str, evidence: Any, *, tags: Iterable[str] = ()
    ) -> Dict[str, Any]:
        return self.memory.write(
            Namespace.EVIDENCE, key, evidence, agent_id=agent_id, tags=tags
        )

    def record_attack_path(
        self, agent_id: str, key: str, path: Any, *, tags: Iterable[str] = ()
    ) -> Dict[str, Any]:
        return self.memory.write(
            Namespace.ATTACK_PATH, key, path, agent_id=agent_id, tags=tags
        )

    def record_access_path(
        self, agent_id: str, key: str, path: Any, *, tags: Iterable[str] = ()
    ) -> Dict[str, Any]:
        """Record an operator-provided access path (test account, provided key)."""
        return self.memory.write(
            Namespace.ACCESS_PATH, key, path, agent_id=agent_id, tags=tags
        )

    # -- context assembly --------------------------------------------------
    def context_for(self, agent_id: str, *, limit: int = 40) -> Dict[str, Any]:
        """Everything one agent needs to continue its work."""
        agent = self.hierarchy.get(agent_id)
        recent = self.memory.history()[-limit:]
        return {
            "agent": agent.to_dict(),
            "scope": self.policy.scope_targets(),
            "policy": self.policy.describe(),
            "leads": self.memory.latest(Namespace.LEAD),
            "evidence": self.memory.latest(Namespace.EVIDENCE),
            "attack_paths": self.memory.latest(Namespace.ATTACK_PATH),
            "access_paths": self.memory.latest(Namespace.ACCESS_PATH),
            "recent_events": [
                {
                    "ts": r.get("ts"),
                    "namespace": r.get("namespace"),
                    "key": r.get("key"),
                    "agent_id": r.get("agent_id"),
                }
                for r in recent
            ],
            "rules": self.rules(),
        }

    def rules(self) -> List[str]:
        if not self.rules_path or not self.rules_path.exists():
            return []
        return [
            line.strip()
            for line in self.rules_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def system_prompt(self) -> str:
        if not self.prompt_path or not self.prompt_path.exists():
            return ""
        return self.prompt_path.read_text(encoding="utf-8")

    # -- reporting ---------------------------------------------------------
    def tree(self) -> Dict[str, Any]:
        return self.hierarchy.to_dict()

    def render_tree(self) -> str:
        return self.hierarchy.render()

    def stats(self) -> Dict[str, Any]:
        return {
            "agents": len(self.hierarchy.nodes()),
            "active_agents": len(self.hierarchy.active_nodes()),
            "memory": self.memory.stats(),
            "policy": self.policy.describe(),
        }

    def export_state(self, path: str) -> str:
        """Write hierarchy + memory snapshot to disk."""
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "exported_at": time.time(),
            "hierarchy": self.hierarchy.to_dict(),
            "memory": self.memory.snapshot(),
        }
        target.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return str(target.resolve())
