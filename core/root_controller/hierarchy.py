"""Hierarchical agent tree for the HunterAI root controller.

Structure rules enforced here:

* every node except the root has exactly one parent;
* a node may spawn at most ``max_children`` children;
* tree depth is bounded by ``max_depth``;
* capabilities flow downward only -- a child can never hold a capability its
  parent does not hold, and widening a capability set is an explicit root
  operation so every escalation is visible in the audit trail;
* the parent may re-task, suspend, kill, or replace any descendant.

Python 3.11, standard library only.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

__all__ = [
    "AgentHierarchy",
    "AgentNode",
    "AgentStatus",
    "HierarchyError",
]


class HierarchyError(RuntimeError):
    """Raised when a hierarchy operation is not permitted."""


class AgentStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    SUSPENDED = "suspended"
    KILLED = "killed"
    REPLACED = "replaced"

    @classmethod
    def coerce(cls, value: Any) -> "AgentStatus":
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).lower())
        except ValueError as exc:
            raise HierarchyError(f"unknown agent status: {value!r}") from exc


@dataclass
class AgentNode:
    """One agent in the tree."""

    agent_id: str
    role: str
    objective: str = ""
    parent_id: Optional[str] = None
    depth: int = 0
    status: AgentStatus = AgentStatus.ACTIVE
    capabilities: List[str] = field(default_factory=list)
    tool_ids: List[str] = field(default_factory=list)
    model: str = ""
    children: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "objective": self.objective,
            "parent_id": self.parent_id,
            "depth": self.depth,
            "status": self.status.value,
            "capabilities": list(self.capabilities),
            "tool_ids": list(self.tool_ids),
            "model": self.model,
            "children": list(self.children),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentNode":
        return cls(
            agent_id=str(data["agent_id"]),
            role=str(data.get("role", "unknown")),
            objective=str(data.get("objective", "")),
            parent_id=data.get("parent_id"),
            depth=int(data.get("depth", 0)),
            status=AgentStatus.coerce(data.get("status", "active")),
            capabilities=list(data.get("capabilities") or []),
            tool_ids=list(data.get("tool_ids") or []),
            model=str(data.get("model", "")),
            children=list(data.get("children") or []),
            created_at=float(data.get("created_at", time.time())),
            updated_at=float(data.get("updated_at", time.time())),
            metadata=dict(data.get("metadata") or {}),
        )


class AgentHierarchy:
    """The agent tree itself: create, delegate, re-task, kill, replace."""

    def __init__(
        self,
        *,
        root_role: str = "root_controller",
        root_objective: str = (
            "Own the engagement: hold scope, plan the hunt, delegate, verify, report."
        ),
        root_capabilities: Optional[Iterable[str]] = None,
        max_depth: int = 4,
        max_children: int = 6,
    ) -> None:
        if max_depth < 1:
            raise HierarchyError("max_depth must be >= 1")
        if max_children < 1:
            raise HierarchyError("max_children must be >= 1")
        self.max_depth = int(max_depth)
        self.max_children = int(max_children)
        self._nodes: Dict[str, AgentNode] = {}
        root = AgentNode(
            agent_id="root",
            role=root_role,
            objective=root_objective,
            parent_id=None,
            depth=0,
            capabilities=sorted(set(root_capabilities or [])),
        )
        self._nodes[root.agent_id] = root

    # -- accessors ---------------------------------------------------------
    @property
    def root(self) -> AgentNode:
        return self._nodes["root"]

    def get(self, agent_id: str) -> AgentNode:
        try:
            return self._nodes[agent_id]
        except KeyError as exc:
            raise HierarchyError(f"unknown agent: {agent_id}") from exc

    def nodes(self) -> List[AgentNode]:
        return list(self._nodes.values())

    def active_nodes(self) -> List[AgentNode]:
        return [n for n in self._nodes.values() if n.status is AgentStatus.ACTIVE]

    def children_of(self, agent_id: str) -> List[AgentNode]:
        return [self._nodes[cid] for cid in self.get(agent_id).children]

    # -- mutation ----------------------------------------------------------
    def add_child(
        self,
        parent_id: str,
        role: str,
        objective: str = "",
        *,
        capabilities: Optional[Iterable[str]] = None,
        tool_ids: Optional[Iterable[str]] = None,
        model: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentNode:
        """Create a child agent under ``parent_id``.

        Capabilities default to the parent's set.  Requesting a capability the
        parent does not hold is rejected -- widening happens through
        :meth:`grant_capability`, which the root controller only performs on an
        explicit operator instruction.
        """
        parent = self.get(parent_id)
        if parent.status is not AgentStatus.ACTIVE:
            raise HierarchyError(
                f"parent '{parent_id}' is {parent.status.value}; only active agents may spawn"
            )
        if parent.depth + 1 > self.max_depth:
            raise HierarchyError(
                f"depth limit reached: parent depth {parent.depth}, max_depth {self.max_depth}"
            )
        if len(parent.children) >= self.max_children:
            raise HierarchyError(
                f"child limit reached for '{parent_id}': max_children {self.max_children}"
            )

        requested = sorted(
            set(capabilities) if capabilities is not None else set(parent.capabilities)
        )
        extra = [c for c in requested if c not in parent.capabilities]
        if extra:
            raise HierarchyError(
                "capability escalation requires an explicit root grant: " + ", ".join(extra)
            )

        agent_id = f"{role}-{uuid.uuid4().hex[:8]}"
        node = AgentNode(
            agent_id=agent_id,
            role=role,
            objective=objective,
            parent_id=parent_id,
            depth=parent.depth + 1,
            capabilities=requested,
            tool_ids=sorted(set(tool_ids or [])),
            model=model,
            metadata=dict(metadata or {}),
        )
        self._nodes[agent_id] = node
        parent.children.append(agent_id)
        parent.updated_at = time.time()
        return node

    def grant_capability(self, agent_id: str, capability: str) -> AgentNode:
        """Widen one agent's capability set (root-only operation)."""
        node = self.get(agent_id)
        if capability not in node.capabilities:
            node.capabilities = sorted(set(node.capabilities) | {capability})
            node.updated_at = time.time()
        granted = node.metadata.setdefault("granted_capabilities", [])
        if capability not in granted:
            granted.append(capability)
        return node

    def revoke_capability(self, agent_id: str, capability: str) -> AgentNode:
        node = self.get(agent_id)
        node.capabilities = [c for c in node.capabilities if c != capability]
        node.updated_at = time.time()
        return node

    def retask(self, agent_id: str, objective: str) -> AgentNode:
        node = self.get(agent_id)
        node.objective = objective
        node.updated_at = time.time()
        node.metadata.setdefault("retasks", []).append(
            {"objective": objective, "at": time.time()}
        )
        return node

    def set_status(self, agent_id: str, status: AgentStatus) -> AgentNode:
        node = self.get(agent_id)
        node.status = AgentStatus.coerce(status)
        node.updated_at = time.time()
        return node

    def kill(self, agent_id: str, reason: str = "") -> List[str]:
        """Kill an agent and its whole subtree; returns the ids terminated."""
        node = self.get(agent_id)
        killed: List[str] = []
        for target_id in self.descendants(agent_id) + [agent_id]:
            target = self._nodes[target_id]
            if target.status is not AgentStatus.KILLED:
                target.status = AgentStatus.KILLED
                target.updated_at = time.time()
                target.metadata["kill_reason"] = reason
                killed.append(target_id)
        return killed

    def replace(self, agent_id: str, role: str) -> AgentNode:
        """Replace an agent with a fresh node that inherits its remit."""
        old = self.get(agent_id)
        if old.status in (AgentStatus.KILLED, AgentStatus.REPLACED):
            raise HierarchyError(
                f"agent '{agent_id}' is {old.status.value} and cannot be replaced"
            )
        parent = self.get(old.parent_id) if old.parent_id else None
        if parent is not None and len(parent.children) >= self.max_children:
            raise HierarchyError(
                f"child limit reached for '{parent.agent_id}': max_children {self.max_children}"
            )

        new_id = f"{role}-{uuid.uuid4().hex[:8]}"
        replacement = AgentNode(
            agent_id=new_id,
            role=role,
            objective=old.objective,
            parent_id=old.parent_id,
            depth=old.depth,
            capabilities=list(old.capabilities),
            tool_ids=list(old.tool_ids),
            model=old.model,
            metadata={**old.metadata, "replaces": old.agent_id},
        )
        self._nodes[new_id] = replacement

        for child_id in list(old.children):
            child = self._nodes[child_id]
            child.parent_id = new_id
            child.depth = old.depth + 1
            replacement.children.append(child_id)
        old.children = []
        old.status = AgentStatus.REPLACED
        old.updated_at = time.time()

        if parent is not None:
            parent.children = [
                new_id if cid == old.agent_id else cid for cid in parent.children
            ]
        return replacement

    # -- queries -----------------------------------------------------------
    def descendants(self, agent_id: str) -> List[str]:
        """Depth-first list of every descendant id (excluding ``agent_id``)."""
        found: List[str] = []
        stack = list(self.get(agent_id).children)
        while stack:
            current = stack.pop(0)
            if current in found:
                continue
            found.append(current)
            stack.extend(self._nodes[current].children)
        return found

    def path_to_root(self, agent_id: str) -> List[str]:
        path: List[str] = []
        current: Optional[str] = agent_id
        while current:
            path.append(current)
            node = self._nodes.get(current)
            if node is None:
                break
            current = node.parent_id
        return list(reversed(path))

    def is_ancestor(self, ancestor_id: str, descendant_id: str) -> bool:
        if ancestor_id == descendant_id:
            return False
        return ancestor_id in self.path_to_root(descendant_id)

    def may_command(self, commander_id: str, target_id: str) -> bool:
        """True when ``commander_id`` may re-task/kill/replace ``target_id``."""
        if commander_id == target_id:
            return True
        return self.is_ancestor(commander_id, target_id)

    # -- persistence -------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root.agent_id,
            "max_depth": self.max_depth,
            "max_children": self.max_children,
            "nodes": {aid: node.to_dict() for aid, node in self._nodes.items()},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentHierarchy":
        hierarchy = cls(
            root_role="root_controller",
            max_depth=int(data.get("max_depth", 4)),
            max_children=int(data.get("max_children", 6)),
        )
        nodes: Dict[str, AgentNode] = {}
        for agent_id, raw in (data.get("nodes") or {}).items():
            node = AgentNode.from_dict(raw)
            node.agent_id = agent_id
            nodes[agent_id] = node
        if "root" in nodes:
            hierarchy._nodes = nodes
        return hierarchy

    def save(self, path: str) -> str:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return str(target.resolve())

    @classmethod
    def load(cls, path: str) -> "AgentHierarchy":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    # -- rendering ---------------------------------------------------------
    def render(self) -> str:
        """ASCII tree for the CLI."""
        lines: List[str] = []

        def walk(node: AgentNode, prefix: str, is_last: bool, is_root: bool) -> None:
            if is_root:
                lines.append(f"{node.role} [{node.status.value}] {node.agent_id}")
            else:
                connector = "`-- " if is_last else "|-- "
                lines.append(f"{prefix}{connector}{node.role} [{node.status.value}] {node.agent_id}")
            child_prefix = prefix if is_root else prefix + ("    " if is_last else "|   ")
            for index, child_id in enumerate(node.children):
                child = self._nodes.get(child_id)
                if child is None:
                    continue
                walk(child, child_prefix, index == len(node.children) - 1, False)

        walk(self.root, "", True, True)
        return "\n".join(lines)
