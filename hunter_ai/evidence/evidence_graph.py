"""
Evidence Graph — Full causal chain for security findings.

Chain: Host -> Endpoint -> Parameter -> Request -> Response
       -> Observation -> Hypothesis -> Experiment -> Evidence -> Verdict

Every finding in HunterAI MUST have a complete causal chain.
No LLM opinion = finding. Evidence comes from execution, not inference.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class EvidenceType(str, Enum):
    HOST        = "HOST"
    ENDPOINT    = "ENDPOINT"
    PARAMETER   = "PARAMETER"
    REQUEST     = "REQUEST"
    RESPONSE    = "RESPONSE"
    OBSERVATION = "OBSERVATION"
    HYPOTHESIS  = "HYPOTHESIS"
    EXPERIMENT  = "EXPERIMENT"
    EVIDENCE    = "EVIDENCE"
    VERDICT     = "VERDICT"


@dataclass
class EvidenceNode:
    node_id: str = field(default_factory=lambda: f"E-{uuid.uuid4().hex[:6].upper()}")
    node_type: EvidenceType = EvidenceType.OBSERVATION
    content: Dict[str, Any] = field(default_factory=dict)
    parent_id: Optional[str] = None   # links to prior node in causal chain
    timestamp: float = field(default_factory=time.time)
    agent: str = ""                    # which agent created this node
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id":   self.node_id,
            "node_type": self.node_type.value,
            "content":   self.content,
            "parent_id": self.parent_id,
            "timestamp": self.timestamp,
            "agent":     self.agent,
        }


class EvidenceGraph:
    """
    Directed acyclic graph where each node points to its parent.
    Traversing from VERDICT → back reconstructs the full causal chain.

    Usage:
        graph = EvidenceGraph()
        resp_id = graph.build_from_request_response(...)
        obs_id  = graph.add_observation(resp_id, "id param controls object", agent="WebAgent")
        chain   = graph.get_chain(obs_id)   # [HOST, ENDPOINT, REQUEST, RESPONSE, OBSERVATION]
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, EvidenceNode] = {}

    # ── Core operations ───────────────────────────────────────────────────────

    def add_node(self, node: EvidenceNode) -> str:
        self._nodes[node.node_id] = node
        return node.node_id

    def get_node(self, node_id: str) -> Optional[EvidenceNode]:
        return self._nodes.get(node_id)

    def get_chain(self, node_id: str) -> List[EvidenceNode]:
        """Walk up the parent chain from node_id to root (inclusive). Returns root-first."""
        chain: List[EvidenceNode] = []
        current_id: Optional[str] = node_id
        visited: set = set()
        while current_id and current_id not in visited:
            visited.add(current_id)
            node = self._nodes.get(current_id)
            if not node:
                break
            chain.append(node)
            current_id = node.parent_id
        return list(reversed(chain))

    def get_by_type(self, node_type: EvidenceType) -> List[EvidenceNode]:
        return [n for n in self._nodes.values() if n.node_type == node_type]

    # ── Convenience builders ──────────────────────────────────────────────────

    def build_from_request_response(
        self,
        host: str,
        endpoint: str,
        method: str,
        request_body: str,
        response_status: int,
        response_body: str,
        agent: str = "",
    ) -> str:
        """
        Creates HOST -> ENDPOINT -> REQUEST -> RESPONSE chain.
        Returns the RESPONSE node_id (leaf of the chain).
        """
        host_node = EvidenceNode(
            node_type=EvidenceType.HOST,
            content={"host": host},
            agent=agent,
        )
        h_id = self.add_node(host_node)

        ep_node = EvidenceNode(
            node_type=EvidenceType.ENDPOINT,
            content={"endpoint": endpoint, "method": method},
            parent_id=h_id,
            agent=agent,
        )
        ep_id = self.add_node(ep_node)

        req_node = EvidenceNode(
            node_type=EvidenceType.REQUEST,
            content={"method": method, "endpoint": endpoint, "body": request_body[:500]},
            parent_id=ep_id,
            agent=agent,
        )
        req_id = self.add_node(req_node)

        resp_node = EvidenceNode(
            node_type=EvidenceType.RESPONSE,
            content={"status": response_status, "body": response_body[:500]},
            parent_id=req_id,
            agent=agent,
        )
        return self.add_node(resp_node)

    def add_observation(self, parent_id: str, observation: str, agent: str = "") -> str:
        """Creates an OBSERVATION node chained from a RESPONSE."""
        node = EvidenceNode(
            node_type=EvidenceType.OBSERVATION,
            content={"text": observation},
            parent_id=parent_id,
            agent=agent,
        )
        return self.add_node(node)

    def add_experiment(self, parent_id: str, plan: str, result: Dict[str, Any], agent: str = "") -> str:
        """Creates an EXPERIMENT node (differential test record)."""
        node = EvidenceNode(
            node_type=EvidenceType.EXPERIMENT,
            content={"plan": plan, "result": result},
            parent_id=parent_id,
            agent=agent,
        )
        return self.add_node(node)

    def add_verdict(self, parent_id: str, verdict: str, reason: str, confidence: float, agent: str = "") -> str:
        """Creates a VERDICT node. verdict ∈ {CONFIRMED, REJECTED, INCONCLUSIVE}."""
        node = EvidenceNode(
            node_type=EvidenceType.VERDICT,
            content={"verdict": verdict, "reason": reason, "confidence": confidence},
            parent_id=parent_id,
            agent=agent,
        )
        return self.add_node(node)

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        counts = {t.value: 0 for t in EvidenceType}
        for n in self._nodes.values():
            counts[n.node_type.value] += 1
        return {"total_nodes": len(self._nodes), "by_type": counts}

    def __len__(self) -> int:
        return len(self._nodes)
