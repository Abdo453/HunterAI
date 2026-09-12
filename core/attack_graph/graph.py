"""
Causal Attack Graph Engine (LuaN1ao & Cairn-Inspired)
Centralized directed causal graph representing assets, attack surfaces, vulnerabilities,
privilege transitions, and security blast radius.
"""
import logging
from collections import deque
from typing import Dict, List, Set, Any, Optional, Tuple

from core.attack_graph.nodes import AttackNode, NodeType
from core.attack_graph.edges import AttackEdge, EdgeType

log = logging.getLogger("core.attack_graph.graph")


class CausalAttackGraph:
    """
    الرسم البياني السببي للهجوم:
    يربط بين الأصول والمسارات والهويات والثغرات في شبكة سببية موجهة
    تمكن الـ Agent من فهم سلسلة القتل (Kill Chain) ونصف قطر الانفجار (Blast Radius)
    """

    def __init__(self, target: str = "target.local"):
        self.target = target
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: Dict[str, AttackEdge] = {}
        self._adj: Dict[str, List[str]] = {}       # node_id -> list of target_ids
        self._inv_adj: Dict[str, List[str]] = {}   # node_id -> list of source_ids

    def add_node(self, node: AttackNode) -> AttackNode:
        """Add or update a node in the graph"""
        self.nodes[node.id] = node
        if node.id not in self._adj:
            self._adj[node.id] = []
        if node.id not in self._inv_adj:
            self._inv_adj[node.id] = []
        return node

    def get_node(self, node_id: str) -> Optional[AttackNode]:
        return self.nodes.get(node_id)

    def find_nodes_by_type(self, node_type: NodeType) -> List[AttackNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def find_node_by_label(self, label: str, node_type: Optional[NodeType] = None) -> Optional[AttackNode]:
        for n in self.nodes.values():
            if n.label == label:
                if node_type is None or n.node_type == node_type:
                    return n
        return None

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        weight: float = 1.0,
        confidence: float = 1.0,
        properties: Optional[Dict[str, Any]] = None,
        provenance: Optional[str] = None
    ) -> AttackEdge:
        """Create a directed causal edge between two nodes"""
        if source_id not in self.nodes:
            raise KeyError(f"Source node '{source_id}' does not exist in graph.")
        if target_id not in self.nodes:
            raise KeyError(f"Target node '{target_id}' does not exist in graph.")

        edge = AttackEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            weight=weight,
            confidence=confidence,
            properties=properties or {},
            provenance=provenance
        )
        self.edges[edge.id] = edge
        self._adj[source_id].append(target_id)
        self._inv_adj[target_id].append(source_id)
        return edge

    def get_outgoing_edges(self, node_id: str) -> List[AttackEdge]:
        return [e for e in self.edges.values() if e.source_id == node_id]

    def get_incoming_edges(self, node_id: str) -> List[AttackEdge]:
        return [e for e in self.edges.values() if e.target_id == node_id]

    def calculate_blast_radius(self, start_node_id: str, max_depth: int = 5) -> Dict[str, Any]:
        """
        حساب نصف قطر الانفجار (Blast Radius) والأثر التراكمي لاختراق عقدة معينة
        يرجع جميع العقد التي يمكن للمهاجم الوصول إليها انطلاقاً من هذه العقدة
        """
        if start_node_id not in self.nodes:
            return {"reachable_nodes": [], "max_depth": 0, "cumulative_risk": 0.0}

        visited: Set[str] = {start_node_id}
        queue = deque([(start_node_id, 0)])
        reachable_details: List[Dict[str, Any]] = []
        max_reached_depth = 0
        cumulative_risk = 0.0

        while queue:
            curr_id, depth = queue.popleft()
            curr_node = self.nodes[curr_id]
            max_reached_depth = max(max_reached_depth, depth)
            cumulative_risk += curr_node.risk_score

            if curr_id != start_node_id:
                reachable_details.append({
                    "id": curr_id,
                    "label": curr_node.label,
                    "type": curr_node.node_type.value,
                    "depth": depth,
                    "risk_score": curr_node.risk_score
                })

            if depth < max_depth:
                for next_id in self._adj.get(curr_id, []):
                    if next_id not in visited:
                        visited.add(next_id)
                        queue.append((next_id, depth + 1))

        # Categorize by impact types
        impact_nodes = [r for r in reachable_details if r["type"] == NodeType.IMPACT.value]
        identity_nodes = [r for r in reachable_details if r["type"] == NodeType.IDENTITY.value]

        return {
            "root_node": self.nodes[start_node_id].label,
            "reachable_count": len(reachable_details),
            "max_depth": max_reached_depth,
            "cumulative_risk": round(cumulative_risk, 2),
            "critical_impacts": [n["label"] for n in impact_nodes],
            "compromised_identities": [n["label"] for n in identity_nodes],
            "reachable_nodes": reachable_details
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete graph for UI visualization and API export"""
        return {
            "target": self.target,
            "summary": {
                "total_nodes": len(self.nodes),
                "total_edges": len(self.edges),
                "node_types": self._get_node_type_counts(),
                "edge_types": self._get_edge_type_counts()
            },
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()]
        }

    def _get_node_type_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for n in self.nodes.values():
            counts[n.node_type.value] = counts.get(n.node_type.value, 0) + 1
        return counts

    def _get_edge_type_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self.edges.values():
            counts[e.edge_type.value] = counts.get(e.edge_type.value, 0) + 1
        return counts
