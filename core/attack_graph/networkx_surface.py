"""
NetworkX Graph Topology & Attack Surface Path Prioritization
Models interconnected attack surfaces as directed graphs (DAG), calculating shortest
testing paths, highest-risk entry points, and topological execution order.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class GraphNodeData:
    node_id: str
    node_type: str  # "domain", "subdomain", "endpoint", "parameter", "auth"
    risk_score: float = 0.0  # 0.0 to 10.0
    tested: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)


class NetworkXAttackSurfaceTopology:
    """
    طبولوجيا سطح الهجوم ورسم مسارات الفحص (NetworkX-Compatible Graph Topology):
    - تمثيل الأهداف والعلاقات كـ Directed Graph.
    - ترتيب الأولويات واختيار أعلى مسارات الفحص خطورة وأقصرها زمناً.
    """

    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.nodes: Dict[str, GraphNodeData] = {}
        self.adjacency: Dict[str, List[str]] = {}  # parent -> children
        self.in_degree: Dict[str, int] = {}

        # Root
        self.add_node(f"domain:{target_domain}", "domain", risk_score=1.0)

    def add_node(self, node_id: str, node_type: str, risk_score: float = 0.0, attributes: Optional[Dict[str, Any]] = None) -> GraphNodeData:
        if node_id not in self.nodes:
            node = GraphNodeData(node_id=node_id, node_type=node_type, risk_score=risk_score, attributes=attributes or {})
            self.nodes[node_id] = node
            self.adjacency[node_id] = []
            self.in_degree[node_id] = 0
            return node
        return self.nodes[node_id]

    def add_edge(self, from_id: str, to_id: str):
        if from_id in self.nodes and to_id in self.nodes:
            if to_id not in self.adjacency[from_id]:
                self.adjacency[from_id].append(to_id)
                self.in_degree[to_id] = self.in_degree.get(to_id, 0) + 1

    def get_highest_risk_untested_nodes(self, limit: int = 10) -> List[GraphNodeData]:
        """استرجاع العقد ذات الأولوية والخطورة الأعلى التي لم تُفحص بعد"""
        untested = [n for n in self.nodes.values() if not n.tested and n.node_type in ("endpoint", "parameter", "auth")]
        # Sort descending by risk score
        return sorted(untested, key=lambda n: n.risk_score, reverse=True)[:limit]

    def mark_tested(self, node_id: str):
        if node_id in self.nodes:
            self.nodes[node_id].tested = True

    def calculate_topological_plan(self) -> List[str]:
        """ترتيب تسلسل الفحص المنطقي من الجذور وحتى أعمق نقطة"""
        visited = set()
        order = []

        def dfs(curr: str):
            visited.add(curr)
            for child in self.adjacency.get(curr, []):
                if child not in visited:
                    dfs(child)
            order.append(curr)

        root = f"domain:{self.target_domain}"
        if root in self.nodes:
            dfs(root)

        return list(reversed(order))
