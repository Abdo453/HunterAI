"""
Mission Topology & Attack Graph Synchronizer (v2.0)
===================================================
Real-time graph model representing target surface topology, discovered parameters,
vulnerability hypotheses, and verified attack chains for Web UI visualization.
"""

import time
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class GraphNode:
    id: str
    label: str
    type: str  # "target", "endpoint", "parameter", "technology", "vulnerability"
    severity: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str  # "exposes", "accepts_param", "vulnerable_to", "authenticated_as"
    metadata: Dict[str, Any] = field(default_factory=dict)


class MissionTopologySynchronizer:
    """Manages the live attack graph for mission visualization"""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.root_node_id = f"target_{hashlib.md5(target_url.encode()).hexdigest()[:6]}"
        self.nodes: Dict[str, GraphNode] = {
            self.root_node_id: GraphNode(id=self.root_node_id, label=target_url, type="target")
        }
        self.edges: List[GraphEdge] = []

    def add_endpoint(self, endpoint_url: str, method: str = "GET") -> str:
        ep_id = f"ep_{hashlib.md5(f'{method}_{endpoint_url}'.encode()).hexdigest()[:6]}"
        if ep_id not in self.nodes:
            self.nodes[ep_id] = GraphNode(
                id=ep_id,
                label=f"{method} {endpoint_url}",
                type="endpoint",
                metadata={"url": endpoint_url, "method": method}
            )
            self.edges.append(GraphEdge(source=self.root_node_id, target=ep_id, relation="exposes"))
        return ep_id

    def add_parameter(self, endpoint_id: str, param_name: str, param_type: str = "query") -> str:
        p_id = f"param_{endpoint_id}_{param_name}"
        if p_id not in self.nodes:
            self.nodes[p_id] = GraphNode(
                id=p_id,
                label=param_name,
                type="parameter",
                metadata={"name": param_name, "param_type": param_type}
            )
            self.edges.append(GraphEdge(source=endpoint_id, target=p_id, relation="accepts_param"))
        return p_id

    def add_vulnerability(self, param_id: str, vuln_title: str, severity: str = "High") -> str:
        v_id = f"vuln_{param_id}_{hashlib.md5(vuln_title.encode()).hexdigest()[:4]}"
        if v_id not in self.nodes:
            self.nodes[v_id] = GraphNode(
                id=v_id,
                label=vuln_title,
                type="vulnerability",
                severity=severity,
                metadata={"title": vuln_title}
            )
            self.edges.append(GraphEdge(source=param_id, target=v_id, relation="vulnerable_to"))
        return v_id

    def to_cytoscape_json(self) -> Dict[str, Any]:
        """Exports graph in Cytoscape/D3 compatible JSON format"""
        elements = []
        for n in self.nodes.values():
            elements.append({
                "data": {
                    "id": n.id,
                    "label": n.label,
                    "type": n.type,
                    "severity": n.severity,
                    **n.metadata
                }
            })
        for e in self.edges:
            elements.append({
                "data": {
                    "source": e.source,
                    "target": e.target,
                    "relation": e.relation,
                    **e.metadata
                }
            })
        return {"elements": elements, "node_count": len(self.nodes), "edge_count": len(self.edges)}
