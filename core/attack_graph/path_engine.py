"""
Attack Path & Kill-Chain Engine (LuaN1ao-Inspired)
Identifies multi-hop kill chains, shortest paths to high-value impact nodes,
and calculates defensive chokepoints / bottlenecks in the Attack Graph.
"""
import logging
from collections import deque
from typing import Dict, List, Set, Any, Optional

from core.attack_graph.graph import CausalAttackGraph
from core.attack_graph.nodes import NodeType

log = logging.getLogger("core.attack_graph.path_engine")


class AttackPathEngine:
    """
    محرك مسارات الهجوم وسلاسل القتل:
    يكتشف السلاسل السببية التي تربط نقاط الدخول بالأهداف الحساسة
    ويحدد نقاط الاختناق (Chokepoints) لقطع الهجوم بأقل كلفة دفاعية
    """

    def __init__(self, graph: CausalAttackGraph):
        self.graph = graph

    def find_shortest_kill_chain(
        self,
        start_node_id: str,
        target_node_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        العثور على أقصر سلسلة قتل بين نقطة البداية ونقطة الهدف
        """
        if start_node_id not in self.graph.nodes or target_node_id not in self.graph.nodes:
            return None

        queue = deque([(start_node_id, [start_node_id])])
        visited: Set[str] = {start_node_id}

        while queue:
            curr_id, path = queue.popleft()
            if curr_id == target_node_id:
                return self._build_path_summary(path)

            for neighbor_id in self.graph._adj.get(curr_id, []):
                if neighbor_id not in visited:
                    visited.add(neighbor_id)
                    queue.append((neighbor_id, path + [neighbor_id]))

        return None

    def find_all_kill_chains(
        self,
        start_node_id: str,
        target_node_id: str,
        max_hops: int = 6
    ) -> List[Dict[str, Any]]:
        """
        استخراج كافة مسارات الهجوم الممكنة بين نقطتين بحد أقصى للقفزات
        """
        if start_node_id not in self.graph.nodes or target_node_id not in self.graph.nodes:
            return []

        all_paths: List[List[str]] = []

        def _dfs(current: str, current_path: List[str], depth: int):
            if current == target_node_id:
                all_paths.append(list(current_path))
                return
            if depth >= max_hops:
                return

            for neighbor in self.graph._adj.get(current, []):
                if neighbor not in current_path:  # Prevent cycles
                    current_path.append(neighbor)
                    _dfs(neighbor, current_path, depth + 1)
                    current_path.pop()

        _dfs(start_node_id, [start_node_id], 0)
        return [self._build_path_summary(p) for p in all_paths]

    def identify_chokepoints(
        self,
        entrypoints: Optional[List[str]] = None,
        impact_nodes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        تحديد نقاط الاختناق (Chokepoints / Bottlenecks):
        العقد التي تتكرر في معظم سلاسل الهجوم والتي بقطعها ينكسر أكبر عدد من مسارات الاختراق
        """
        starts = entrypoints or [
            n.id for n in self.graph.find_nodes_by_type(NodeType.ASSET)
            if not self.graph._inv_adj.get(n.id)  # Entrypoint roots
        ]
        if not starts:
            starts = [n.id for n in self.graph.find_nodes_by_type(NodeType.ASSET)]

        goals = impact_nodes or [
            n.id for n in self.graph.find_nodes_by_type(NodeType.IMPACT)
        ]

        # Gather all paths between all (start, goal) pairs
        node_frequencies: Dict[str, int] = {}
        total_paths = 0

        for s in starts:
            for g in goals:
                chains = self.find_all_kill_chains(s, g, max_hops=6)
                for chain in chains:
                    total_paths += 1
                    # Count intermediate nodes (exclude direct start and goal)
                    for node_info in chain["nodes"][1:-1]:
                        nid = node_info["id"]
                        node_frequencies[nid] = node_frequencies.get(nid, 0) + 1

        if total_paths == 0:
            return []

        chokepoints = []
        for nid, count in node_frequencies.items():
            node = self.graph.nodes[nid]
            blocking_ratio = round(count / total_paths, 3)
            chokepoints.append({
                "node_id": nid,
                "label": node.label,
                "type": node.node_type.value,
                "paths_intercepted": count,
                "total_paths": total_paths,
                "interception_ratio": blocking_ratio,
                "remediation_recommendation": f"Securing '{node.label}' neutralizes {count} of {total_paths} ({blocking_ratio:.1%}) attack chains."
            })

        chokepoints.sort(key=lambda x: x["paths_intercepted"], reverse=True)
        return chokepoints

    def _build_path_summary(self, node_ids: List[str]) -> Dict[str, Any]:
        nodes_detail = []
        cumulative_risk = 0.0

        for nid in node_ids:
            n = self.graph.nodes[nid]
            cumulative_risk += n.risk_score
            nodes_detail.append({
                "id": nid,
                "label": n.label,
                "type": n.node_type.value,
                "risk_score": n.risk_score
            })

        # Chain description e.g. "Asset -> Endpoint -> Vuln -> Impact"
        chain_readable = " ➔ ".join(n["label"] for n in nodes_detail)

        return {
            "hop_count": len(node_ids) - 1,
            "chain_readable": chain_readable,
            "cumulative_risk": round(cumulative_risk, 2),
            "nodes": nodes_detail
        }
