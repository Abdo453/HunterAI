"""
Unit Tests for Causal Attack Graph (LuaN1ao & Cairn-Inspired)
Tests: Nodes, Edges, Topological traversal, Blast radius calculation, and Graph serialization
"""
import pytest
from core.attack_graph.nodes import AttackNode, NodeType
from core.attack_graph.edges import AttackEdge, EdgeType
from core.attack_graph.graph import CausalAttackGraph


class TestCausalAttackGraph:
    """Test core graph modeling and blast radius computations"""

    def setup_method(self):
        self.graph = CausalAttackGraph(target="target.local")

    def test_node_creation_and_retrieval(self):
        node = AttackNode(
            id="asset-1",
            node_type=NodeType.ASSET,
            label="api.target.local",
            risk_score=2.0
        )
        self.graph.add_node(node)
        retrieved = self.graph.get_node("asset-1")
        assert retrieved is not None
        assert retrieved.label == "api.target.local"
        assert retrieved.node_type == NodeType.ASSET

    def test_edge_creation_and_connections(self):
        n1 = self.graph.add_node(AttackNode(id="n1", node_type=NodeType.ASSET, label="Host"))
        n2 = self.graph.add_node(AttackNode(id="n2", node_type=NodeType.SERVICE, label="Nginx"))
        edge = self.graph.add_edge(source_id=n1.id, target_id=n2.id, edge_type=EdgeType.EXPOSES)

        assert edge.source_id == "n1"
        assert edge.target_id == "n2"
        assert len(self.graph.get_outgoing_edges("n1")) == 1
        assert len(self.graph.get_incoming_edges("n2")) == 1

    def test_edge_fails_on_missing_node(self):
        self.graph.add_node(AttackNode(id="valid_node", node_type=NodeType.ASSET, label="Valid"))
        with pytest.raises(KeyError):
            self.graph.add_edge(source_id="valid_node", target_id="non_existent", edge_type=EdgeType.EXPOSES)

    def test_blast_radius_calculation(self):
        # Build multi-tier chain: Asset -> Service -> Endpoint -> Vuln -> Impact
        a = self.graph.add_node(AttackNode(id="a", node_type=NodeType.ASSET, label="Host", risk_score=1.0))
        s = self.graph.add_node(AttackNode(id="s", node_type=NodeType.SERVICE, label="HTTP", risk_score=2.0))
        e = self.graph.add_node(AttackNode(id="e", node_type=NodeType.ENDPOINT, label="/invoices", risk_score=3.0))
        v = self.graph.add_node(AttackNode(id="v", node_type=NodeType.VULNERABILITY, label="BOLA", risk_score=8.0))
        i = self.graph.add_node(AttackNode(id="i", node_type=NodeType.IMPACT, label="Data Exfil", risk_score=9.0))

        self.graph.add_edge("a", "s", EdgeType.EXPOSES)
        self.graph.add_edge("s", "e", EdgeType.EXPOSES)
        self.graph.add_edge("e", "v", EdgeType.HAS_VULNERABILITY)
        self.graph.add_edge("v", "i", EdgeType.LEADS_TO_IMPACT)

        blast = self.graph.calculate_blast_radius(start_node_id="a")
        assert blast["reachable_count"] == 4
        assert blast["max_depth"] == 4
        assert "Data Exfil" in blast["critical_impacts"]
        assert blast["cumulative_risk"] == 23.0  # 1+2+3+8+9

    def test_graph_serialization_to_dict(self):
        self.graph.add_node(AttackNode(id="a1", node_type=NodeType.ASSET, label="Host A"))
        d = self.graph.to_dict()
        assert "target" in d
        assert "summary" in d
        assert d["summary"]["total_nodes"] == 1
        assert len(d["nodes"]) == 1
