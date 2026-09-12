"""
Unit Tests for AttackPathEngine (LuaN1ao-Inspired)
Tests: Shortest kill chains, all attack chains, and defensive chokepoints/bottleneck identification
"""
import pytest
from core.attack_graph.nodes import AttackNode, NodeType
from core.attack_graph.edges import EdgeType
from core.attack_graph.graph import CausalAttackGraph
from core.attack_graph.path_engine import AttackPathEngine


@pytest.fixture
def complex_attack_graph():
    """
    Creates a diamond-shaped graph with a shared critical chokepoint:
    Entry 1 \
              --> Gateway/API (Chokepoint) --> Auth Bypass --> Impact (DB Exfil)
    Entry 2 /
    """
    g = CausalAttackGraph(target="enterprise.local")
    e1 = g.add_node(AttackNode(id="e1", node_type=NodeType.ASSET, label="External Subdomain 1"))
    e2 = g.add_node(AttackNode(id="e2", node_type=NodeType.ASSET, label="External Subdomain 2"))
    gw = g.add_node(AttackNode(id="gw", node_type=NodeType.ENDPOINT, label="/api/gateway", risk_score=4.0))
    vuln = g.add_node(AttackNode(id="vuln", node_type=NodeType.VULNERABILITY, label="JWT Key Confusion", risk_score=8.5))
    impact = g.add_node(AttackNode(id="impact", node_type=NodeType.IMPACT, label="Database Exfiltration", risk_score=10.0))

    g.add_edge("e1", "gw", EdgeType.EXPOSES)
    g.add_edge("e2", "gw", EdgeType.EXPOSES)
    g.add_edge("gw", "vuln", EdgeType.HAS_VULNERABILITY)
    g.add_edge("vuln", "impact", EdgeType.LEADS_TO_IMPACT)

    return g


class TestAttackPathEngine:
    def test_find_shortest_kill_chain(self, complex_attack_graph):
        engine = AttackPathEngine(complex_attack_graph)
        chain = engine.find_shortest_kill_chain(start_node_id="e1", target_node_id="impact")
        assert chain is not None
        assert chain["hop_count"] == 3
        assert "External Subdomain 1 ➔ /api/gateway ➔ JWT Key Confusion ➔ Database Exfiltration" == chain["chain_readable"]

    def test_find_all_kill_chains(self, complex_attack_graph):
        engine = AttackPathEngine(complex_attack_graph)
        chains_from_e1 = engine.find_all_kill_chains("e1", "impact")
        chains_from_e2 = engine.find_all_kill_chains("e2", "impact")
        assert len(chains_from_e1) == 1
        assert len(chains_from_e2) == 1

    def test_identify_chokepoints_detects_bottleneck(self, complex_attack_graph):
        engine = AttackPathEngine(complex_attack_graph)
        chokepoints = engine.identify_chokepoints(entrypoints=["e1", "e2"], impact_nodes=["impact"])
        assert len(chokepoints) >= 2

        # Both /api/gateway and JWT Key Confusion appear on 100% (2 of 2) of attack chains
        top_chokepoint = chokepoints[0]
        assert top_chokepoint["paths_intercepted"] == 2
        assert top_chokepoint["interception_ratio"] == 1.0
        assert "neutralizes 2 of 2" in top_chokepoint["remediation_recommendation"]
