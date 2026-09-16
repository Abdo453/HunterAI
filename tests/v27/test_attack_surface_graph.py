"""
Tests for Attack Surface Graph (9 Epistemic Statuses)
"""
import pytest
from core.reasoning.attack_surface_graph import (
    AttackSurfaceGraph,
    EpistemicStatus,
    SurfaceEdge,
    SurfaceNode,
)


def test_attack_surface_graph_partially_verified_handling():
    graph = AttackSurfaceGraph(target_domain="saas.local")

    n_login = graph.add_node(SurfaceNode(node_id="n_login", node_type="STATE", name="LOGIN", epistemic_status=EpistemicStatus.OBSERVED))
    n_dashboard = graph.add_node(SurfaceNode(node_id="n_dash", node_type="STATE", name="DASHBOARD", epistemic_status=EpistemicStatus.OBSERVED))

    edge_jump = graph.add_edge(SurfaceEdge(
        edge_id="e_jump",
        source_node_id="n_login",
        target_node_id="n_dash",
        relation_type="CANDIDATE_VIOLATION",
        epistemic_status=EpistemicStatus.CANDIDATE,
    ))

    candidates = graph.get_unexplored_candidates()
    assert len(candidates) == 1
    assert candidates[0].edge_id == "e_jump"

    graph.update_status("e_jump", EpistemicStatus.PARTIALLY_VERIFIED, evidence_ref="ev_e1_pass_e2_fail", rationale="Metamorphic divergence")
    assert edge_jump.epistemic_status == EpistemicStatus.PARTIALLY_VERIFIED

    partially = graph.get_partially_verified()
    assert len(partially) == 1
    assert partially[0].edge_id == "e_jump"
