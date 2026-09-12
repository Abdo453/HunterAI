"""
Test Suite for Advanced Security Library Stack & Graph Topology
"""
from __future__ import annotations

import pytest
from core.static.js_ast_analyzer import JavaScriptASTAnalyzer
from core.traffic.traffic_interceptor import TrafficStreamInterceptor
from core.attack_graph.networkx_surface import NetworkXAttackSurfaceTopology


def test_js_ast_analyzer():
    sample_bundle_js = """
    import React from 'react';
    const API_URL = "/api/v1/users";
    function fetchOrders(userId) {
        return axios.get(`/api/v2/orders?user_id=${userId}`);
    }
    const query = gql`
        query GetUserProfile($id: ID!) {
            user(id: $id) { name email role }
        }
    `;
    const config = {
        apiKey: "AIzaSyD9876543210ZYXWVUTSRQPONMLK",
        params: {
            auth_token: "secret123",
            redirect_uri: "/dashboard"
        }
    };
    """
    res = JavaScriptASTAnalyzer.analyze_source(sample_bundle_js, "bundle.app.js")

    assert "React" in res.framework_hints
    assert "Apollo/GraphQL" in res.framework_hints
    assert any("/api/v1/users" in ep for ep in res.discovered_endpoints)
    assert any("user_id" in p for p in res.extracted_parameters)
    assert len(res.graphql_queries) >= 1
    assert len(res.potential_secrets) >= 1


def test_traffic_stream_interceptor_and_differentials():
    interceptor = TrafficStreamInterceptor()

    # 1. Record normal flow
    f1 = interceptor.record_flow(
        method="GET",
        url="https://app.local/api/profile?id=101",
        request_headers={"Host": "app.local", "User-Agent": "HunterAI"},
        request_body=None,
        status_code=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"id": 101, "name": "Alice"}',
        response_time_ms=45.2
    )

    # 2. Record probe flow with differential
    f2 = interceptor.record_flow(
        method="GET",
        url="https://app.local/api/profile?id=101'",
        request_headers={"Host": "app.local", "User-Agent": "HunterAI"},
        request_body=None,
        status_code=500,
        response_headers={"Content-Type": "application/json"},
        response_body='{"error": "SQL syntax error"}',
        response_time_ms=52.0
    )

    diff = interceptor.calculate_differential(f1, f2)
    assert diff["status_changed"] is True
    assert diff["is_significant_delta"] is True
    assert diff["baseline_status"] == 200
    assert diff["probe_status"] == 500


def test_networkx_attack_surface_topology():
    topo = NetworkXAttackSurfaceTopology("shop.local")

    topo.add_node("subdomain:api.shop.local", "subdomain", risk_score=2.0)
    topo.add_edge("domain:shop.local", "subdomain:api.shop.local")

    topo.add_node("endpoint:/api/v1/checkout", "endpoint", risk_score=8.5)
    topo.add_edge("subdomain:api.shop.local", "endpoint:/api/v1/checkout")

    topo.add_node("parameter:coupon_code", "parameter", risk_score=9.0)
    topo.add_edge("endpoint:/api/v1/checkout", "parameter:coupon_code")

    highest_risk = topo.get_highest_risk_untested_nodes(limit=2)
    assert len(highest_risk) == 2
    assert highest_risk[0].node_id == "parameter:coupon_code"
    assert highest_risk[0].risk_score == 9.0

    plan = topo.calculate_topological_plan()
    assert plan[0] == "domain:shop.local"
    assert "parameter:coupon_code" in plan
