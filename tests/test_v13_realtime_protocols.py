"""
HunterAI V13.0 Modern & Real-Time Protocol Security Test Suite
==============================================================
Verifies:
1. Cross-Site WebSocket Hijacking (CSWSH) Origin Spoofing Matrix
2. WebSocket Frame-Level Authorization & Sensitive Mutation Detection
3. GraphQL Subscription connection_init Authentication Gating
4. GraphQL Pub/Sub Cross-Tenant Data Leak Detection (Tenant Boundary Isolation)
5. GraphQL Subscription Query Complexity & Fan-Out Depth Limits
6. Protobuf Binary Wire Dissection without .proto Schema
7. gRPC-Web Metadata Authentication & Sensitive Method Auditing
8. gRPC Error Trailer Internal Information Leak Detection
9. AST Protocol Defensive Remediation Synthesis (WebSocket, GraphQL, gRPC)
"""
import pytest
from core.protocols.websocket_agent import (
    WebSocketSecurityAgent,
    CSWSHOriginTestType,
    CSWSHTrialResult,
)
from core.protocols.graphql_subscription_auditor import (
    GraphQLSubscriptionAuditor,
    GraphQLSubProtocol,
    SubscriptionAuditEvent,
)
from core.protocols.grpc_web_dissector import (
    ProtobufWireDissector,
    ProtobufWireType,
    GRPCWebSecurityAuditor,
)
from core.remediation.protocol_remediation import (
    ProtocolRemediationEngine,
    ProtocolRemediationResult,
)


def test_cswsh_origin_matrix_detection():
    agent = WebSocketSecurityAgent(target_domain="acme.com")

    # Mock server that erroneously accepts upgrade for any origin
    def vulnerable_handshake(url, headers):
        return 101, {"Upgrade": "websocket"}

    trials = agent.audit_cswsh_matrix(
        ws_url="wss://acme.com/ws/chat",
        cookies={"session_id": "authenticated_cookie_123"},
        handshake_fn=vulnerable_handshake
    )

    assert len(trials) == 4
    # All non-target origins accepted with authenticated cookies must be flagged as vulnerable
    vuln_trials = [t for t in trials if t.is_vulnerable]
    assert len(vuln_trials) == 4
    assert any(t.test_type == CSWSHOriginTestType.EXTERNAL_EVIL_DOMAIN for t in vuln_trials)
    assert any(t.test_type == CSWSHOriginTestType.NULL_ORIGIN for t in vuln_trials)
    assert vuln_trials[0].cwe_id == "CWE-1385"


def test_cswsh_origin_matrix_secure_rejection():
    agent = WebSocketSecurityAgent(target_domain="acme.com")

    # Secure server: rejects untrusted origins with HTTP 403
    def secure_handshake(url, headers):
        return 403, {}

    trials = agent.audit_cswsh_matrix(
        ws_url="wss://acme.com/ws/chat",
        cookies={"session_id": "authenticated_cookie_123"},
        handshake_fn=secure_handshake
    )

    assert len(trials) == 4
    assert all(not t.is_vulnerable for t in trials)
    assert all(t.handshake_status == 403 for t in trials)


def test_websocket_frame_authorization():
    agent = WebSocketSecurityAgent(target_domain="acme.com")

    frames = [
        '{"event": "ping"}',
        '{"event": "transfer_funds", "action": "transfer", "amount": 500, "to": "attacker"}',
    ]

    # Without session token: mutation must be flagged
    report_unauth = agent.audit_frame_authorization("wss://acme.com/ws", frames, has_session_token=False)
    assert report_unauth.vulnerability_detected is True
    assert report_unauth.unauthenticated_mutations_allowed is True
    assert report_unauth.unauthorized_frames_accepted == 1

    # With session token: verified
    report_auth = agent.audit_frame_authorization("wss://acme.com/ws", frames, has_session_token=True)
    assert report_auth.vulnerability_detected is False


def test_graphql_subscription_connection_init():
    # 1. Missing token
    valid_no_token, msg = GraphQLSubscriptionAuditor.validate_connection_init("graphql-ws", {})
    assert valid_no_token is False
    assert "VULNERABLE" in msg

    # 2. Present token
    valid_with_token, msg2 = GraphQLSubscriptionAuditor.validate_connection_init(
        "graphql-ws", {"Authorization": "Bearer sample_jwt_token"}
    )
    assert valid_with_token is True
    assert "SECURE" in msg2


def test_graphql_subscription_cross_tenant_isolation():
    query = "subscription { invoiceGenerated { id tenantId total } }"

    # Attack/Leak Case: Subscriber belongs to 'org_alpha', but receives event with 'org_beta'
    leaked_event = {"id": "INV-99", "tenantId": "org_beta", "total": 4500.0}
    audit_leak = GraphQLSubscriptionAuditor.audit_tenant_boundary(
        subscription_query=query,
        subscriber_tenant_id="org_alpha",
        emitted_event_data=leaked_event
    )
    assert audit_leak.is_cross_tenant_leak is True
    assert audit_leak.severity == "CRITICAL"
    assert "CRITICAL MULTI-TENANT LEAK" in audit_leak.details

    # Compliant Case: Event belongs to 'org_alpha'
    safe_event = {"id": "INV-100", "tenantId": "org_alpha", "total": 120.0}
    audit_safe = GraphQLSubscriptionAuditor.audit_tenant_boundary(
        subscription_query=query,
        subscriber_tenant_id="org_alpha",
        emitted_event_data=safe_event
    )
    assert audit_safe.is_cross_tenant_leak is False
    assert audit_safe.severity == "NONE"


def test_graphql_subscription_complexity_depth():
    shallow_query = "subscription { userOnline { id name } }"
    res_shallow = GraphQLSubscriptionAuditor.audit_subscription_complexity(shallow_query, max_depth_limit=5)
    assert res_shallow["is_excessive_depth"] is False
    assert res_shallow["risk"] == "LOW"

    deep_query = "subscription { a { b { c { d { e { f { g { h { leak } } } } } } } } }"
    res_deep = GraphQLSubscriptionAuditor.audit_subscription_complexity(deep_query, max_depth_limit=5)
    assert res_deep["is_excessive_depth"] is True
    assert res_deep["risk"] == "HIGH"


def test_protobuf_wire_dissector():
    # Construct binary protobuf:
    # Field 1: string "hello" -> Tag: (1 << 3) | 2 = 10 (0x0A), Length: 5, Bytes: b"hello"
    # Field 2: varint 150 -> Tag: (2 << 3) | 0 = 16 (0x10), Varint 150: 150 = 0x96 0x01
    sample_bytes = b"\x0a\x05hello\x10\x96\x01"

    fields = ProtobufWireDissector.dissect(sample_bytes)
    assert len(fields) == 2

    f1 = fields[0]
    assert f1.field_number == 1
    assert f1.wire_type == ProtobufWireType.LENGTH_DELIMITED
    assert f1.decoded_value == "hello"

    f2 = fields[1]
    assert f2.field_number == 2
    assert f2.wire_type == ProtobufWireType.VARINT
    assert f2.decoded_value == 150


def test_grpc_web_security_auditor():
    rpc_method = "/api.AdminService/PurgeRecords"
    raw_payload = b"\x0a\x03all"

    # 1. Unauthenticated request to sensitive RPC
    res_unauth = GRPCWebSecurityAuditor.audit_rpc_request(
        rpc_method_path=rpc_method,
        headers={"content-type": "application/grpc-web+proto"},
        raw_protobuf_body=raw_payload
    )
    assert res_unauth["is_sensitive_operation"] is True
    assert res_unauth["has_authorization_metadata"] is False
    assert res_unauth["is_unauthorized_hazard"] is True
    assert res_unauth["risk_level"] == "HIGH"

    # 2. Authenticated request
    res_auth = GRPCWebSecurityAuditor.audit_rpc_request(
        rpc_method_path=rpc_method,
        headers={"content-type": "application/grpc-web+proto", "authorization": "Bearer token123"},
        raw_protobuf_body=raw_payload
    )
    assert res_auth["has_authorization_metadata"] is True
    assert res_auth["is_unauthorized_hazard"] is False


def test_grpc_error_trailer_leak_detection():
    # Leaking SQL syntax error
    trailers_leaking = {
        "grpc-status": "13",
        "grpc-message": "Internal error: pg_query() syntax error at or near 'admin'"
    }
    audit_leak = GRPCWebSecurityAuditor.audit_response_trailers(trailers_leaking)
    assert audit_leak["contains_internal_leak"] is True
    assert audit_leak["risk_level"] == "HIGH"

    # Sanitized trailer
    trailers_safe = {
        "grpc-status": "3",
        "grpc-message": "Invalid argument provided."
    }
    audit_safe = GRPCWebSecurityAuditor.audit_response_trailers(trailers_safe)
    assert audit_safe["contains_internal_leak"] is False


def test_protocol_remediation_engine_synthesis():
    # 1. WebSocket Origin Guard
    ws_rem = ProtocolRemediationEngine.generate_websocket_origin_guard(["acme.com"])
    assert ws_rem.protocol == "websocket"
    assert "verify_websocket_origin" in ws_rem.middleware_code
    assert "test_websocket_rejects_untrusted_origin" in ws_rem.regression_test_code

    # 2. GraphQL Subscription Tenant Guard
    gql_rem = ProtocolRemediationEngine.generate_graphql_tenant_guard()
    assert gql_rem.protocol == "graphql-sub"
    assert "require_subscription_tenant_match" in gql_rem.middleware_code
    assert "test_subscriber_only_receives_own_tenant_events" in gql_rem.regression_test_code

    # 3. gRPC Auth Interceptor
    grpc_rem = ProtocolRemediationEngine.generate_grpc_auth_interceptor()
    assert grpc_rem.protocol == "grpc"
    assert "GRPCAuthInterceptor" in grpc_rem.middleware_code
    assert "grpc.StatusCode.UNAUTHENTICATED" in grpc_rem.middleware_code
