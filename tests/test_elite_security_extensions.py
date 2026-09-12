"""
Test Suite for the 5 Elite Security Subsystems:
1. Out-of-Band (OOB) Blind Interaction Engine
2. Multi-Role RBAC Privilege Matrix Engine
3. WebSocket Security & CSWSH Inspector
4. Adaptive WAF Playwright Bridge
5. Context-Aware Injection Escaping & Minimal Canary Engine
"""
from __future__ import annotations

import pytest
from core.oob.oob_client import OOBInteractionClient, OOBProbeContext
from core.authz.rbac_matrix_engine import RBACPrivilegeMatrixEngine, RoleSession
from core.websocket.websocket_inspector import WebSocketSecurityInspector
from core.waf.adaptive_waf_bridge import AdaptiveWAFPlaywrightBridge, WAFClearanceBundle
from core.canary.context_canary_engine import ContextCanaryEngine, ReflectionContext


def test_oob_interaction_client():
    client = OOBInteractionClient(base_callback_domain="oob.hunter.local")
    ctx: OOBProbeContext = client.generate_probe_context(
        target_endpoint="/api/v1/import?url=",
        parameter_name="url",
        vulnerability_type="blind_ssrf"
    )

    assert ctx.token in ctx.canary_domain
    assert ctx.canary_domain.endswith(".oob.hunter.local")

    payloads = client.craft_canary_payload(ctx)
    assert ctx.canary_domain in payloads["http_url"]
    assert "nslookup" in payloads["rce_nslookup"]

    # Simulate incoming DNS/HTTP interaction from target server
    matched_ctx = client.record_incoming_interaction(
        token=ctx.token,
        protocol="DNS",
        remote_address="192.168.1.50",
        raw_query_or_path=ctx.canary_domain
    )

    assert matched_ctx is not None
    assert matched_ctx.probe_id == ctx.probe_id
    assert matched_ctx.verified_interaction.protocol == "DNS"

    polled, inter = client.poll_for_verification(ctx.token)
    assert polled is True
    assert inter.remote_address == "192.168.1.50"


def test_rbac_privilege_matrix_engine():
    engine = RBACPrivilegeMatrixEngine()
    engine.register_role_session("admin", "admin_user_01", auth_headers={"Authorization": "Bearer admin_token"})
    engine.register_role_session("standard_user", "regular_user_02", auth_headers={"Authorization": "Bearer user_token"})
    engine.register_role_session("anonymous", "unauth_guest", auth_headers={})

    # Mock request executor simulating a vulnerable admin endpoint
    def mock_request_executor(url: str, method: str, session: RoleSession):
        if url == "/api/admin/users":
            if session.role_name == "admin":
                return 200, 450, '{"users": [{"id": 1}, {"id": 2}]}'
            elif session.role_name == "standard_user":
                # VULNERABILITY: Standard user improperly receives admin data!
                return 200, 450, '{"users": [{"id": 1}, {"id": 2}]}'
            else:
                return 401, 30, '{"error": "Unauthorized"}'
        return 404, 0, ""

    eval_res = engine.evaluate_endpoint(
        endpoint_url="/api/admin/users",
        method="GET",
        expected_allowed_roles=["admin"],
        request_executor_fn=mock_request_executor
    )

    assert eval_res.vulnerability_detected is True
    assert eval_res.vulnerability_type == "BFLA_Vertical_Privilege_Escalation"
    assert eval_res.severity == "High"
    assert eval_res.role_results["standard_user"].accessible is True
    assert eval_res.role_results["anonymous"].accessible is False

    matrix_md = engine.generate_matrix_markdown()
    assert "[MATRIX] RBAC Privilege Access Control Matrix" in matrix_md
    assert "BFLA_Vertical_Privilege_Escalation" in matrix_md


def test_websocket_security_inspector():
    inspector = WebSocketSecurityInspector(evil_origin="https://evil-attacker.local")

    # 1. Test CSWSH Handshake (Mock server rejecting evil origin)
    def secure_handshake_fn(url: str, headers: dict):
        if headers.get("Origin") == "https://evil-attacker.local":
            return 403, {"Content-Type": "text/plain"}
        return 101, {"Upgrade": "websocket"}

    audit_secure = inspector.audit_cswsh_handshake(
        ws_url="wss://app.local/ws/chat",
        cookies={"session": "auth_cookie_123"},
        handshake_fn=secure_handshake_fn
    )
    assert audit_secure.cswsh_vulnerable is False
    assert audit_secure.handshake_status == 403

    # 2. Test CSWSH Handshake (Vulnerable server accepting evil origin)
    def vuln_handshake_fn(url: str, headers: dict):
        return 101, {"Upgrade": "websocket", "Connection": "Upgrade"}

    audit_vuln = inspector.audit_cswsh_handshake(
        ws_url="wss://app.local/ws/notifications",
        cookies={"session": "auth_cookie_123"},
        handshake_fn=vuln_handshake_fn
    )
    assert audit_vuln.cswsh_vulnerable is True
    assert audit_vuln.handshake_status == 101

    # 3. Test Message Frame Inspection
    msg_audit = inspector.inspect_message_frame(
        ws_url="wss://app.local/ws/chat",
        raw_message='{"jsonrpc": "2.0", "method": "update_balance", "params": {"token": "secret123", "amount": 1000}}'
    )
    assert msg_audit.protocol == "json-rpc"
    assert msg_audit.contains_sensitive_data is True
    assert msg_audit.allows_unauthorized_mutation is True


@pytest.mark.asyncio
async def test_adaptive_waf_playwright_bridge():
    bridge = AdaptiveWAFPlaywrightBridge(headless=True)

    # 1. Challenge Response Detection
    is_chal, waf = bridge.is_challenge_response(
        status_code=403,
        response_headers={"Server": "cloudflare", "cf-ray": "12345"},
        response_body="<html><title>Just a moment...</title>challenges.cloudflare.com</html>"
    )
    assert is_chal is True
    assert "Cloudflare" in waf

    # 2. Solve Challenge and Extract Clearance
    bundle = await bridge.solve_challenge_and_extract_clearance("https://protected.target.local")
    assert bundle.challenge_solved is True
    assert "cf_clearance" in bundle.clearance_cookies

    # 3. Inject Clearance into Outgoing Request Headers
    req_headers = {"User-Agent": "Old-UA"}
    injected = bridge.inject_clearance_into_headers("https://protected.target.local/api/test", req_headers)
    assert "cf_clearance=" in injected["Cookie"]
    assert injected["User-Agent"] == bundle.user_agent


def test_context_canary_engine():
    engine = ContextCanaryEngine()
    marker = "HNT_SAFE_9876"

    # 1. HTML Body Context
    html_1 = f"<div>Search results for: {marker}</div>"
    res_1 = engine.detect_reflection_context(marker, html_1)
    assert res_1.context == ReflectionContext.HTML_BODY
    assert "<b>hnt_canary</b>" in res_1.recommended_safe_escape

    # 2. Attribute Value Context
    html_2 = f'<input type="text" name="q" value="{marker}">'
    res_2 = engine.detect_reflection_context(marker, html_2)
    assert res_2.context == ReflectionContext.ATTRIBUTE_VALUE
    assert '"><b>hnt_canary</b>' in res_2.recommended_safe_escape

    # 3. Script Block Context
    html_3 = f"<script>let user = '{marker}'; console.log(user);</script>"
    res_3 = engine.detect_reflection_context(marker, html_3)
    assert res_3.context == ReflectionContext.SCRIPT_BLOCK
    assert "'-hnt_canary-'" in res_3.recommended_safe_escape

    # 4. Safe Breakout Verification
    escaped_reflected_html = "<input type=\"text\" value=\"\"><b>hnt_canary</b>"
    verified, proof = engine.verify_safe_breakout('"><b>hnt_canary</b>', escaped_reflected_html)
    assert verified is True
    assert "CONFIRMED" in proof
