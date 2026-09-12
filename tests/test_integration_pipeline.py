"""
End-to-End Integration Test for BurpAgent, EventBus, SecurityIntelligenceAdapter, and AutonomousBrain
Tests the complete real event-driven nervous system of HunterAI.
"""
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock

from agents.burp_agent.pipeline.event_bus import BurpEvent, EventBus
from agents.burp_agent.storage.models import HTTPRequestModel, HTTPResponseModel
from agents.security_intelligence.brain import SecurityIntelligence
from agents.security_intelligence.schemas import (
    ScopeRule,
    ScopeMode,
    ActionPriority,
    IntelligenceFinding,
    SecurityDecision
)
from core.integration.security_intelligence_adapter import SecurityIntelligenceAdapter
from core.brain.autonomous_brain import AutonomousBrain


@pytest.mark.asyncio
async def test_full_burp_to_intelligence_pipeline():
    # 1. Setup shared EventBus and SecurityIntelligence
    event_bus = EventBus()
    si = SecurityIntelligence()
    si.set_scope(ScopeRule(target="api.payments.local", allowed_domains=["api.payments.local"]))

    decisions_received = []
    findings_received = []

    async def on_decision(dec: SecurityDecision):
        decisions_received.append(dec)

    async def on_finding(fnd: IntelligenceFinding):
        findings_received.append(fnd)

    # 2. Attach Adapter to EventBus
    adapter = SecurityIntelligenceAdapter(
        security_intelligence=si,
        event_bus=event_bus,
        on_decision_callback=on_decision,
        on_finding_callback=on_finding
    )

    # 3. Simulate Burp Ingestion Pipeline publishing TRAFFIC_STORED with behavioral diff
    req = HTTPRequestModel(
        id="req-9901",
        method="GET",
        url="https://api.payments.local/api/v1/invoices/9412",
        path="/api/v1/invoices/9412",
        host="api.payments.local",
        port=443,
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
        body=""
    )
    resp = HTTPResponseModel(
        id="resp-9901",
        request_id="req-9901",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"invoice_id": 9412, "customer": "Alice", "amount": 540.00}',
        response_time_ms=45.0
    )


    # Publish Burp Traffic Stored Event
    await event_bus.publish(BurpEvent.TRAFFIC_STORED, {
        "request": req,
        "response": resp,
        "behavior_difference": "User Bob accessed User Alice invoice with 200 OK"
    })

    # 4. Verify that findings and decisions flowed through the entire pipeline
    assert len(findings_received) > 0
    f = findings_received[0]
    assert f.vulnerability_type == "BOLA"
    assert f.confidence_score >= 0.60
    assert len(f.evidence) > 0
    assert f.provenance is not None

    assert len(decisions_received) > 0
    dec = decisions_received[0]
    assert dec.target == "api.payments.local"
    assert dec.action_priority in [ActionPriority.IMMEDIATE, ActionPriority.HIGH]
    assert len(dec.rationale) > 0

    # 5. Verify that Teacher can immediately generate a pedagogical lesson
    lesson = await si.teach_from_finding(f)
    assert lesson.topic == f.title
    assert "المستوى 1" in lesson.explanations["simple"]


@pytest.mark.asyncio
async def test_adapter_lightweight_filtering():
    """Verify that static asset traffic is filtered out and does not trigger cognitive AI pipeline"""
    event_bus = EventBus()
    si = SecurityIntelligence()
    
    findings_received = []
    async def on_finding(fnd: IntelligenceFinding):
        findings_received.append(fnd)

    adapter = SecurityIntelligenceAdapter(
        security_intelligence=si,
        event_bus=event_bus,
        on_finding_callback=on_finding
    )

    # Simulate static asset (PNG image)
    req = HTTPRequestModel(
        id="req-static",
        method="GET",
        url="https://api.payments.local/static/images/logo.png",
        path="/static/images/logo.png",
        host="api.payments.local",
        port=443,
        headers={},
        body=""
    )
    resp = HTTPResponseModel(
        id="resp-static",
        request_id="req-static",
        status_code=200,
        headers={"Content-Type": "image/png"},
        body="",
        response_time_ms=10.0
    )


    await event_bus.publish(BurpEvent.TRAFFIC_STORED, {"request": req, "response": resp})
    
    # Should be ignored by lightweight filter
    assert len(findings_received) == 0


@pytest.mark.asyncio
async def test_autonomous_brain_defense_in_depth_scope():
    """Verify Defense-in-Depth scope blocking inside AutonomousBrain._execute_tool"""
    rm = MagicMock()
    tm = MagicMock()
    tm.is_available.return_value = True

    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=False)
    
    # Set strict scope on SecurityIntelligence inside AutonomousBrain
    brain.security_intelligence.set_scope(ScopeRule(
        target="authorized.local",
        allowed_domains=["authorized.local"],
        allow_active_tests=True
    ))

    # 1. Attempt to execute tool against unauthorized target
    res_blocked = await brain._execute_tool("SmartPoC", target="https://evil-unauthorized.com/test", params=["id"], focus="sqli", proxy="", auth={})
    assert res_blocked == []

    # Verify audit log contains scope block
    blocked_audit = [a for a in brain._audit_log if a.get("event") == "tool_scope_blocked"]
    assert len(blocked_audit) > 0
    assert blocked_audit[0]["target"] == "https://evil-unauthorized.com/test"


@pytest.mark.asyncio
async def test_adapter_action_loop_protection():
    """Verify that repeated decisions on the same target and action are halted after max_action_repeat"""
    event_bus = EventBus()
    si = SecurityIntelligence()
    si.set_scope(ScopeRule(target="api.payments.local", allowed_domains=["api.payments.local"]))

    decisions_published = []
    async def on_decision(dec):
        decisions_published.append(dec)

    adapter = SecurityIntelligenceAdapter(
        security_intelligence=si,
        event_bus=event_bus,
        on_decision_callback=on_decision
    )
    adapter.max_action_repeat = 2  # limit to 2

    # Simulate 4 identical requests to the same target/endpoint
    for i in range(4):
        req = HTTPRequestModel(
            id=f"req-loop-{i}",
            method="GET",
            url="https://api.payments.local/api/v1/invoices/100",
            path="/api/v1/invoices/100",
            host="api.payments.local",
            headers={"Authorization": "Bearer token"},
            body=""
        )
        resp = HTTPResponseModel(
            id=f"resp-loop-{i}",
            request_id=f"req-loop-{i}",
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"invoice": 1}'
        )
        await event_bus.publish(BurpEvent.TRAFFIC_STORED, {
            "request": req,
            "response": resp,
            "behavior_difference": "User Bob accessed User Alice invoice with 200 OK"
        })

    # Total published decisions must be capped at max_action_repeat (2) instead of 4
    assert len(decisions_published) == 2


@pytest.mark.asyncio
async def test_internal_bus_to_burp_bus_bridge():
    """Verify that internal SecurityEventBus events are bridged to outer Burp EventBus"""
    outer_bus = EventBus()
    si = SecurityIntelligence()

    bridged_findings = []
    async def on_outer_finding(data):
        bridged_findings.append(data)

    outer_bus.subscribe(BurpEvent.FINDING_CREATED, on_outer_finding)

    # Initialize adapter with bridge enabled
    adapter = SecurityIntelligenceAdapter(
        security_intelligence=si,
        event_bus=outer_bus
    )

    # Trigger internal event on si.bus
    from agents.security_intelligence.events import SecurityEvent, SecurityEventType
    await si.bus.publish(SecurityEvent(
        event_type=SecurityEventType.FINDING_CREATED,
        target="api.test.local",
        source="internal_analyst",
        data={"finding_id": "FIND-999", "title": "BOLA Detected", "type": "BOLA"},
        confidence=0.88
    ))

    # Verify bridged event was received on outer Burp EventBus
    assert len(bridged_findings) > 0
    assert bridged_findings[0]["finding_id"] == "FIND-999"
    assert bridged_findings[0]["source"] == "SecurityIntelligence.internal"


@pytest.mark.asyncio
async def test_autonomous_brain_orient_integration():
    """Verify that AutonomousBrain OODA ORIENT phase consults SecurityIntelligence and forms hypotheses"""
    rm = MagicMock()
    tm = MagicMock()
    tm.is_available.return_value = True

    brain = AutonomousBrain(resource_manager=rm, tool_manager=tm, dry_run=True)
    brain._fetch_target = AsyncMock(return_value=(
        "<html><a href='/api/v1/invoices/999'>Invoice</a></html>",
        200,
        {"server": "nginx"}
    ))
    brain._check_burp_online = AsyncMock(return_value=False)

    res = await brain.run_scan(target="https://target.local", mode="auto")

    # Check that audit log contains security_intelligence_oriented event
    orient_audit = [a for a in brain._audit_log if a.get("event") == "security_intelligence_oriented"]
    assert len(orient_audit) > 0
    assert "hypotheses" in orient_audit[0]
    assert len(orient_audit[0]["hypotheses"]) > 0


