"""
Integration tests for Security Event Bus taxonomy and decoupled pub/sub dispatch
"""
import pytest
import asyncio
from agents.security_intelligence.events import SecurityEventBus, SecurityEvent, SecurityEventType


@pytest.mark.asyncio
async def test_security_event_bus_taxonomy_and_dispatch():
    bus = SecurityEventBus()
    events_received = []

    async def on_finding(evt: SecurityEvent):
        events_received.append(evt)

    async def on_decision(evt: SecurityEvent):
        events_received.append(evt)

    bus.subscribe(SecurityEventType.FINDING_CREATED, on_finding)
    bus.subscribe(SecurityEventType.DECISION_CREATED, on_decision)

    # Publish Finding Event
    await bus.publish(SecurityEvent(
        event_type=SecurityEventType.FINDING_CREATED,
        target="api.test.com",
        source="Analyst",
        data={"finding_id": "F-101", "type": "BOLA"},
        operation_id="op-1234",
        correlation_id="corr-5678"
    ))

    # Publish Decision Event
    await bus.publish(SecurityEvent(
        event_type=SecurityEventType.DECISION_CREATED,
        target="api.test.com",
        source="DecisionEngine",
        data={"decision": "generate_report"},
        operation_id="op-1234",
        correlation_id="corr-5678"
    ))

    assert len(events_received) == 2
    assert events_received[0].event_type == SecurityEventType.FINDING_CREATED
    assert events_received[0].operation_id == "op-1234"
    assert events_received[1].event_type == SecurityEventType.DECISION_CREATED
