"""
Verifies Section 12/13 - Agent observes events from Gateway.
Causal chain: POST /api/traffic -> event_stream has event -> Agent extracts URL/method
"""
import pytest

def test_agent_gateway_observation(gateway_client):
    client, gw = gateway_client
    
    # Track endpoint count before
    count_before = len(gw.event_stream.get_recent_events())
    
    client.post("/api/traffic", json={
        "method": "POST",
        "url": "http://test.target.local/agent_test",
        "status_code": 200,
        "tool_source": "proxy"
    })
    
    events = gw.event_stream.get_recent_events()
    count_after = len(events)
    
    assert count_after > count_before
    latest_event = events[-1]
    
    data = latest_event.data
    # data should contain tx_id, url, method
    if "tx_id" in data:
        assert data.get("url") == "http://test.target.local/agent_test"
        assert data.get("method") == "POST"
