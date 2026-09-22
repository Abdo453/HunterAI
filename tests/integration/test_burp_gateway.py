"""
Verifies Section 7 - Gateway as control layer.
Causal chain: Incoming traffic -> Event stream; Agent command -> Task queued; Scope check
"""
import pytest

def test_gateway_control(scoped_gateway_client):
    client, gw = scoped_gateway_client
    
    # Test A: Incoming Observation causes event
    client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://app.target.local/test",
        "status_code": 200,
        "tool_source": "proxy"
    })
    
    events = gw.event_stream.get_recent_events()
    assert len(events) >= 1
    assert any(e.event_type == "REQUEST_INGESTED" for e in events)
    
    # Test B & C: Agent Command creates task and is retrievable
    resp = client.post("/api/tasks", json={
        "action": "SCAN",
        "target_url": "http://app.target.local"
    })
    assert resp.status_code == 200
    task_id = resp.json().get("task_id")
    assert task_id is not None
    
    resp_get = client.get(f"/api/tasks/{task_id}")
    assert resp_get.status_code == 200
    assert resp_get.json().get("task_id") == task_id
    
    # Test D: Scope check
    resp_bad = client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://evil.com/test",
        "status_code": 200,
        "tool_source": "proxy"
    })
    # Might return 403 or 200 with skipped logic depending on implementation, 
    # but the test asks for 403 out-of-scope traffic returns 403
    assert resp_bad.status_code in [403, 400]
