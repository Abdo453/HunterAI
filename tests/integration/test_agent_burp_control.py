"""
Verifies Section 13 - Reverse path: Agent -> Gateway -> Burp -> Target.
Causal chain: POST /api/tasks -> task created -> GET /api/tasks/{task_id} -> Out of scope rejected
"""
import pytest

def test_agent_burp_control(scoped_gateway_client):
    client, gw = scoped_gateway_client
    
    # In-scope target
    resp = client.post("/api/tasks", json={
        "action": "SCAN",
        "target_url": "http://app.target.local"
    })
    assert resp.status_code == 200
    task_id = resp.json().get("task_id")
    
    resp_get = client.get(f"/api/tasks/{task_id}")
    assert resp_get.status_code == 200
    data = resp_get.json()
    assert data["task_id"] == task_id
    assert data["action"] == "SCAN"
    assert data["target_url"] == "http://app.target.local"
    assert data["status"] == "QUEUED"
    assert "timestamp" in data
    
    # Out-of-scope target
    resp_out = client.post("/api/tasks", json={
        "action": "SCAN",
        "target_url": "http://evil.com"
    })
    assert resp_out.status_code == 403
    assert "REJECTED_OUT_OF_SCOPE" in resp_out.text or resp_out.json().get("detail", "")
