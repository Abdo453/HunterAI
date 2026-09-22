"""
Verifies Section 14 - Scope and Safety.
Causal chain: In-scope traffic allowed, out-of-scope traffic denied.
"""
import pytest

def test_scope_policy(scoped_gateway_client):
    client, gw = scoped_gateway_client
    
    # In-scope
    resp_in = client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://app.target.local/ok",
        "status_code": 200
    })
    assert resp_in.status_code == 200
    
    # Out-of-scope
    resp_out = client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://evil.com/bad",
        "status_code": 200
    })
    assert resp_out.status_code == 403
    
    # Task Out-of-scope
    resp_task = client.post("/api/tasks", json={
        "action": "SCAN",
        "target_url": "http://evil.com"
    })
    assert resp_task.status_code == 403
    
    # Scope update
    gw.set_scope(include=["evil.com"])
    resp_update = client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://evil.com/now_ok",
        "status_code": 200
    })
    assert resp_update.status_code == 200
