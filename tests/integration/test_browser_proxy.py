"""
Verifies Section 4 of the test plan - browser generates requests that reach the proxy.
Causal chain: Simulated browser action -> Gateway /api/traffic -> CaptureStore verification
"""
import pytest
import json

def test_browser_proxy_capture(gateway_client):
    client, gw = gateway_client
    
    # Simulate GET
    resp = client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://test.target.local/api/users?id=1",
        "req_headers": {"Host": "test.target.local", "User-Agent": "Mozilla/5.0"},
        "resp_headers": {"Content-Type": "application/json"},
        "req_body": "",
        "resp_body": '{"id": 1}',
        "status_code": 200,
        "tool_source": "proxy"
    })
    assert resp.status_code == 200
    
    # Simulate POST with JSON
    resp = client.post("/api/traffic", json={
        "method": "POST",
        "url": "http://test.target.local/api/users",
        "req_headers": {"Host": "test.target.local", "Cookie": "session=abc"},
        "resp_headers": {"Set-Cookie": "session=def"},
        "req_body": '{"name": "test"}',
        "resp_body": '{"id": 2}',
        "status_code": 201,
        "tool_source": "proxy"
    })
    assert resp.status_code == 200

    txs = gw.capture_store.list_transactions()
    assert len(txs) == 2
    
    get_tx = next(t for t in txs if t.method == "GET")
    assert get_tx.url == "http://test.target.local/api/users?id=1"
    
    post_tx = next(t for t in txs if t.method == "POST")
    assert post_tx.cookies.get("session") in ["abc", "def"] # Check cookie parsing
