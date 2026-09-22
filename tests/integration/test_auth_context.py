"""
Verifies Section 17 - Authentication Context.
Causal chain: Auth header/cookies in traffic -> Auth context tracked
"""
import pytest

def test_auth_context(gateway_client):
    client, gw = gateway_client
    
    # Bearer
    client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://test.target.local/auth1",
        "req_headers": {"Authorization": "Bearer token123"},
        "status_code": 200
    })
    
    # Set-Cookie
    client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://test.target.local/auth2",
        "resp_headers": {"Set-Cookie": "sess=abc; Path=/"},
        "status_code": 200
    })
    
    # CSRF Token
    client.post("/api/traffic", json={
        "method": "POST",
        "url": "http://test.target.local/auth3",
        "req_body": "csrf_token=xyz123&data=test",
        "status_code": 200
    })
    
    txs = gw.capture_store.list_transactions()
    
    bearer_tx = next(t for t in txs if t.url.endswith("auth1"))
    assert bearer_tx.req_headers.get("Authorization") == "Bearer token123"
    
    cookie_tx = next(t for t in txs if t.url.endswith("auth2"))
    assert "sess" in cookie_tx.cookies
    
    csrf_tx = next(t for t in txs if t.url.endswith("auth3"))
    assert "csrf_token=xyz123" in csrf_tx.req_body
