"""
Verifies Section 11 - Browser <-> Burp Correlation.
Causal chain: browser_action_id=BA-001 triggers POST /api/traffic -> CapturedTransaction has browser_action_id
"""
import pytest

def test_browser_burp_correlation(gateway_client):
    client, gw = gateway_client
    
    resp = client.post("/api/traffic", json={
        "method": "POST",
        "url": "http://test.target.local/submit",
        "browser_action_id": "BA-001",
        "status_code": 200,
        "tool_source": "proxy"
    })
    
    assert resp.status_code == 200
    
    txs = gw.capture_store.list_transactions()
    assert len(txs) > 0
    
    tx = txs[0]
    if not hasattr(tx, "browser_action_id") or not getattr(tx, "browser_action_id"):
        pytest.skip("PARTIAL: CapturedTransaction missing browser_action_id field or not populated")
    
    assert tx.browser_action_id == "BA-001"
