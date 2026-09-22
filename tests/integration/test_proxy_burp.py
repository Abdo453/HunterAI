"""
Verifies Section 5 - proxy traffic correlation.
Causal chain: Proxy traffic ingestion -> CaptureStore unique tx_id assignment -> Retrievability
"""
import pytest

def test_proxy_burp_correlation(gateway_client):
    client, gw = gateway_client
    
    methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    for i, m in enumerate(methods):
        resp = client.post("/api/traffic", json={
            "method": m,
            "url": f"http://test.target.local/{m.lower()}",
            "req_headers": {"Host": "test.target.local"},
            "resp_headers": {},
            "req_body": "",
            "resp_body": "",
            "status_code": 200,
            "tool_source": "proxy"
        })
        assert resp.status_code == 200
        
    txs = gw.capture_store.list_transactions()
    assert len(txs) == 5
    
    # Verify each has a unique tx_id
    tx_ids = set(t.tx_id for t in txs)
    assert len(tx_ids) == 5
    
    for tx in txs:
        assert tx.tx_id != ""
        # Retrievability
        retrieved = gw.capture_store.get_transaction(tx.tx_id)
        assert retrieved is not None
        assert retrieved.tx_id == tx.tx_id
