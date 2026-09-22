"""
Verifies Section 16 - Request/Response isolation under concurrency.
Causal chain: Concurrent requests -> Unique TX IDs -> No cross-contamination
"""
import pytest
import asyncio

@pytest.mark.asyncio
async def test_request_response_correlation(gateway_client):
    client, gw = gateway_client
    
    import httpx
    
    async with httpx.AsyncClient(app=gw.app, base_url="http://test") as ac:
        reqs = []
        for i in range(3):
            reqs.append(ac.post("/api/traffic", json={
                "method": "GET",
                "url": f"http://test.target.local/{i}",
                "resp_body": f"body_{i}",
                "status_code": 200
            }))
        
        responses = await asyncio.gather(*reqs)
        
    for r in responses:
        assert r.status_code == 200
        
    txs = gw.capture_store.list_transactions()
    assert len(txs) == 3
    
    bodies = {t.resp_body for t in txs}
    assert bodies == {"body_0", "body_1", "body_2"}
    
    for tx in txs:
        retrieved = gw.capture_store.get_transaction(tx.tx_id)
        assert retrieved.resp_body == tx.resp_body
