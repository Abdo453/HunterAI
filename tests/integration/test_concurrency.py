"""
Verifies Section 29 - Concurrency.
Causal chain: concurrent requests -> distinct tx_ids, no collision.
"""
import pytest
import asyncio

@pytest.mark.asyncio
async def test_concurrency(gateway_client):
    client, gw = gateway_client
    import httpx
    
    async with httpx.AsyncClient(app=gw.app, base_url="http://test") as ac:
        reqs = []
        for i in range(10):
            reqs.append(ac.post("/api/traffic", json={
                "method": "GET",
                "url": f"http://test.target.local/{i}",
                "status_code": 200
            }))
            
        resps = await asyncio.gather(*reqs)
        
    for r in resps:
        assert r.status_code == 200
        
    txs = gw.capture_store.list_transactions()
    assert len(txs) == 10
    
    tx_ids = set(t.tx_id for t in txs)
    assert len(tx_ids) == 10
    
    events = [e for e in gw.event_stream.get_recent_events() if e.event_type == "REQUEST_INGESTED"]
    assert len(events) == 10
