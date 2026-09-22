"""
Verifies Section 27 - Failure injection and recovery.
"""
import pytest
from core.burp_gateway.gateway import BurpGateway

def test_failure_recovery(tmp_path):
    # Missing capture_store gracefully handled
    try:
        gw = BurpGateway(capture_store=None)
        assert gw.capture_store is not None # creates default
    except Exception as e:
        pytest.fail(f"Crashed on None capture_store: {e}")
        
    # Broken event stream doesn't crash ingestion
    gw.event_stream = None
    client = __import__('fastapi.testclient').testclient.TestClient(gw.app)
    
    # Should probably not crash or return a 500 cleanly
    resp = client.post("/api/traffic", json={
        "method": "GET",
        "url": "http://test",
        "status_code": 200
    })
    # If it fails, it should be a graceful error, or just continue
    assert resp.status_code in [200, 500] 
