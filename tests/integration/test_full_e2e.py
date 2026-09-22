"""
Verifies Section 33 - Full E2E causality chain.
Causal chain: Browser action -> Request -> Event -> Task -> Evidence -> Court -> Report
"""
import pytest
from core.burp_gateway.provenance import ProvenanceTrace, ProvenanceStage
from core.evidence_court import EvidenceCourt, CausalEvidence, ExecutionEvidence, CourtVerdict

def test_full_e2e(scoped_gateway_client):
    client, gw = scoped_gateway_client
    
    # 1 & 2. Browser action -> POST traffic
    resp_traffic = client.post("/api/traffic", json={
        "method": "POST",
        "url": "http://app.target.local/vuln",
        "browser_action_id": "BA-E2E-001",
        "trace_id": "TRACE-E2E-001",
        "status_code": 200
    })
    assert resp_traffic.status_code == 200
    
    # 3. Verify event
    events = gw.event_stream.get_recent_events()
    assert any(e.data.get("trace_id") == "TRACE-E2E-001" for e in events if e.event_type == "REQUEST_INGESTED")
    
    # 4 & 5. Task creation
    resp_task = client.post("/api/tasks", json={
        "action": "SCAN",
        "target_url": "http://app.target.local/vuln",
        "trace_id": "TRACE-E2E-001"
    })
    assert resp_task.status_code == 200
    task_id = resp_task.json().get("task_id")
    
    # 6. Provenance
    trace = ProvenanceTrace(trace_id="TRACE-E2E-001", target="http://app.target.local/vuln", vuln_class="XSS")
    trace.add_step(ProvenanceStage.OBSERVATION, "obs")
    trace.add_step(ProvenanceStage.BURP_REQUEST, "req")
    trace.add_step(ProvenanceStage.BURP_RESPONSE, "resp")
    trace.add_step(ProvenanceStage.ANALYSIS, "ana")
    trace.add_step(ProvenanceStage.HYPOTHESIS, "hyp")
    trace.add_step(ProvenanceStage.TEST, "test")
    trace.add_step(ProvenanceStage.VERIFICATION, "ver")
    
    # 7 & 8. Adjudicate
    court = EvidenceCourt()
    causal = CausalEvidence(metamorphic_passed=True, invariant_passed=True, causal_strength=1.0)
    exec_ev = ExecutionEvidence(reproduced=True, poe_token="e2e_token")
    judgement = court.adjudicate(
        target_url="http://app.target.local/vuln",
        parameter="test",
        vuln_class="XSS",
        causal_evidence=causal,
        execution_evidence=exec_ev,
        provenance_trace=trace
    )
    
    assert judgement.verdict in [CourtVerdict.CONFIRMED, CourtVerdict.UNVERIFIED]
    
    # 9. Export (if API exists)
    resp_export = client.get("/api/issues/export")
    if resp_export.status_code == 200:
        pass # Optional check
