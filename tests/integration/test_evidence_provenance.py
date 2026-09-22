"""
Verifies Section 9 - Provenance chain.
Causal chain: Provenance trace created -> stages added -> integrity check
"""
import pytest
from core.burp_gateway.provenance import ProvenanceTrace, ProvenanceStage

def test_evidence_provenance():
    trace = ProvenanceTrace(target="test", vuln_class="XSS")
    
    trace.add_step(ProvenanceStage.OBSERVATION, "obs")
    trace.add_step(ProvenanceStage.BURP_REQUEST, "req")
    trace.add_step(ProvenanceStage.BURP_RESPONSE, "resp")
    trace.add_step(ProvenanceStage.ANALYSIS, "ana")
    trace.add_step(ProvenanceStage.HYPOTHESIS, "hyp")
    trace.add_step(ProvenanceStage.TEST, "test")
    trace.add_step(ProvenanceStage.VERIFICATION, "ver")
    
    valid, errors = trace.verify_integrity()
    assert valid is True
    assert len(errors) == 0
    
    # Missing stage breaks integrity or out of order
    bad_trace = ProvenanceTrace()
    bad_trace.add_step(ProvenanceStage.VERIFICATION, "ver")
    bad_trace.add_step(ProvenanceStage.OBSERVATION, "obs")
    valid_bad, errors_bad = bad_trace.verify_integrity()
    assert valid_bad is False
