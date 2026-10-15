"""
Tests for the HunterAI Evidence System:
  - EvidenceGraph causal chain
  - HypothesisEngine pattern matching
  - FindingLifecycle state machine
"""
import pytest
from hunter_ai.evidence.evidence_graph import EvidenceGraph, EvidenceNode, EvidenceType
from hunter_ai.evidence.hypothesis_engine import HypothesisEngine, HypothesisStatus
from hunter_ai.evidence.finding_lifecycle import Finding, FindingLifecycle, FindingStatus


# ── EvidenceGraph tests ───────────────────────────────────────────────────────

def test_evidence_graph_chain_order():
    """build_from_request_response creates 4-node chain in root-first order."""
    g = EvidenceGraph()
    resp_id = g.build_from_request_response(
        host="target.com",
        endpoint="/api/users/1",
        method="GET",
        request_body="",
        response_status=200,
        response_body='{"id":1,"email":"a@b.com"}',
        agent="WebAgent",
    )
    chain = g.get_chain(resp_id)
    assert len(chain) == 4
    assert chain[0].node_type == EvidenceType.HOST
    assert chain[1].node_type == EvidenceType.ENDPOINT
    assert chain[2].node_type == EvidenceType.REQUEST
    assert chain[3].node_type == EvidenceType.RESPONSE


def test_evidence_graph_by_type():
    """get_by_type returns only nodes of the requested type."""
    g = EvidenceGraph()
    g.build_from_request_response("a.com", "/x", "GET", "", 200, "ok", "a")
    g.build_from_request_response("b.com", "/y", "POST", "{}", 403, "deny", "b")
    responses = g.get_by_type(EvidenceType.RESPONSE)
    hosts     = g.get_by_type(EvidenceType.HOST)
    assert len(responses) == 2
    assert len(hosts) == 2


def test_evidence_graph_add_observation_and_verdict():
    """Full chain: RESPONSE -> OBSERVATION -> EXPERIMENT -> VERDICT."""
    g = EvidenceGraph()
    resp_id = g.build_from_request_response("t.com", "/api", "GET", "", 200, "data")
    obs_id  = g.add_observation(resp_id, "id param may control object", "WebAgent")
    exp_id  = g.add_experiment(obs_id, "swap user_id A/B", {"status_A": 200, "status_B": 200, "body_delta": 120}, "Verifier")
    vrd_id  = g.add_verdict(exp_id, "CONFIRMED", "Different body for different user_id", 0.94)

    chain = g.get_chain(vrd_id)
    types = [n.node_type for n in chain]
    assert EvidenceType.HOST     in types
    assert EvidenceType.RESPONSE in types
    assert EvidenceType.OBSERVATION in types
    assert EvidenceType.EXPERIMENT  in types
    assert EvidenceType.VERDICT     in types


def test_evidence_graph_summary():
    """summary() returns correct counts per type."""
    g = EvidenceGraph()
    g.build_from_request_response("x.com", "/", "GET", "", 200, "ok")
    s = g.summary()
    assert s["total_nodes"] == 4
    assert s["by_type"]["HOST"] == 1
    assert s["by_type"]["RESPONSE"] == 1


def test_evidence_graph_len():
    g = EvidenceGraph()
    assert len(g) == 0
    g.build_from_request_response("x.com", "/", "GET", "", 200, "ok")
    assert len(g) == 4


# ── HypothesisEngine tests ────────────────────────────────────────────────────

def test_hypothesis_engine_idor_match():
    """Observation with 'id' keyword generates IDOR hypothesis."""
    eng = HypothesisEngine()
    hyps = eng.generate_from_observation(
        observation="The user_id parameter controls which object is returned",
        endpoint="/api/users/{user_id}",
        params=["user_id"],
    )
    assert len(hyps) >= 1
    assert any(h.vuln_type == "IDOR" for h in hyps)


def test_hypothesis_engine_cors_match():
    """Observation with 'cors' keyword generates CORS_MISCONFIGURATION hypothesis."""
    eng = HypothesisEngine()
    hyps = eng.generate_from_observation(
        observation="The CORS origin header is reflected in Access-Control-Allow-Origin",
        endpoint="/api/data",
        params=["origin"],
    )
    assert any(h.vuln_type == "CORS_MISCONFIGURATION" for h in hyps)


def test_hypothesis_engine_no_false_match():
    """Unrelated observation generates zero hypotheses."""
    eng = HypothesisEngine()
    hyps = eng.generate_from_observation(
        observation="The page loads a CSS stylesheet from CDN",
        endpoint="/static/style.css",
        params=["v"],
    )
    assert len(hyps) == 0


def test_hypothesis_engine_deduplication():
    """Same vuln_type + endpoint is not generated twice."""
    eng = HypothesisEngine()
    eng.generate_from_observation("user_id controls object", "/api/users", ["user_id"])
    second = eng.generate_from_observation("id controls object", "/api/users", ["id"])
    # IDOR for /api/users should not be duplicated
    idor_count = sum(1 for h in eng.get_all() if h.vuln_type == "IDOR" and h.endpoint == "/api/users")
    assert idor_count == 1


def test_hypothesis_engine_verdict_flow():
    """ASSIGNED -> TESTING -> CONFIRMED via set_verdict."""
    eng = HypothesisEngine()
    hyps = eng.generate_from_observation("user_id param leaks data", "/api", ["user_id"])
    h = hyps[0]
    eng.update_status(h.hyp_id, HypothesisStatus.TESTING)
    assert eng.get(h.hyp_id).status == HypothesisStatus.TESTING
    eng.set_verdict(h.hyp_id, "CONFIRMED", "Different user data returned", confidence_delta=0.35)
    confirmed = eng.get_confirmed()
    assert any(c.hyp_id == h.hyp_id for c in confirmed)


def test_hypothesis_engine_reject():
    """REJECTED hypothesis not in get_confirmed()."""
    eng = HypothesisEngine()
    hyps = eng.generate_from_observation("sql query in search", "/api/search", ["q"])
    h = hyps[0]
    eng.set_verdict(h.hyp_id, "REJECTED", "Responses identical for both payloads")
    assert len(eng.get_confirmed()) == 0
    assert eng.get(h.hyp_id).status == HypothesisStatus.REJECTED


def test_hypothesis_engine_invalid_verdict():
    """set_verdict with invalid string returns False."""
    eng = HypothesisEngine()
    hyps = eng.generate_from_observation("user_id", "/api", ["user_id"])
    result = eng.set_verdict(hyps[0].hyp_id, "MAYBE", "unsure")
    assert result is False


def test_hypothesis_engine_summary():
    eng = HypothesisEngine()
    eng.generate_from_observation("user_id param", "/api/users", ["user_id"])
    eng.generate_from_observation("cors origin", "/api/data", ["origin"])
    s = eng.summary()
    assert s["total"] == 2
    assert s["confirmed"] == 0


# ── FindingLifecycle tests ────────────────────────────────────────────────────

def test_finding_lifecycle_valid_path():
    """Full happy path: DISCOVERED -> SUSPECTED -> HYPOTHESIS -> TESTING -> EVIDENCE -> VERIFIED."""
    fl = FindingLifecycle()
    f  = fl.create("IDOR on /api/users", severity="HIGH", confidence=0.94)
    assert fl.advance(f.finding_id, FindingStatus.SUSPECTED,          "pattern matched")
    assert fl.advance(f.finding_id, FindingStatus.HYPOTHESIS,         "hypothesis H-004 created")
    assert fl.advance(f.finding_id, FindingStatus.TESTING,            "experiment designed")
    assert fl.advance(f.finding_id, FindingStatus.EVIDENCE_COLLECTED, "2 requests captured")
    assert fl.advance(f.finding_id, FindingStatus.VERIFIED,           "verdict: CONFIRMED 94%")
    assert fl.get(f.finding_id).status == FindingStatus.VERIFIED


def test_finding_lifecycle_invalid_transition():
    """DISCOVERED -> VERIFIED is invalid (skips intermediate states)."""
    fl = FindingLifecycle()
    f  = fl.create("test", severity="INFO")
    result = fl.advance(f.finding_id, FindingStatus.VERIFIED, "skipping steps")
    assert result is False
    assert fl.get(f.finding_id).status == FindingStatus.DISCOVERED


def test_finding_lifecycle_false_positive_terminal():
    """FALSE_POSITIVE is a terminal state — no further transitions allowed."""
    fl = FindingLifecycle()
    f  = fl.create("test")
    fl.advance(f.finding_id, FindingStatus.FALSE_POSITIVE, "confirmed FP")
    result = fl.advance(f.finding_id, FindingStatus.SUSPECTED, "trying to re-open")
    assert result is False
    assert fl.get(f.finding_id).status == FindingStatus.FALSE_POSITIVE


def test_finding_lifecycle_history_recorded():
    """status_history records every transition with reason."""
    fl = FindingLifecycle()
    f  = fl.create("test")
    fl.advance(f.finding_id, FindingStatus.SUSPECTED, "reason-A")
    fl.advance(f.finding_id, FindingStatus.HYPOTHESIS, "reason-B")
    history = fl.get(f.finding_id).status_history
    assert len(history) == 2
    assert history[0]["reason"] == "reason-A"
    assert history[1]["to"] == "HYPOTHESIS"


def test_finding_lifecycle_add_evidence():
    """add_evidence appends evidence node IDs correctly."""
    fl = FindingLifecycle()
    f  = fl.create("test")
    fl.add_evidence(f.finding_id, "E-001")
    fl.add_evidence(f.finding_id, "E-002")
    assert len(fl.get(f.finding_id).evidence_ids) == 2


def test_finding_lifecycle_confirmed_filter():
    """get_confirmed() returns only VERIFIED/REVIEWED/REPORTED findings."""
    fl = FindingLifecycle()
    f1 = fl.create("confirmed finding")
    fl.advance(f1.finding_id, FindingStatus.SUSPECTED)
    fl.advance(f1.finding_id, FindingStatus.HYPOTHESIS)
    fl.advance(f1.finding_id, FindingStatus.TESTING)
    fl.advance(f1.finding_id, FindingStatus.EVIDENCE_COLLECTED)
    fl.advance(f1.finding_id, FindingStatus.VERIFIED)

    f2 = fl.create("false positive")
    fl.advance(f2.finding_id, FindingStatus.FALSE_POSITIVE)

    confirmed = fl.get_confirmed()
    assert len(confirmed) == 1
    assert confirmed[0].finding_id == f1.finding_id


def test_full_evidence_to_finding_chain():
    """Integration: EvidenceGraph + HypothesisEngine + FindingLifecycle work together."""
    # 1. Build evidence
    g = EvidenceGraph()
    resp_id = g.build_from_request_response(
        "target.com", "/api/users/100", "GET", "", 200, '{"id":100,"email":"a@b.com"}'
    )
    obs_id = g.add_observation(resp_id, "user_id controls which object is returned", "WebAgent")

    # 2. Generate hypothesis
    eng  = HypothesisEngine()
    hyps = eng.generate_from_observation("user_id controls which object is returned", "/api/users/100", ["user_id"])
    assert len(hyps) >= 1
    h = hyps[0]

    # 3. Record experiment
    exp_id = g.add_experiment(obs_id, h.experiment_plan, {"status_A": 200, "status_B": 200, "body_delta": 180})
    eng.update_status(h.hyp_id, HypothesisStatus.TESTING, exp_id)

    # 4. Set verdict
    vrd_id = g.add_verdict(exp_id, "CONFIRMED", "Different user data returned for different IDs", 0.94)
    eng.set_verdict(h.hyp_id, "CONFIRMED", "Different user data returned for different IDs", confidence_delta=0.39)

    # 5. Create finding
    fl = FindingLifecycle()
    f  = fl.create("IDOR on /api/users/{id}", hypothesis_id=h.hyp_id, severity="HIGH", confidence=h.confidence, endpoint="/api/users/100")
    fl.add_evidence(f.finding_id, vrd_id)

    # Advance to VERIFIED
    for status in (FindingStatus.SUSPECTED, FindingStatus.HYPOTHESIS,
                   FindingStatus.TESTING, FindingStatus.EVIDENCE_COLLECTED, FindingStatus.VERIFIED):
        fl.advance(f.finding_id, status, "automated")

    # Verify everything
    assert fl.get(f.finding_id).status == FindingStatus.VERIFIED
    assert eng.get_confirmed()[0].hyp_id == h.hyp_id
    chain = g.get_chain(vrd_id)
    assert chain[0].node_type == EvidenceType.HOST
    assert chain[-1].node_type == EvidenceType.VERDICT
