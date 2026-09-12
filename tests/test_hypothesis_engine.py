"""
Unit Tests for HypothesisEngine — Heuristic Hypothesis Generation
Tests: BOLA, BFLA, SQLi, SSRF, Mass Assignment, Info Disclosure, edge cases
"""
import pytest
from agents.security_intelligence.hypothesis_engine import HypothesisEngine
from agents.security_intelligence.schemas import SecurityObservation, ObservationType


def _make_obs(path="/api/test", method="GET", params=None, headers=None, body="", endpoints=None):
    data = {
        "path": path,
        "url": f"https://target.local{path}",
        "method": method,
        "parameters": params or [],
        "headers": headers or {},
        "body": body,
    }
    if endpoints:
        data["endpoints"] = endpoints
    return SecurityObservation(
        target="target.local",
        obs_type=ObservationType.HTTP_REQUEST,
        data=data
    )


class TestBOLAHypothesis:
    """BOLA/IDOR hypothesis generation"""

    def test_numeric_id_in_path_triggers_bola(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/users/12345")
        hyps = engine.generate_hypotheses(obs)
        bola = [h for h in hyps if h.vulnerability_type == "BOLA"]
        assert len(bola) >= 1
        assert bola[0].cwe_id == "CWE-639"
        assert bola[0].confidence >= 0.60

    def test_uuid_in_path_triggers_bola(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/invoices/a1b2c3d4-e5f6-7890-abcd-ef1234567890")
        hyps = engine.generate_hypotheses(obs)
        bola = [h for h in hyps if h.vulnerability_type == "BOLA"]
        assert len(bola) >= 1

    def test_id_in_params_triggers_bola(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/data", params=["user_id", "format"])
        hyps = engine.generate_hypotheses(obs)
        bola = [h for h in hyps if h.vulnerability_type == "BOLA"]
        assert len(bola) >= 1

    def test_no_id_pattern_no_bola(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/health", params=["verbose"])
        hyps = engine.generate_hypotheses(obs)
        bola = [h for h in hyps if h.vulnerability_type == "BOLA"]
        assert len(bola) == 0

    def test_bola_from_discovered_endpoints(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/health", endpoints=["/api/orders/999"])
        hyps = engine.generate_hypotheses(obs)
        bola = [h for h in hyps if h.vulnerability_type == "BOLA"]
        assert len(bola) >= 1


class TestBFLAHypothesis:
    """Broken Function Level Authorization hypothesis"""

    def test_admin_path_triggers_bfla(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/admin/users/manage")
        hyps = engine.generate_hypotheses(obs)
        bfla = [h for h in hyps if h.vulnerability_type == "BFLA"]
        assert len(bfla) >= 1
        assert bfla[0].cwe_id == "CWE-285"

    def test_dashboard_path_triggers_bfla(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/internal/dashboard/stats")
        hyps = engine.generate_hypotheses(obs)
        bfla = [h for h in hyps if h.vulnerability_type == "BFLA"]
        assert len(bfla) >= 1

    def test_regular_path_no_bfla(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/public/feed")
        hyps = engine.generate_hypotheses(obs)
        bfla = [h for h in hyps if h.vulnerability_type == "BFLA"]
        assert len(bfla) == 0


class TestSQLiHypothesis:
    """SQL Injection hypothesis generation"""

    def test_search_param_triggers_sqli(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/search", params=["query", "page"])
        hyps = engine.generate_hypotheses(obs)
        sqli = [h for h in hyps if h.vulnerability_type == "SQLi"]
        assert len(sqli) >= 1
        assert sqli[0].cwe_id == "CWE-89"

    def test_filter_param_triggers_sqli(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/data", params=["filter", "sort"])
        hyps = engine.generate_hypotheses(obs)
        sqli = [h for h in hyps if h.vulnerability_type == "SQLi"]
        assert len(sqli) >= 1

    def test_no_sql_indicators_no_sqli(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/images/upload", params=["format", "size"])
        hyps = engine.generate_hypotheses(obs)
        sqli = [h for h in hyps if h.vulnerability_type == "SQLi"]
        assert len(sqli) == 0


class TestSSRFHypothesis:
    """Server-Side Request Forgery hypothesis"""

    def test_url_param_triggers_ssrf(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/fetch", params=["url", "format"])
        hyps = engine.generate_hypotheses(obs)
        ssrf = [h for h in hyps if h.vulnerability_type == "SSRF"]
        assert len(ssrf) >= 1
        assert ssrf[0].cwe_id == "CWE-918"

    def test_webhook_param_triggers_ssrf(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/notifications", params=["webhook", "event"])
        hyps = engine.generate_hypotheses(obs)
        ssrf = [h for h in hyps if h.vulnerability_type == "SSRF"]
        assert len(ssrf) >= 1

    def test_no_url_params_no_ssrf(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/users", params=["name", "email"])
        hyps = engine.generate_hypotheses(obs)
        ssrf = [h for h in hyps if h.vulnerability_type == "SSRF"]
        assert len(ssrf) == 0


class TestMassAssignmentHypothesis:
    """Mass Assignment / Property Injection hypothesis"""

    def test_json_api_post_triggers_mass_assignment(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/users", method="POST",
                        headers={"content-type": "application/json"},
                        params=["name", "email"])
        hyps = engine.generate_hypotheses(obs)
        ma = [h for h in hyps if h.vulnerability_type == "Mass_Assignment"]
        assert len(ma) >= 1
        assert ma[0].cwe_id == "CWE-915"

    def test_put_to_api_triggers_mass_assignment(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/profile", method="PUT",
                        headers={"content-type": "application/json"})
        hyps = engine.generate_hypotheses(obs)
        ma = [h for h in hyps if h.vulnerability_type == "Mass_Assignment"]
        assert len(ma) >= 1

    def test_get_request_no_mass_assignment(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/api/users", method="GET")
        hyps = engine.generate_hypotheses(obs)
        ma = [h for h in hyps if h.vulnerability_type == "Mass_Assignment"]
        assert len(ma) == 0


class TestFallbackHypothesis:
    """When no specific pattern matches, fallback to Info_Disclosure"""

    def test_generic_endpoint_gets_info_disclosure(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/static/logo.svg", method="GET")
        hyps = engine.generate_hypotheses(obs)
        assert len(hyps) >= 1
        assert hyps[0].vulnerability_type == "Info_Disclosure"

    def test_hypotheses_sorted_by_confidence_descending(self):
        engine = HypothesisEngine()
        obs = _make_obs(path="/admin/users/123", method="POST",
                        params=["user_id", "query", "url"],
                        headers={"content-type": "application/json"})
        hyps = engine.generate_hypotheses(obs)
        assert len(hyps) >= 3
        for i in range(len(hyps) - 1):
            assert hyps[i].confidence >= hyps[i + 1].confidence
