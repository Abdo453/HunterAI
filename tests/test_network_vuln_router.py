"""Tests لـ Service→Vuln Router — candidate-only, rule-based."""
from core.network_model import HostGraph, ServiceRecord
from core.network_vuln_router import NetworkVulnRouter


def _svc(port, name=None, protocol="tcp", state="open", product=None, version=None, banner=None):
    return ServiceRecord(host="10.0.0.5", port=port, protocol=protocol, state=state,
                         service_name=name, service_product=product,
                         service_version=version, banner=banner)


def test_redis_maps_to_candidate_exposure():
    router = NetworkVulnRouter()
    findings = router.route_service(_svc(6379, "redis"))
    assert len(findings) == 1
    f = findings[0]
    assert f.vuln_class == "UNAUTHENTICATED_SERVICE"
    assert f.severity == "HIGH"
    assert f.status == "candidate"
    assert f.evidence_level == "E0"
    assert f.confidence < 0.85  # never at confirmation confidence
    assert "redis-cli" in f.reproduction_command


def test_web_services_are_skipped():
    router = NetworkVulnRouter()
    assert router.route_service(_svc(443, "https")) == []
    assert router.route_service(_svc(8080, "http-alt")) == []


def test_closed_service_produces_nothing():
    router = NetworkVulnRouter()
    assert router.route_service(_svc(6379, "redis", state="filtered")) == []


def test_version_rule_vsftpd_backdoor():
    router = NetworkVulnRouter()
    f = router.route_service(_svc(21, "ftp", product="vsftpd", version="2.3.4"))[0]
    assert f.severity == "CRITICAL"
    assert "CVE-2011-2523" in f.title
    assert f.cwe == "CWE-506"


def test_docker_api_is_critical():
    router = NetworkVulnRouter()
    f = router.route_service(_svc(2375, "docker"))[0]
    assert f.severity == "CRITICAL"


def test_route_graph_deduplicates():
    graph = HostGraph()
    graph.add_service(_svc(445, "microsoft-ds"))
    graph.add_service(_svc(6379, "redis"))
    graph.add_service(_svc(22, "ssh"))
    findings = NetworkVulnRouter().route_graph(graph)
    keys = {(f.host, f.port, f.vuln_class) for f in findings}
    assert len(findings) == len(keys)  # no duplicates
    assert all(f.status == "candidate" for f in findings)


def test_reproduction_placeholder_for_database():
    router = NetworkVulnRouter()
    f = router.route_service(_svc(3306, "mysql"))[0]
    assert "--script mysql-info" in f.reproduction_command
