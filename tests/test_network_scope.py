"""Phase 0 — Network Scope Firewall & Network Data Model acceptance tests.

Covers:
  * fail-closed defaults for network endpoints (protocol/port/host),
  * the independent ``allow_active_network_tests`` opt-in gate,
  * inviolable invariants (cloud metadata / RFC1918) on non-HTTP protocols,
  * audit trail + ScopeViolationError on denial,
  * the unified Host/Service/ProtocolTrace/NetworkFinding model + HostGraph.

The test session forces GOVERNED mode (``HUNTER_UNRESTRICTED=0``) via conftest,
so the fail-closed paths are exercised by default.
"""
from __future__ import annotations

import pytest

from core.network_scope_guard import NetworkScopeGuard, ScopeViolationError
from core.network_scope_policy import NetworkScopePolicy
from core.network_model import (
    HostGraph,
    HostRecord,
    NetworkFinding,
    ProtocolTrace,
    ServiceRecord,
    ServiceState,
)
from core.scope_engine import ScopePolicy


def _open_network_policy(**overrides) -> NetworkScopePolicy:
    """A deliberately permissive policy used only to isolate a single gate."""
    base = dict(
        allowed_targets=["lab.target.local"],
        allowed_protocols=["tcp", "smb", "ldap", "kerberos"],
        allow_active_network_tests=True,
        allowed_ports=[],
        fail_closed=True,
    )
    base.update(overrides)
    return NetworkScopePolicy(**base)


# ── Scope firewall ───────────────────────────────────────────────────────────

def test_network_guard_default_endpoint_is_fail_closed():
    allowed, _ = NetworkScopeGuard().check_endpoint("example.com", 443, "https")
    assert allowed is False


def test_network_guard_default_url_is_fail_closed():
    assert NetworkScopeGuard().check_url("https://example.com/")[0] is False


def test_network_guard_blocks_non_http_protocol_by_default():
    guard = NetworkScopeGuard(ScopePolicy(allowed_targets=["lab.target.local"]))
    allowed, reason = guard.check_endpoint("lab.target.local", 445, "smb")
    assert allowed is False
    assert "protocol allowlist" in reason


def test_network_guard_requires_active_testing_opt_in():
    policy = _open_network_policy(allow_active_network_tests=False)
    guard = NetworkScopeGuard(network_policy=policy)
    allowed, reason = guard.check_endpoint("lab.target.local", 445, "smb")
    assert allowed is False
    assert "Active network testing is disabled" in reason


def test_network_guard_allows_authorized_endpoint():
    policy = _open_network_policy(allowed_ports=[445, 139])
    guard = NetworkScopeGuard(network_policy=policy)
    allowed, reason = guard.check_endpoint("lab.target.local", 445, "smb")
    assert allowed is True, reason


def test_network_guard_blocks_excluded_relay_port():
    policy = _open_network_policy(allowed_ports=[25], allowed_protocols=["tcp"])
    guard = NetworkScopeGuard(network_policy=policy)
    allowed, reason = guard.check_endpoint("lab.target.local", 25, "tcp")
    assert allowed is False
    assert "excluded port" in reason.lower()


def test_network_guard_blocks_port_outside_allowlist():
    policy = _open_network_policy(allowed_ports=[445])
    guard = NetworkScopeGuard(network_policy=policy)
    allowed, reason = guard.check_endpoint("lab.target.local", 3389, "smb")
    assert allowed is False
    assert "port policy" in reason


def test_network_guard_blocks_cloud_metadata_even_with_allowlist_and_lab():
    policy = NetworkScopePolicy(
        allowed_targets=["169.254.169.254"],
        allowed_protocols=["tcp"],
        allow_active_network_tests=True,
        allow_private_ips_override=True,
    )
    guard = NetworkScopeGuard(network_policy=policy)
    allowed, reason = guard.check_endpoint("169.254.169.254", 80, "tcp")
    assert allowed is False
    assert "INVARIANT" in reason


def test_network_guard_blocks_rfc1918_without_lab_override():
    policy = _open_network_policy(allowed_targets=["10.0.0.0/8"], allowed_ports=[22])
    guard = NetworkScopeGuard(network_policy=policy)
    allowed, reason = guard.check_endpoint("10.0.0.5", 22, "tcp")
    assert allowed is False
    assert "INVARIANT" in reason


def test_network_guard_allows_rfc1918_in_lab_mode():
    policy = _open_network_policy(
        allowed_targets=["10.0.0.0/8"],
        allowed_ports=[22],
        allow_private_ips_override=True,
    )
    guard = NetworkScopeGuard(network_policy=policy)
    allowed, reason = guard.check_endpoint("10.0.0.5", 22, "tcp")
    assert allowed is True, reason


def test_assert_endpoint_allowed_audits_and_raises():
    guard = NetworkScopeGuard()  # fail-closed
    with pytest.raises(ScopeViolationError) as exc:
        guard.assert_endpoint_allowed("lab.target.local", 445, "smb", caller_context="test")
    assert "lab.target.local" in str(exc.value)
    assert len(guard.blocked_audit_log) == 1
    entry = guard.blocked_audit_log[0]
    assert entry["event_type"] == "NETWORK_EGRESS_BLOCKED"
    assert entry["protocol"] == "smb"
    assert entry["port"] == 445


def test_check_ports_splits_allowed_and_denied():
    policy = _open_network_policy(allowed_ports=[445])
    guard = NetworkScopeGuard(network_policy=policy)
    allowed, denied = guard.check_ports("lab.target.local", [445, 3389], protocol="tcp")
    assert allowed == [445]
    assert [p for p, _ in denied] == [3389]


def test_network_guard_unrestricted_mode_allows_endpoint(monkeypatch):
    monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
    guard = NetworkScopeGuard()
    allowed, _ = guard.check_endpoint("203.0.113.9", 445, "smb")
    assert allowed is True


def test_backward_compat_check_url_and_redirect():
    guard = NetworkScopeGuard(ScopePolicy(allowed_targets=["target.com"]))
    assert guard.check_url("https://target.com/api")[0] is True
    allowed, reason = guard.check_url("file:///etc/passwd")
    assert allowed is False
    assert "Disallowed protocol scheme" in reason
    # Redirect to out-of-scope destination is blocked.
    assert guard.check_redirect("https://target.com/login", "https://evil.com/x")[0] is False


def test_network_policy_from_scope_policy_keeps_http_only():
    derived = NetworkScopePolicy.from_scope_policy(
        ScopePolicy(allowed_targets=["target.com"], allow_private_ips_override=True)
    )
    assert derived.allowed_targets == ["target.com"]
    assert derived.allow_private_ips_override is True
    assert derived.is_protocol_allowed("https") is True
    assert derived.is_protocol_allowed("smb") is False
    assert derived.allow_active_network_tests is False


def test_network_policy_port_ranges():
    policy = NetworkScopePolicy(allowed_port_ranges=["1-1024"])
    assert policy.is_port_allowed(22) is True
    assert policy.is_port_allowed(1024) is True
    assert policy.is_port_allowed(3306) is False
    assert policy.is_port_allowed(587) is False  # excluded relay port always wins


# ── Network data model ───────────────────────────────────────────────────────

def test_service_record_from_nmap_record():
    from core.nmap.schemas import NmapPortRecord

    nmap = NmapPortRecord(
        record_id="",
        host="10.0.0.5",
        port=445,
        protocol="tcp",
        state="open",
        service_name="microsoft-ds",
        service_product="Samba",
        service_version="4.15",
        banner="SMB 4.15",
        confidence="confirmed",
        evidence_level="E1",
    )
    svc = ServiceRecord.from_nmap_record(nmap)
    assert svc.canonical_key == "tcp://10.0.0.5:445"
    assert svc.service_name == "microsoft-ds"
    assert svc.is_high_value is True
    assert svc.record_id.startswith("svc_")


def test_host_graph_add_and_query():
    graph = HostGraph()
    host = graph.upsert_host("dc01.lab.local", address="10.0.0.10", source_tool="nmap")
    graph.add_service(ServiceRecord(host="dc01.lab.local", port=445, service_name="microsoft-ds"))
    graph.add_service(ServiceRecord(host="dc01.lab.local", port=389, service_name="ldap"))
    graph.add_service(ServiceRecord(host="dc01.lab.local", port=3389, service_name="ms-wbt-server",
                                    state=ServiceState.FILTERED))

    assert graph.get_host("10.0.0.10") is host
    assert host.open_ports == [389, 445]
    assert [h.host for h in graph.hosts_with_service("ldap")] == ["dc01.lab.local"]
    assert len(graph.high_value_services()) == 2
    assert graph.summary()["hosts"] == 1
    assert graph.summary()["open_services"] == 2


def test_host_graph_round_trip_and_evidence_nodes():
    graph = HostGraph()
    graph.upsert_host("web.lab.local")
    graph.add_service(ServiceRecord(host="web.lab.local", port=443, service_name="https"))

    restored = HostGraph.from_dict(graph.to_dict())
    assert restored.summary()["hosts"] == 1
    assert restored.open_services()[0].port == 443

    nodes = graph.to_evidence_nodes()
    types = {n["type"] for n in nodes}
    assert types == {"host", "service", "edge"}


def test_negative_space_tracking():
    graph = HostGraph()
    graph.record_negative_space("db.lab.local", 3306, "SKIPPED_POLICY_RESTRICTION")
    assert graph.summary()["negative_space"] == 1
    assert graph.negative_space[0]["reason"] == "SKIPPED_POLICY_RESTRICTION"


def test_protocol_trace_hash_and_finding_defaults():
    trace = ProtocolTrace(host="10.0.0.5", port=445, protocol="smb",
                          request="NEGOTIATE", response="OK")
    assert len(trace.sha256) == 64
    finding = NetworkFinding(title="SMB signing disabled", host="10.0.0.5", port=445,
                             protocol="smb", service_name="microsoft-ds",
                             vuln_class="MISCONFIG", severity="MEDIUM")
    assert finding.status == "candidate"
    assert finding.evidence_level == "E0"
    assert finding.to_dict()["port"] == 445
