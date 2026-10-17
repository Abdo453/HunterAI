"""Tests لـ AD Model + Enumeration Planner (Phase 2)."""
from core.ad_model import (
    ADDomainController,
    ADDomainInfo,
    ADEnumPlanner,
    ADGraph,
    ADPrincipal,
    ADShare,
    plan_from_host_graph,
)
from core.network_model import HostGraph, ServiceRecord


def _build_graph():
    g = ADGraph()
    g.add_domain(ADDomainInfo(
        domain="corp.local", netbios="CORP",
        machine_account_quota=0,
        password_policy={"min_password_length": 6, "lockout_threshold": 0},
    ))
    g.add_dc(ADDomainController(
        host="DC01", address="10.0.0.10", domain="corp.local",
        services=["smb", "ldap", "kerberos"], smb_signing=False, smbv1_enabled=True,
    ))
    g.add_principal(ADPrincipal(name="svc_sql", sam_account_name="svc_sql",
                                domain="corp.local", spn_list=["MSSQLSvc/db:1433"]))
    g.add_principal(ADPrincipal(name="jdoe", sam_account_name="jdoe",
                                domain="corp.local", does_not_require_preauth=True))
    g.add_principal(ADPrincipal(name="WEB01", sam_account_name="WEB01$",
                                domain="corp.local", kind="computer",
                                unconstrained_delegation=True))
    g.add_share(ADShare(name="Public", host="10.0.0.10", domain="corp.local",
                        access="READ,WRITE", is_anonymous=True))
    return g


def test_graph_summary_counts():
    g = _build_graph()
    s = g.summary()
    assert s["domains"] == 1
    assert s["domain_controllers"] == 1
    assert s["kerberoastable"] == 1
    assert s["asreproastable"] == 1
    assert s["unconstrained_delegation"] == 1
    assert s["writable_shares"] == 1
    assert s["anonymous_shares"] == 1


def test_principal_roastability_flags():
    g = _build_graph()
    assert g.kerberoastable()[0].sam_account_name == "svc_sql"
    assert g.asreproastable()[0].sam_account_name == "jdoe"
    # A computer with unconstrained delegation is not "kerberoastable".
    assert all(p.kind == "user" for p in g.kerberoastable())


def test_planner_emits_candidate_findings_only():
    g = _build_graph()
    findings = ADEnumPlanner().plan(g)
    classes = {f.vuln_class for f in findings}
    assert "KERBEROASTABLE_ACCOUNT" in classes
    assert "ASREP_ROASTABLE_ACCOUNT" in classes
    assert "UNCONSTRAINED_DELEGATION" in classes
    assert "WRITABLE_SHARE" in classes
    assert "ANONYMOUS_SMB_ACCESS" in classes
    assert "SMB_SIGNING_DISABLED" in classes
    assert "SMBV1_ENABLED" in classes
    assert "WEAK_PASSWORD_POLICY" in classes

    # The golden rule: nothing is confirmed, everything is a candidate.
    assert all(f.status == "candidate" for f in findings)
    assert all(f.evidence_level == "E0" for f in findings)
    assert all(f.confidence < 0.85 for f in findings)
    # Highest severity first.
    assert findings[0].severity in ("HIGH", "CRITICAL")


def test_planner_tasks_are_ordered_and_flagged():
    g = _build_graph()
    tasks = ADEnumPlanner().tasks(g)
    phases = [t.phase for t in tasks]
    assert phases == sorted(phases, key=lambda p: {
        "fingerprint": 0, "anonymous-enum": 1, "authenticated-enum": 2,
        "privilege-escalation": 3, "credential-access": 4, "lateral-movement": 5,
    }[p])
    assert any(t.tool == "enum4linux-ng" for t in tasks)
    assert any("GetUserSPNs" in t.command for t in tasks)
    # AS-REP roast needs no credentials.
    asrep = [t for t in tasks if "GetNPUsers" in t.command]
    assert asrep and asrep[0].requires_credentials is False


def test_from_host_graph_detects_domain_controller():
    net = HostGraph()
    net.upsert_host("10.0.0.10", address="10.0.0.10")
    net.add_service(ServiceRecord(host="10.0.0.10", port=88, protocol="tcp",
                                  state="open", service_name="kerberos"))
    net.add_service(ServiceRecord(host="10.0.0.10", port=389, protocol="tcp",
                                  state="open", service_name="ldap"))
    ad = ADGraph.from_host_graph(net)
    assert ad.summary()["domain_controllers"] == 1
    assert plan_from_host_graph(net) == [] or all(
        f.status == "candidate" for f in plan_from_host_graph(net)
    )


def test_graph_round_trip_and_evidence_nodes():
    g = _build_graph()
    g2 = ADGraph.from_dict(g.to_dict())
    assert g2.summary()["principals"] == g.summary()["principals"]
    types = {n["type"] for n in g.to_evidence_nodes()}
    assert {"ad_domain", "ad_domain_controller", "ad_principal", "ad_share"} <= types
