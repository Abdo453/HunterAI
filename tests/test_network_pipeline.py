"""Tests لـ Network Pipeline v1 — discover → fingerprint → graph → route."""
import asyncio

from core.network_model import ServiceRecord
from core.network_pipeline import NetworkPipeline
from core.network_scope_guard import NetworkScopeGuard
from core.network_scope_policy import NetworkScopePolicy


def _permissive_guard():
    policy = NetworkScopePolicy(
        allowed_targets=["10.0.0.0/8", "lab.local"],
        allowed_protocols=["tcp"],
        allow_active_network_tests=True,
        allow_private_ips_override=True,
        allowed_ports=[22, 445, 6379],
    )
    return NetworkScopeGuard(network_policy=policy)


async def _fake_discover(target, ports="1-65535", rate=1000, protocol="tcp"):
    return [
        ServiceRecord(host=target, port=445, protocol="tcp", state="open", source_tool="masscan"),
        ServiceRecord(host=target, port=6379, protocol="tcp", state="open", source_tool="masscan"),
        ServiceRecord(host=target, port=9999, protocol="tcp", state="open", source_tool="masscan"),
    ]


async def _fake_fingerprint(host, ports):
    out = []
    for p in ports:
        if p == 445:
            out.append(ServiceRecord(host=host, port=445, protocol="tcp", state="open",
                                     service_name="microsoft-ds", source_tool="nmap"))
        elif p == 6379:
            out.append(ServiceRecord(host=host, port=6379, protocol="tcp", state="open",
                                     service_name="redis", source_tool="nmap"))
    return out


def test_pipeline_end_to_end_with_synthetic_stages():
    pipeline = NetworkPipeline(
        discover=_fake_discover,
        fingerprint=_fake_fingerprint,
        scope_guard=_permissive_guard(),
    )
    assessment = asyncio.run(pipeline.run(["10.0.0.5"]))

    stats = assessment.stats
    assert stats["hosts"] == 1
    # Port 9999 is outside the port allowlist → dropped to Negative Space.
    assert stats["open_services"] == 2
    assert stats["candidate_findings"] >= 1
    assert stats["confirmed_findings"] == 0
    assert any(f.vuln_class == "UNAUTHENTICATED_SERVICE" for f in assessment.findings)
    assert all(f.status == "candidate" for f in assessment.findings)

    # 9999 was denied by port policy → recorded with a causal reason.
    assert any(ns["port"] == 9999 and ns["reason"] == "SKIPPED_SCOPE"
               for ns in assessment.negative_space)

    stage_names = [s["stage"] for s in assessment.stages]
    assert stage_names == ["discovery", "fingerprint", "graph", "routing", "ad_planning"]
    ad_stage = [s for s in assessment.stages if s["stage"] == "ad_planning"][0]
    assert ad_stage["status"] == "skipped"  # no AD surface in this scenario


async def _ad_discover(target, ports="1-65535", rate=1000, protocol="tcp"):
    return [
        ServiceRecord(host=target, port=88, protocol="tcp", state="open", source_tool="masscan"),
        ServiceRecord(host=target, port=389, protocol="tcp", state="open", source_tool="masscan"),
    ]


async def _ad_fingerprint(host, ports):
    names = {88: "kerberos", 389: "ldap"}
    return [ServiceRecord(host=host, port=p, protocol="tcp", state="open",
                          service_name=names[p], source_tool="nmap") for p in ports]


def test_pipeline_plans_ad_when_dc_detected():
    policy = NetworkScopePolicy(
        allowed_targets=["10.0.0.0/8"],
        allowed_protocols=["tcp"],
        allow_active_network_tests=True,
        allow_private_ips_override=True,
        allowed_ports=[88, 389],
    )
    pipeline = NetworkPipeline(
        discover=_ad_discover, fingerprint=_ad_fingerprint,
        scope_guard=NetworkScopeGuard(network_policy=policy),
    )
    assessment = asyncio.run(pipeline.run(["10.0.0.10"]))
    assert any(s["stage"] == "ad_planning" and s["status"] == "ok" for s in assessment.stages)
    assert assessment.stats["ad_candidate_findings"] >= 1
    # Even the AD planner never auto-confirms.
    assert all(f.status == "candidate" for f in assessment.findings)
    assert assessment.stats["confirmed_findings"] == 0


def test_pipeline_default_guard_is_fail_closed():
    pipeline = NetworkPipeline(discover=_fake_discover, fingerprint=_fake_fingerprint)
    assessment = asyncio.run(pipeline.run(["10.0.0.5"]))
    assert assessment.stats["open_services"] == 0
    assert assessment.stats["candidate_findings"] == 0
    assert any(ns["reason"] == "SKIPPED_SCOPE" for ns in assessment.negative_space)


def test_pipeline_out_of_scope_target_recorded_in_negative_space():
    pipeline = NetworkPipeline(discover=_fake_discover, scope_guard=_permissive_guard())
    assessment = asyncio.run(pipeline.run(["evil.example.net"]))
    assert assessment.stats["open_services"] == 0
    assert any(ns["host"] == "evil.example.net" and ns["stage"] == "discovery"
               for ns in assessment.negative_space)


def test_pipeline_discovery_failure_is_isolated():
    async def _boom(target, ports="1-65535", rate=1000, protocol="tcp"):
        raise RuntimeError("masscan exploded")

    pipeline = NetworkPipeline(discover=_boom, scope_guard=_permissive_guard())
    assessment = asyncio.run(pipeline.run(["10.0.0.5"]))
    assert assessment.stats["open_services"] == 0
    disc = [s for s in assessment.stages if s["stage"] == "discovery"][0]
    assert disc["error"] == "masscan exploded"


def test_pipeline_to_dict_serializable():
    import json
    pipeline = NetworkPipeline(discover=_fake_discover, fingerprint=_fake_fingerprint,
                               scope_guard=_permissive_guard())
    assessment = asyncio.run(pipeline.run(["10.0.0.5"]))
    payload = json.dumps(assessment.to_dict())
    assert "candidate_findings" in payload
