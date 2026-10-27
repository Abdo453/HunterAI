"""Hermetic tests for the safe detector lab (loopback only, no external traffic)."""
from __future__ import annotations

import time

import pytest

from core.detectors.cli import main as cli_main
from core.detectors.contract import DetectionContext, Probe
from core.detectors.evidence_chain import EvidenceChain
from core.detectors.idor import IDORDetector
from core.detectors.local_target import ALICE_CANARY, LocalFakeTarget
from core.detectors.sqli_boolean import SQLiBooleanDetector
from core.detectors.transport import (
    HttpTransport,
    PolicyViolation,
    TransportConfig,
)
from core.detectors.xss_reflected import XSSReflectedDetector
from core.policy.red_team import (
    AuthorizationGrant,
    Profile,
    RedTeamPolicyEngine,
    ScopeTarget,
)


@pytest.fixture()
def target():
    server = LocalFakeTarget().start()
    try:
        yield server
    finally:
        server.stop()


def _client() -> HttpTransport:
    return HttpTransport(TransportConfig(allowed_hosts={"127.0.0.1"}))


def _sqli_context(target, path="/search"):
    return DetectionContext(base_url=target.base_url, path=path, parameter="q")


def _xss_context(target, path="/echo"):
    return DetectionContext(base_url=target.base_url, path=path, parameter="name")


def _idor_context(target, path="/profile"):
    return DetectionContext(
        base_url=target.base_url,
        path=path,
        id_parameter="id",
        resource_id="1",
        owner_headers={"X-User": "alice"},
        other_headers={"X-User": "bob"},
        owner_marker=ALICE_CANARY,
    )


# -- SQLi -------------------------------------------------------------------

def test_sqli_confirms_on_vulnerable_endpoint(target):
    detection = SQLiBooleanDetector().detect(_sqli_context(target), _client())
    assert detection.confirmed is True
    assert detection.confidence >= 0.9
    assert detection.finding is not None
    assert detection.finding.cwe == "CWE-89"
    assert detection.finding.severity == "HIGH"
    assert len(detection.exchanges) == 6  # control pair + two payload pairs


def test_sqli_rejects_safe_endpoint(target):
    detection = SQLiBooleanDetector().detect(
        _sqli_context(target, "/search/safe"), _client()
    )
    assert detection.confirmed is False
    assert "differential" in detection.reason


# -- XSS --------------------------------------------------------------------

def test_xss_confirms_on_vulnerable_endpoint(target):
    detection = XSSReflectedDetector().detect(_xss_context(target), _client())
    assert detection.confirmed is True
    assert detection.finding is not None
    assert detection.finding.cwe == "CWE-79"
    assert detection.finding.verification.proof_token


def test_xss_rejects_escaped_endpoint(target):
    detection = XSSReflectedDetector().detect(
        _xss_context(target, "/echo/safe"), _client()
    )
    assert detection.confirmed is False
    assert "encoded" in detection.reason


# -- IDOR -------------------------------------------------------------------

def test_idor_confirms_on_vulnerable_endpoint(target):
    detection = IDORDetector().detect(_idor_context(target), _client())
    assert detection.confirmed is True
    assert detection.finding is not None
    assert detection.finding.cwe == "CWE-639"
    assert detection.finding.severity == "HIGH"


def test_idor_rejects_owner_checked_endpoint(target):
    detection = IDORDetector().detect(
        _idor_context(target, "/profile/safe"), _client()
    )
    assert detection.confirmed is False
    assert "authorization held" in detection.reason


def test_idor_requires_an_owner_canary(target):
    context = _idor_context(target)
    context.owner_marker = ""
    detection = IDORDetector().detect(context, _client())
    assert detection.confirmed is False
    assert "owner_marker is required" in detection.reason
    assert target.requests == []


# -- transport and policy ---------------------------------------------------

def test_transport_rejects_write_methods():
    with pytest.raises(ValueError):
        Probe(method="POST", url="http://127.0.0.1/")


def test_policy_denial_happens_before_the_server_is_hit(target):
    secret = b"detector-secret"
    now = time.time()
    grant = AuthorizationGrant.sign(
        secret,
        grant_id="ENG-DET",
        authorized_by="Test",
        scope=[ScopeTarget("domain", "example.com")],
        not_before=now - 60,
        not_after=now + 3600,
        profiles=[Profile.RED_TEAM],
    )
    engine = RedTeamPolicyEngine(grant, Profile.RED_TEAM, secret)
    client = HttpTransport(
        TransportConfig(allowed_hosts={"127.0.0.1"}), policy_engine=engine
    )
    with pytest.raises(PolicyViolation):
        client.get(f"{target.base_url}/health")
    assert target.requests == []


def test_all_detector_traffic_is_get_only(target):
    client = _client()
    SQLiBooleanDetector().detect(_sqli_context(target), client)
    XSSReflectedDetector().detect(_xss_context(target), client)
    IDORDetector().detect(_idor_context(target), client)
    assert target.requests
    assert {item["method"] for item in target.requests} == {"GET"}


# -- evidence chain ---------------------------------------------------------

def test_evidence_chain_verifies_and_detects_tampering(target):
    detection = SQLiBooleanDetector().detect(_sqli_context(target), _client())
    chain = EvidenceChain()
    chain.append_all(detection)
    assert chain.verify() is True
    assert [record.kind for record in chain.records].count("exchange") == 6
    assert [record.kind for record in chain.records].count("detection") == 1

    chain._records[0].payload_hash = "f" * 64
    assert chain.verify() is False


def test_evidence_chain_round_trips_through_disk(target, tmp_path):
    detection = XSSReflectedDetector().detect(_xss_context(target), _client())
    chain = EvidenceChain()
    chain.append_all(detection)
    path = tmp_path / "chain.jsonl"
    chain.save(str(path))

    loaded = EvidenceChain.load(str(path))
    assert len(loaded.records) == len(chain.records)
    assert loaded.verify() is True


# -- CLI --------------------------------------------------------------------

def test_cli_demo_runs_clean(capsys):
    assert cli_main(["demo"]) == 0
    output = capsys.readouterr().out
    assert '"ok": true' in output
    assert '"chain_verified": true' in output
    assert '"only_get_requests": true' in output


def test_cli_scan_writes_verifiable_chain(target, tmp_path, capsys):
    path = tmp_path / "scan_chain.jsonl"
    code = cli_main(
        [
            "scan",
            "--target",
            target.base_url,
            "--path",
            "/search",
            "--param",
            "q",
            "--class",
            "sqli",
            "--out",
            str(path),
        ]
    )
    assert code == 0
    assert path.exists()
    assert EvidenceChain.load(str(path)).verify() is True
    assert '"confirmed": true' in capsys.readouterr().out
