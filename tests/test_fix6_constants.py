"""Regression tests for FIX 6 (Unify Configuration Constants)."""

from enum import Enum
import inspect

from core.burp_adapter import BurpAdapterConfig
from core.burp_gateway.capture_store import CaptureStore
from core.burp_gateway.gateway import BurpGateway
from core.code_intel.models import SecretStatus
from core.code_intel.secret_hunter import SecretHunter
from core.confidence_checker import ConfidenceChecker, ModelVerdict
from core.constants import (
    BURP_GATEWAY_HOST,
    BURP_GATEWAY_PORT,
    CourtVerdict as CanonicalCourtVerdict,
    SHANNON_ENTROPY_ADMISSION,
    SHANNON_ENTROPY_REJECTION,
)
from core.evidence_court import CourtVerdict as EvidenceCourtVerdict, EvidenceCourt
from core.host_bridge import HostGuard as AliasHostGuard
from core.readiness.checker import ReadinessChecker
from core.system.host_bridge import HostBridge, HostGuard


def test_canonical_constants_values():
    assert BURP_GATEWAY_HOST == "127.0.0.1"
    assert BURP_GATEWAY_PORT == 8085
    assert SHANNON_ENTROPY_ADMISSION == 3.3
    assert SHANNON_ENTROPY_REJECTION == 3.2
    assert SHANNON_ENTROPY_ADMISSION > SHANNON_ENTROPY_REJECTION

    assert issubclass(CanonicalCourtVerdict, str)
    assert issubclass(CanonicalCourtVerdict, Enum)
    expected = {
        "CONFIRMED": "CONFIRMED",
        "FALSE_POSITIVE": "FALSE_POSITIVE",
        "UNVERIFIED_SIGNAL": "UNVERIFIED_SIGNAL",
        "DISPROVED": "DISPROVED",
        "INCONCLUSIVE": "INCONCLUSIVE",
        "BLOCKED": "BLOCKED",
        "OUT_OF_SCOPE": "OUT_OF_SCOPE",
        "DUPLICATE": "DUPLICATE",
    }
    assert {m.name: m.value for m in CanonicalCourtVerdict} == expected


def test_secret_hunter_uses_entropy_constants():
    import core.code_intel.secret_hunter as sh_mod

    assert sh_mod.SHANNON_ENTROPY_ADMISSION == SHANNON_ENTROPY_ADMISSION
    assert sh_mod.SHANNON_ENTROPY_REJECTION == SHANNON_ENTROPY_REJECTION

    # A 20-char token with entropy ~3.24 sits between REJECTION (3.2) and ADMISSION (3.3):
    # - hunt_secrets() does not admit generic tokens below SHANNON_ENTROPY_ADMISSION (3.3)
    # - _process_candidate() validates >= SHANNON_ENTROPY_REJECTION (3.2) and rejects < 3.2
    mid_token = "qqqqqqgghijklmnopqrs"  # no placeholders, len=20, entropy ~3.24
    mid_ent = SecretHunter.calculate_shannon_entropy(mid_token)
    assert SHANNON_ENTROPY_REJECTION <= mid_ent < SHANNON_ENTROPY_ADMISSION
    assert SecretHunter.hunt_secrets(f'api_key = "{mid_token}"', "app.js") == []

    mid_cand = SecretHunter._process_candidate(
        "generic_credential", mid_token, "app.js", 2, entropy=mid_ent
    )
    assert mid_cand.status == SecretStatus.VALIDATED

    low_cand = SecretHunter._process_candidate(
        "generic_credential", "zzzzzzzzzzzzzzzzzzzz", "app.js", 1, entropy=3.19
    )
    assert low_cand.status == SecretStatus.REJECTED

    high_token = "ghijklmnopqrstuv1234"
    high_ent = SecretHunter.calculate_shannon_entropy(high_token)
    assert high_ent >= SHANNON_ENTROPY_ADMISSION
    admitted = SecretHunter.hunt_secrets(f'api_key = "{high_token}"', "app.js")
    assert len(admitted) == 1
    assert admitted[0].status == SecretStatus.VALIDATED


def test_burp_gateway_uses_gateway_constants(tmp_path):
    sig = inspect.signature(BurpGateway.__init__)
    assert sig.parameters["host"].default == BURP_GATEWAY_HOST
    assert sig.parameters["port"].default == BURP_GATEWAY_PORT

    gw = BurpGateway(capture_store=CaptureStore("test_fix6", base_dir=tmp_path))
    assert gw.host == BURP_GATEWAY_HOST
    assert gw.port == BURP_GATEWAY_PORT


def test_burp_adapter_checker_and_host_bridge_use_gateway_constants(tmp_path):
    cfg = BurpAdapterConfig()
    assert cfg.gateway_base_url == f"http://{BURP_GATEWAY_HOST}:{BURP_GATEWAY_PORT}"

    checker_sig = inspect.signature(ReadinessChecker.__init__)
    assert checker_sig.parameters["gateway_host"].default == BURP_GATEWAY_HOST
    assert checker_sig.parameters["gateway_port"].default == BURP_GATEWAY_PORT
    checker = ReadinessChecker()
    assert checker.gateway == (BURP_GATEWAY_HOST, BURP_GATEWAY_PORT)

    guard = HostGuard(allowed_root=tmp_path)
    assert BURP_GATEWAY_PORT in guard.allowed_ports
    assert AliasHostGuard is HostGuard
    bridge = HostBridge(sandbox_root=tmp_path)
    assert BURP_GATEWAY_PORT in bridge.host_guard.allowed_ports


def test_confidence_checker_uses_court_verdict_constants():
    import core.confidence_checker as cc_mod

    assert cc_mod.CourtVerdict is CanonicalCourtVerdict
    checker = ConfidenceChecker()

    fp_votes = [
        ModelVerdict("m", "sec", CanonicalCourtVerdict.FALSE_POSITIVE.value, 0.9, "e", "r", 0.1)
        for _ in range(3)
    ]
    res_fp = checker._calculate_consensus("claim", "http://target.local", fp_votes, "", "", 0.0)
    assert res_fp.final_verdict == CanonicalCourtVerdict.FALSE_POSITIVE.value

    conf_votes = [
        ModelVerdict("m", "sec", CanonicalCourtVerdict.CONFIRMED.value, 0.95, "e", "r", 0.1)
        for _ in range(5)
    ]
    res_corr = checker._calculate_consensus("claim", "http://target.local", conf_votes, "", "", 0.0)
    assert res_corr.final_verdict == "CORROBORATED"
    assert res_corr.final_verdict != CanonicalCourtVerdict.CONFIRMED.value


def test_evidence_court_verdict_compatibility():
    # Every canonical verdict matches by value with core.evidence_court.CourtVerdict
    for member in CanonicalCourtVerdict:
        court_member = getattr(EvidenceCourtVerdict, member.name)
        assert court_member == member
        assert court_member.value == member.value

    # Backwards-compatible UNVERIFIED verdict remains intact
    assert EvidenceCourtVerdict.UNVERIFIED.value == "UNVERIFIED"
    j = EvidenceCourt.adjudicate(
        target_url="https://target.local/item",
        parameter="id",
        vuln_class="idor",
        verifier_result={"reproduced": False},
        is_in_scope=True,
    )
    assert j.verdict is EvidenceCourtVerdict.UNVERIFIED
    assert j.verdict.value == "UNVERIFIED"
