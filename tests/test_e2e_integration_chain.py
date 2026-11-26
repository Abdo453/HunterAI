"""End-to-end integration chain tests for HunterAI.

Validates the complete sensor -> reasoning -> evidence -> export -> persistence path:

    Browser endpoint discovery -> AttackSurfaceGraph
    High-entropy secret detection -> EvidenceOS Claim in EvidenceCourt
    CONFIRMED verdict -> BurpIssueExporter (on-disk issues.json)
    Finding -> CaptureStore persistence + reload on a new startup

Fixtures mirror the ones in ``tests/test_fix2_fix5_brain_wiring.py`` so the
tests exercise the same real AutonomousBrain wiring used by the fix suites.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from core.brain.autonomous_brain import AutonomousBrain
from core.browser.session import StatefulBrowserSession
from core.burp_gateway.capture_store import CaptureStore, CapturedTransaction
from core.burp_gateway.event_stream import StreamEvent
from core.burp_gateway.issue_exporter import BurpIssueExporter
from core.code_intel.models import SecretCandidate, SecretStatus
from core.code_intel.secret_hunter import SecretHunter
from core.constants import SHANNON_ENTROPY_ADMISSION, CourtVerdict as ConstantsCourtVerdict
from core.evidence_court import CourtJudgment, CourtVerdict, EvidenceCourt, ProofPayload
from core.evidence_os.unified_model import Claim
from core.reasoning.attack_surface_graph import EpistemicStatus

TARGET_URL = "https://e2e.target.local"
ENDPOINT_URL = f"{TARGET_URL}/api/v1/e2e-orders"
SECRET_SOURCE_URL = f"{TARGET_URL}/static/app.js"
# 20 distinct symbols -> Shannon entropy = log2(20) ~= 4.32 bits (> 3.3 admission).
HIGH_ENTROPY_TOKEN = "ghijklmnopqrstuv1234"
LOW_ENTROPY_TOKEN = "zzzzzzzzzzzzzzzzzzzz"


@pytest.fixture
def brain(tmp_path: Path) -> AutonomousBrain:
    """Real AutonomousBrain with a disposable BurpIssueExporter (see fix2/fix5 fixture)."""
    instance = AutonomousBrain(
        resource_manager=MagicMock(),
        tool_manager=MagicMock(),
        dry_run=True,
        max_probes=5,
    )
    instance.burp_issue_exporter = BurpIssueExporter(output_dir=tmp_path / "burp_issues")
    return instance


def _make_browser_session(brain: AutonomousBrain, tmp_path: Path) -> StatefulBrowserSession:
    """Browser sensor whose DOM snapshot contains a single POST API endpoint."""
    session = StatefulBrowserSession(
        target_url=TARGET_URL,
        output_dir=tmp_path / "e2e_browser",
        headless=True,
        event_stream=brain.burp_event_stream,
    )
    session.dom_snapshots[TARGET_URL] = (
        "<html><body>"
        "<script>fetch('/api/v1/e2e-orders', {method: 'POST'});</script>"
        "</body></html>"
    )
    return session


def _hunt_token(token: str) -> SecretCandidate:
    """Run the real entropy-gated detector against a JS config assignment."""
    js = f'const cfg = {{ api_key: "{token}" }};'
    candidates = SecretHunter.hunt_secrets(js, SECRET_SOURCE_URL)
    assert len(candidates) == 1
    return candidates[0]


def _proof_for(token: str) -> ProofPayload:
    """Raw, engine-checkable proof: the token is in the response, absent from baseline."""
    return ProofPayload(
        artifact_type="token",
        expected_token=token,
        response_text=f"const cfg = {{ api_key: '{token}' }};",
        baseline_text="const cfg = {};",
    )


def _secret_event_data(candidate: SecretCandidate) -> Dict[str, Any]:
    return {
        "type": "secret_detected",
        "url": SECRET_SOURCE_URL,
        "secret_type": candidate.secret_type,
        "redacted_preview": candidate.redacted_preview,
        "status": candidate.status.value,
        "confidence": 0.95,
        "validation_notes": candidate.validation_notes,
        "verifier_result": {"reproduced": True},
        "proof_payload": _proof_for(candidate.raw_match),
    }


def _assert_confirmed_export(
    brain: AutonomousBrain,
    exporter_spy: MagicMock,
    real_exporter: BurpIssueExporter,
    tmp_path: Path,
) -> Dict[str, Any]:
    """Shared assertions for the CONFIRMED -> BurpIssueExporter stage."""
    exporter_spy.export_finding.assert_called_once()
    finding = exporter_spy.export_finding.call_args.args[0]
    assert finding["lifecycle_verdict"] == ConstantsCourtVerdict.CONFIRMED.value
    assert finding["endpoint"] == SECRET_SOURCE_URL
    assert finding["type"] == "secret_exposure"

    assert len(real_exporter.exported_issues) == 1
    issues_file = tmp_path / "burp_issues" / "issues.json"
    assert issues_file.exists()
    persisted = json.loads(issues_file.read_text(encoding="utf-8"))
    assert len(persisted) == 1
    assert persisted[0]["url"] == SECRET_SOURCE_URL
    assert persisted[0]["confidence"] == "Certain"
    assert "CONFIRMED" in persisted[0]["issue_detail"]
    return finding


@pytest.mark.asyncio
async def test_e2e_browser_endpoint_discovery_populates_attack_surface_graph(
    brain: AutonomousBrain, tmp_path: Path
) -> None:
    """Stage 1: browser DOM discovery -> EventStream -> brain listener -> AttackSurfaceGraph."""
    session = _make_browser_session(brain, tmp_path)
    try:
        extracted = session._extract_api_endpoints()
        assert any(ep["url"] == ENDPOINT_URL and ep["method"] == "POST" for ep in extracted)

        stream_events = [
            e for e in brain.burp_event_stream.get_recent_events()
            if isinstance(e, StreamEvent) and e.event_type == "browser_endpoint_discovered"
        ]
        assert any(e.data["url"] == ENDPOINT_URL for e in stream_events)

        node = brain.attack_surface_graph.nodes[ENDPOINT_URL]
        assert node.node_type == "ENDPOINT"
        assert node.epistemic_status == EpistemicStatus.OBSERVED
        assert node.attributes["method"] == "POST"
        assert node.attributes["source"] == "browser"

        # Re-observation must NOT downgrade an already CONFIRMED node.
        brain.attack_surface_graph.update_status(
            ENDPOINT_URL, EpistemicStatus.CONFIRMED, rationale="Verified by prior chain"
        )
        brain.burp_event_stream.publish_event(
            "browser_endpoint_discovered",
            {"type": "browser_endpoint_discovered", "url": ENDPOINT_URL, "method": "POST"},
        )
        assert (
            brain.attack_surface_graph.nodes[ENDPOINT_URL].epistemic_status
            == EpistemicStatus.CONFIRMED
        )
    finally:
        await session.close()


def test_e2e_high_entropy_secret_becomes_claim_then_confirmed_burp_issue(
    brain: AutonomousBrain, tmp_path: Path
) -> None:
    """Stages 2+3: entropy > 3.3 -> Claim -> CONFIRMED court verdict -> Burp export."""
    candidate = _hunt_token(HIGH_ENTROPY_TOKEN)
    assert candidate.status is SecretStatus.VALIDATED
    raw_entropy = SecretHunter.calculate_shannon_entropy(candidate.raw_match)
    assert raw_entropy > SHANNON_ENTROPY_ADMISSION
    assert candidate.entropy > SHANNON_ENTROPY_ADMISSION

    real_exporter = brain.burp_issue_exporter
    brain.burp_issue_exporter = MagicMock(wraps=real_exporter)

    with patch.object(EvidenceCourt, "adjudicate", wraps=EvidenceCourt.adjudicate) as court_spy:
        judgment = brain._on_sensor_event(_secret_event_data(candidate))

    # A canonical EvidenceOS Claim reached EvidenceCourt (asdict(finder_claim)).
    court_spy.assert_called_once()
    finder_claim = court_spy.call_args.kwargs["finder_claim"]
    assert finder_claim["claim_id"].startswith("CLM-")
    assert finder_claim["vulnerability_class"] == f"SECRET_EXPOSURE:{candidate.secret_type}"
    assert finder_claim["confidence_score"] == pytest.approx(0.95)
    assert set(Claim.__dataclass_fields__).issubset(finder_claim)

    assert isinstance(judgment, CourtJudgment)
    assert judgment.verdict is CourtVerdict.CONFIRMED
    assert judgment.reportable is True
    _assert_confirmed_export(brain, brain.burp_issue_exporter, real_exporter, tmp_path)


def test_e2e_low_entropy_secret_is_rejected_before_any_court_or_export(
    brain: AutonomousBrain, tmp_path: Path
) -> None:
    """Entropy gate (<= 3.3) stops the chain before a Claim or export can occur."""
    assert SecretHunter.calculate_shannon_entropy(LOW_ENTROPY_TOKEN) < SHANNON_ENTROPY_ADMISSION
    assert SecretHunter.hunt_secrets(
        f'api_key = "{LOW_ENTROPY_TOKEN}"', SECRET_SOURCE_URL
    ) == []

    with patch.object(EvidenceCourt, "adjudicate", wraps=EvidenceCourt.adjudicate) as court_spy:
        # Sensors only publish events for candidates that survive the entropy gate.
        for candidate in SecretHunter.hunt_secrets(
            f'api_key = "{LOW_ENTROPY_TOKEN}"', SECRET_SOURCE_URL
        ):
            brain._on_sensor_event(_secret_event_data(candidate))

    court_spy.assert_not_called()
    assert brain.burp_issue_exporter.exported_issues == []
    assert not (tmp_path / "burp_issues" / "issues.json").exists()


def test_e2e_capture_store_persists_findings_and_reloads_on_startup(tmp_path: Path) -> None:
    """Stage 4: confirmed finding written to disk and reloaded by a new CaptureStore."""
    base_dir = tmp_path / "engagements"
    target = "e2e.target.local"

    store = CaptureStore(target, base_dir=base_dir)
    store.store_transaction(CapturedTransaction(
        tx_id="tx_e2e_01",
        target_host=target,
        method="GET",
        url=SECRET_SOURCE_URL,
        status_code=200,
        resp_body="const cfg = { api_key: 'REDACTED' };",
        trace_id="TRACE-E2E-01",
        browser_action_id="BA-E2E-01",
    ))
    finding = {
        "id": "E2E-SECRET-001",
        "title": "Confirmed Secret Exposure (generic_credential)",
        "severity": "High",
        "lifecycle_verdict": ConstantsCourtVerdict.CONFIRMED.value,
        "endpoint": SECRET_SOURCE_URL,
        "evidence": "Entropy > 3.3 and deterministic token proof verified.",
    }
    store.record_finding(finding)

    finding_file = store.root_dir / "findings" / "E2E-SECRET-001.json"
    assert finding_file.exists()
    assert json.loads(finding_file.read_text(encoding="utf-8"))["title"] == finding["title"]

    # Simulate a process restart: a brand new instance sees the persisted data.
    restarted = CaptureStore(target, base_dir=base_dir)
    assert len(restarted.findings) == 1
    assert restarted.findings[0]["id"] == "E2E-SECRET-001"
    assert restarted.findings[0]["lifecycle_verdict"] == "CONFIRMED"
    assert [tx.tx_id for tx in restarted.list_transactions()] == ["tx_e2e_01"]
    assert restarted.get_summary()["findings_count"] == 1

    # Explicit reload is idempotent (no duplicates).
    restarted.load_previous_session()
    restarted.load_previous_session()
    assert len(restarted.findings) == 1
    assert len(restarted.list_transactions()) == 1


@pytest.mark.asyncio
async def test_e2e_full_integration_chain(brain: AutonomousBrain, tmp_path: Path) -> None:
    """All four stages wired together through the live EventStream and brain listener."""
    real_exporter = brain.burp_issue_exporter
    brain.burp_issue_exporter = MagicMock(wraps=real_exporter)

    # 1) Browser sensor publishes an endpoint; brain registers it in the graph.
    session = _make_browser_session(brain, tmp_path)
    try:
        assert any(
            ep["url"] == ENDPOINT_URL for ep in session._extract_api_endpoints()
        )
    finally:
        await session.close()
    assert brain.attack_surface_graph.nodes[ENDPOINT_URL].epistemic_status == EpistemicStatus.OBSERVED

    # 2) Real SecretHunter admits a high-entropy secret; the event reaches the
    #    brain via BurpLiveEventStream and produces a Claim submitted to the court.
    candidate = _hunt_token(HIGH_ENTROPY_TOKEN)
    with patch.object(EvidenceCourt, "adjudicate", wraps=EvidenceCourt.adjudicate) as court_spy:
        evt = brain.burp_event_stream.publish_event(
            "secret_detected", _secret_event_data(candidate)
        )
        assert isinstance(evt, StreamEvent)
    court_spy.assert_called_once()
    assert court_spy.call_args.kwargs["finder_claim"]["claim_id"].startswith("CLM-")

    # 3) The CONFIRMED verdict triggers the BurpIssueExporter and on-disk index.
    _assert_confirmed_export(brain, brain.burp_issue_exporter, real_exporter, tmp_path)
    exported_issue = real_exporter.exported_issues[0]

    # 4) The confirmed finding survives a CaptureStore restart.
    base_dir = tmp_path / "engagements"
    store = CaptureStore("e2e.target.local", base_dir=base_dir)
    store.record_finding({
        "id": "E2E-FULL-001",
        "title": exported_issue["issue_name"],
        "severity": exported_issue["severity"],
        "lifecycle_verdict": ConstantsCourtVerdict.CONFIRMED.value,
        "endpoint": exported_issue["url"],
    })
    persisted = CaptureStore("e2e.target.local", base_dir=base_dir)
    assert len(persisted.findings) == 1
    assert persisted.findings[0]["id"] == "E2E-FULL-001"
    assert persisted.findings[0]["title"] == exported_issue["issue_name"]
    assert persisted.findings[0]["lifecycle_verdict"] == "CONFIRMED"
