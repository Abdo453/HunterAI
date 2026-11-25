"""Integration tests for FIX 2 (EventStream listener) and FIX 5 (BurpIssueExporter wiring) in AutonomousBrain."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.brain.autonomous_brain import AutonomousBrain
from core.browser.session import StatefulBrowserSession
from core.burp_gateway.event_stream import BurpLiveEventStream, StreamEvent
from core.burp_gateway.issue_exporter import BurpIssueExporter
from core.constants import CourtVerdict as ConstantsCourtVerdict
from core.court.evidence_court_v2 import CourtParticipantRole, CourtRoleVerdict, TribunalRuling
from core.evidence_court import CourtJudgment, CourtVerdict, EvidenceCourt, ProofPayload
from core.evidence_os.unified_model import Claim
from core.hypothesis_engine.engine import HypothesisEngine as CoreHypothesisEngine
from core.reasoning.attack_surface_graph import EpistemicStatus


def _make_brain(tmp_path: Path) -> AutonomousBrain:
    brain = AutonomousBrain(
        resource_manager=MagicMock(),
        tool_manager=MagicMock(),
        dry_run=True,
        max_probes=5,
    )
    brain.burp_issue_exporter = BurpIssueExporter(output_dir=tmp_path / "burp_issues")
    return brain


def test_brain_registers_event_stream_listener_and_subsystems(tmp_path: Path):
    brain = _make_brain(tmp_path)

    assert isinstance(brain.burp_event_stream, BurpLiveEventStream)
    assert brain._on_sensor_event in brain.burp_event_stream._sync_listeners
    assert brain.hypothesis_engine is not None
    assert brain.evidence_court is not None
    assert isinstance(brain.burp_issue_exporter, BurpIssueExporter)


def test_on_sensor_event_browser_endpoint_discovered_stream_and_dict(tmp_path: Path):
    brain = _make_brain(tmp_path)

    # 1. StreamEvent via publish_event
    evt = brain.burp_event_stream.publish_event(
        "browser_endpoint_discovered",
        {
            "type": "browser_endpoint_discovered",
            "url": "https://target.local/api/orders",
            "method": "POST",
            "source": "browser",
            "params": ["order_id"],
        },
    )
    assert isinstance(evt, StreamEvent)
    assert "https://target.local/api/orders" in brain.attack_surface_graph.nodes
    node = brain.attack_surface_graph.nodes["https://target.local/api/orders"]
    assert node.node_type == "ENDPOINT"
    assert node.epistemic_status == EpistemicStatus.OBSERVED
    assert node.attributes["method"] == "POST"

    # 2. Raw dict directly
    brain._on_sensor_event(
        {
            "type": "browser_endpoint_discovered",
            "url": "https://target.local/api/profile",
            "method": "GET",
        }
    )
    assert "https://target.local/api/profile" in brain.attack_surface_graph.nodes

    # 3. Re-observing an already CONFIRMED endpoint must not downgrade status
    brain.attack_surface_graph.update_status(
        "https://target.local/api/profile",
        EpistemicStatus.CONFIRMED,
        rationale="Verified",
    )
    brain._on_sensor_event(
        {
            "type": "browser_endpoint_discovered",
            "url": "https://target.local/api/profile",
            "method": "GET",
        }
    )
    assert (
        brain.attack_surface_graph.nodes["https://target.local/api/profile"].epistemic_status
        == EpistemicStatus.CONFIRMED
    )


def test_on_sensor_event_secret_detected_unconfirmed_does_not_export(tmp_path: Path):
    brain = _make_brain(tmp_path)

    with patch.object(EvidenceCourt, "adjudicate", wraps=EvidenceCourt.adjudicate) as spy_adj:
        brain.burp_event_stream.publish_event(
            "secret_detected",
            {
                "url": "https://target.local/static/app.js",
                "secret_type": "aws_key",
                "redacted_preview": "AKIA****1234",
                "status": "VALIDATED",
            },
        )

    assert spy_adj.call_count == 1
    kwargs = spy_adj.call_args.kwargs
    assert kwargs["target_url"] == "https://target.local/static/app.js"
    assert kwargs["parameter"] == "aws_key"
    assert kwargs["vuln_class"] == "SECRET_EXPOSURE:aws_key"
    assert kwargs["finder_claim"]["claim_id"].startswith("CLM-")
    # Without derived proof, EvidenceCourt will not return CONFIRMED -> no Burp export
    assert brain.burp_issue_exporter.exported_issues == []


def test_on_sensor_event_secret_detected_confirmed_with_mock_1arg_court_exports(tmp_path: Path):
    brain = _make_brain(tmp_path)
    received_claims = []

    class FakeCourt:
        def adjudicate(self, claim: Claim) -> CourtJudgment:
            received_claims.append(claim)
            return CourtJudgment(
                target_url="https://target.local/bundle.js",
                parameter="stripe_key",
                vuln_class=claim.vulnerability_class,
                verdict=ConstantsCourtVerdict.CONFIRMED,  # test core.constants.CourtVerdict interop
                calibrated_severity="High",
                confidence_score=0.98,
                reportable=True,
                adjudication_rationale="Confirmed secret token",
            )

    brain.evidence_court = FakeCourt()
    brain._on_sensor_event(
        {
            "type": "secret_detected",
            "url": "https://target.local/bundle.js",
            "secret_type": "stripe_key",
            "redacted_preview": "sk_l****abcd",
            "confidence": 0.95,
        }
    )

    assert len(received_claims) == 1
    assert isinstance(received_claims[0], Claim)
    assert received_claims[0].vulnerability_class == "SECRET_EXPOSURE:stripe_key"
    assert len(brain.burp_issue_exporter.exported_issues) == 1
    issues_file = tmp_path / "burp_issues" / "issues.json"
    assert issues_file.exists()
    persisted = json.loads(issues_file.read_text(encoding="utf-8"))
    assert len(persisted) == 1
    assert persisted[0]["url"] == "https://target.local/bundle.js"


def test_on_sensor_event_secret_detected_real_evidence_court_confirmed_exports(tmp_path: Path):
    brain = _make_brain(tmp_path)

    proof = ProofPayload(
        artifact_type="token",
        expected_token="SECRET_TOKEN_XYZ_999",
        response_text="config={apiKey:'SECRET_TOKEN_XYZ_999'}",
        baseline_text="config={}",
    )
    brain.burp_event_stream.publish_event(
        "secret_detected",
        {
            "url": "https://target.local/config.js",
            "secret_type": "generic_credential",
            "redacted_preview": "SECR****_999",
            "verifier_result": {"reproduced": True},
            "proof_payload": proof,
        },
    )

    assert len(brain.burp_issue_exporter.exported_issues) == 1
    assert brain.burp_issue_exporter.exported_issues[0]["confidence"] == "Certain"
    assert (tmp_path / "burp_issues" / "issues.json").exists()


def test_on_sensor_event_api_endpoint_found_generates_hypothesis(tmp_path: Path):
    brain = _make_brain(tmp_path)

    brain.burp_event_stream.publish_event(
        "api_endpoint_found",
        {"url": "https://target.local/api/users/42", "method": "GET"},
    )
    brain._on_sensor_event(
        {"type": "api_endpoint_found", "url": "https://target.local/admin/roles", "method": "POST"}
    )

    hyps = list(brain.hypothesis_engine._hypotheses.values())
    assert len(hyps) == 2
    assert hyps[0].target_endpoint == "https://target.local/api/users/42"
    assert hyps[0].vulnerability_class == "BOLA"
    assert hyps[1].target_endpoint == "https://target.local/admin/roles"
    assert hyps[1].vulnerability_class == "BFLA"

    # Also verify compatibility with core.hypothesis_engine.engine.HypothesisEngine
    core_engine = CoreHypothesisEngine()
    brain.hypothesis_engine = core_engine
    brain._on_sensor_event(
        {"type": "api_endpoint_found", "url": "https://target.local/graphql", "method": "POST"}
    )
    assert len(core_engine.list_hypotheses()) == 1
    assert "GRAPHQL_ABUSE" in core_engine.list_hypotheses()[0].description


@pytest.mark.asyncio
async def test_fix5_run_scan_exports_confirmed_finding_from_evidence_court_v2(tmp_path: Path):
    brain = _make_brain(tmp_path)
    # Use dry_run=False only for _execute_tool mock; no real network calls occur
    brain.dry_run = False
    brain.burp_issue_exporter = MagicMock(wraps=brain.burp_issue_exporter)

    brain._check_burp_online = AsyncMock(return_value=False)
    brain._fetch_target = AsyncMock(return_value=("<html></html>", 200, {}))
    brain._extract_endpoints_and_params = MagicMock(
        return_value=(["id"], [{"url": "https://target.local/item?id=1", "param": "id"}])
    )
    brain._extract_js_urls = MagicMock(return_value=[])
    brain.decision.make_plan = AsyncMock(
        return_value={"needed_tools": ["SmartPoC"], "primary_focus": "sqli", "parameters_to_audit": ["id"]}
    )
    brain.decision.classify_tool_output = AsyncMock(return_value={"is_real_vuln": True})
    brain.artifact.analyze_tool_output = AsyncMock(return_value={"remediation_code": "Use parameterized queries"})
    brain.api_esc.call_all_parallel = AsyncMock(return_value=[])
    brain.api_esc.escalate_if_uncertain = AsyncMock(return_value={"api_recommended_action": "keep"})
    brain.security_intelligence = None
    brain.knowledge = None
    brain.learner = None

    async def fake_execute_tool(tool_name: str, **kwargs):
        if tool_name == "SmartPoC":
            return [
                {
                    "tool": "SmartPoC",
                    "param": "id",
                    "endpoint": "https://target.local/item?id=1",
                    "poc_result": {
                        "verified": True,
                        "reproduced": True,
                        "vuln_type": "sqli",
                        "proof_reason": "UNION SQLi confirmed",
                        "evidence": {"probe_snippet": "PostgreSQL 14.2"},
                        "payload_used": "' UNION SELECT version()--",
                        "status_code": 200,
                    },
                }
            ]
        return []

    brain._execute_tool = AsyncMock(side_effect=fake_execute_tool)

    confirmed_ruling = TribunalRuling(
        case_id="CASE-SQLI-1",
        target_endpoint="https://target.local",
        final_verdict="CONFIRMED",
        unanimous=True,
        opinions=[
            CourtRoleVerdict(CourtParticipantRole.CHIEF_JUSTICE, "VOTE_CONFIRM", "Proven", 0.99)
        ],
        chief_justification="Deterministic SQLi proof verified.",
        proof_strength="DERIVED",
        epistemic_state="CONFIRMED",
    )

    with patch("core.brain.autonomous_brain.HumanLikeExplorationEngine") as mock_exp_cls, \
         patch("core.brain.autonomous_brain.StatefulBrowserSession") as mock_sess_cls, \
         patch("core.brain.autonomous_brain.CodeIntelligenceAgent") as mock_ci_cls, \
         patch("core.brain.autonomous_brain.EvidenceCourtV2.adjudicate_case", return_value=confirmed_ruling):
        mock_sess = MagicMock()
        mock_sess.close = AsyncMock()
        mock_sess_cls.return_value = mock_sess

        mock_exp = MagicMock()
        mock_exp.explore = AsyncMock(return_value={"endpoints": [], "params": [], "js_urls": []})
        mock_exp_cls.return_value = mock_exp

        mock_ci = MagicMock()
        mock_ci.analyze_page = AsyncMock(return_value={"manifest": {}, "endpoints": []})
        mock_ci_cls.return_value = mock_ci

        result = await brain.run_scan("https://target.local", mode="sqli")

    assert result["target"] == "https://target.local"
    assert brain.burp_issue_exporter.export_finding.call_count == 1
    exported_arg = brain.burp_issue_exporter.export_finding.call_args.args[0]
    assert exported_arg["lifecycle_verdict"] == "CONFIRMED"
    assert exported_arg["endpoint"] == "https://target.local"
    assert (
        brain.attack_surface_graph.nodes["https://target.local"].epistemic_status
        == EpistemicStatus.CONFIRMED
    )
    issues_file = tmp_path / "burp_issues" / "issues.json"
    assert issues_file.exists()


@pytest.mark.asyncio
async def test_fix5_run_scan_does_not_export_refuted_finding(tmp_path: Path):
    brain = _make_brain(tmp_path)
    brain.dry_run = False
    brain.burp_issue_exporter = MagicMock(wraps=brain.burp_issue_exporter)
    brain.negative_ledger = None

    brain._check_burp_online = AsyncMock(return_value=False)
    brain._fetch_target = AsyncMock(return_value=("<html></html>", 200, {}))
    brain._extract_endpoints_and_params = MagicMock(return_value=(["id"], []))
    brain._extract_js_urls = MagicMock(return_value=[])
    brain.decision.make_plan = AsyncMock(
        return_value={"needed_tools": ["SmartPoC"], "primary_focus": "xss", "parameters_to_audit": ["id"]}
    )
    brain.decision.classify_tool_output = AsyncMock(return_value={"is_real_vuln": True})
    brain.artifact.analyze_tool_output = AsyncMock(return_value={})
    brain.api_esc.call_all_parallel = AsyncMock(return_value=[])
    brain.security_intelligence = None
    brain.knowledge = None
    brain.learner = None

    async def fake_execute_tool(tool_name: str, **kwargs):
        if tool_name == "SmartPoC":
            return [
                {
                    "tool": "SmartPoC",
                    "param": "id",
                    "endpoint": "https://target.local",
                    "poc_result": {
                        "verified": False,
                        "reproduced": False,
                        "vuln_type": "xss",
                        "proof_reason": "Unverified reflection",
                        "evidence": {},
                        "status_code": 200,
                    },
                }
            ]
        return []

    brain._execute_tool = AsyncMock(side_effect=fake_execute_tool)

    refuted_ruling = TribunalRuling(
        case_id="CASE-XSS-1",
        target_endpoint="https://target.local",
        final_verdict="REFUTED",
        unanimous=False,
        opinions=[],
        chief_justification="Reflection is not execution.",
    )

    with patch("core.brain.autonomous_brain.HumanLikeExplorationEngine") as mock_exp_cls, \
         patch("core.brain.autonomous_brain.StatefulBrowserSession") as mock_sess_cls, \
         patch("core.brain.autonomous_brain.CodeIntelligenceAgent") as mock_ci_cls, \
         patch("core.brain.autonomous_brain.EvidenceCourtV2.adjudicate_case", return_value=refuted_ruling):
        mock_sess = MagicMock()
        mock_sess.close = AsyncMock()
        mock_sess_cls.return_value = mock_sess

        mock_exp = MagicMock()
        mock_exp.explore = AsyncMock(return_value={"endpoints": [], "params": [], "js_urls": []})
        mock_exp_cls.return_value = mock_exp

        mock_ci = MagicMock()
        mock_ci.analyze_page = AsyncMock(return_value={"manifest": {}, "endpoints": []})
        mock_ci_cls.return_value = mock_ci

        result = await brain.run_scan("https://target.local", mode="xss")

    assert result["findings"] == []
    brain.burp_issue_exporter.export_finding.assert_not_called()


@pytest.mark.asyncio
async def test_fix1_brain_passes_event_stream_to_stateful_browser_session(tmp_path: Path):
    brain = _make_brain(tmp_path)
    brain._check_burp_online = AsyncMock(return_value=False)
    brain._fetch_target = AsyncMock(return_value=("<html></html>", 200, {}))
    brain._extract_endpoints_and_params = MagicMock(return_value=(["id"], []))
    brain._extract_js_urls = MagicMock(return_value=[])
    brain.decision.make_plan = AsyncMock(
        return_value={"needed_tools": [], "primary_focus": "xss", "parameters_to_audit": ["id"]}
    )
    brain.api_esc.call_all_parallel = AsyncMock(return_value=[])
    brain.security_intelligence = None
    brain.knowledge = None
    brain.learner = None

    with patch("core.brain.autonomous_brain.HumanLikeExplorationEngine") as mock_exp_cls, \
         patch("core.brain.autonomous_brain.StatefulBrowserSession") as mock_sess_cls, \
         patch("core.brain.autonomous_brain.CodeIntelligenceAgent") as mock_ci_cls:
        mock_sess = MagicMock()
        mock_sess.close = AsyncMock()
        mock_sess_cls.return_value = mock_sess

        mock_exp = MagicMock()
        mock_exp.explore = AsyncMock(return_value={"endpoints": [], "params": [], "js_urls": []})
        mock_exp_cls.return_value = mock_exp

        mock_ci = MagicMock()
        mock_ci.analyze_page = AsyncMock(return_value={"manifest": {}, "endpoints": []})
        mock_ci_cls.return_value = mock_ci

        await brain.run_scan("https://target.local", mode="passive")

    assert mock_sess_cls.call_count == 1
    assert mock_sess_cls.call_args.kwargs["event_stream"] is brain.burp_event_stream

    # Real StatefulBrowserSession -> BurpLiveEventStream -> Brain._on_sensor_event -> AttackSurfaceGraph
    session = StatefulBrowserSession(
        target_url="https://target.local",
        output_dir=tmp_path / "browser",
        headless=True,
        event_stream=brain.burp_event_stream,
    )
    try:
        session.dom_snapshots["https://target.local"] = (
            "<script>fetch('/api/v1/secrets', {method: 'POST'});</script>"
        )
        extracted = session._extract_api_endpoints()
        assert any(ep["url"] == "https://target.local/api/v1/secrets" for ep in extracted)
        assert "https://target.local/api/v1/secrets" in brain.attack_surface_graph.nodes
        node = brain.attack_surface_graph.nodes["https://target.local/api/v1/secrets"]
        assert node.epistemic_status == EpistemicStatus.OBSERVED
        assert node.attributes["method"] == "POST"
    finally:
        await session.close()

