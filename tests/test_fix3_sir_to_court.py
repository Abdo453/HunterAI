"""Tests for FIX 3: Bridge SIRGraph to EvidenceCourt (`core.bridges.sir_to_court`)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from core.bridges import sir_entity_to_claim, submit_sir_to_court
from core.compiler.security_ir import SIREntity, SIREntityType, SIRGraph
from core.court.evidence_court_v2 import EvidenceCourtV2
from core.evidence_court import CourtJudgment, CourtVerdict, EvidenceCourt
from core.evidence_os.unified_model import Claim
from core.normalizer.tool_normalizer import ToolOutputNormalizer


class _DuckMockCourt:
    """1-arg mock court accepting a Claim object."""

    def __init__(self) -> None:
        self.received_claims: List[Claim] = []

    def adjudicate(self, claim: Claim) -> CourtJudgment:
        self.received_claims.append(claim)
        return CourtJudgment(
            target_url="https://mock.local/test",
            parameter="id",
            vuln_class=claim.vulnerability_class,
            verdict=CourtVerdict.INCONCLUSIVE,
            confidence_score=claim.confidence_score,
            adjudication_rationale=claim.rationale,
        )


@dataclass
class _AltNode:
    entity_id: str
    entity_type: str
    name: str
    confidence: float
    attributes: Dict[str, Any] = field(default_factory=dict)
    observed_sources: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)


class _AltNodesGraph:
    def __init__(self, nodes: Any, target_host: str = "alt.local") -> None:
        self.nodes = nodes
        self.target_host = target_host


def _build_mixed_confidence_graph() -> SIRGraph:
    graph = SIRGraph(target_host="app.example.com")
    graph.add_entity(
        SIREntity(
            entity_id="sink_high_095",
            entity_type=SIREntityType.SINK,
            name="SQLI Sink on /api/users",
            attributes={
                "url": "https://app.example.com/api/users",
                "parameter": "id",
                "vuln_class": "SQLI",
            },
            observed_sources={"SQLMAP"},
            evidence_refs=["sig_sqlm_01"],
            confidence=0.95,
        )
    )
    graph.add_entity(
        SIREntity(
            entity_id="sink_boundary_080",
            entity_type=SIREntityType.SINK,
            name="XSS Sink on /search",
            attributes={
                "endpoint": "/search",
                "parameter": "q",
                "vuln_class": "XSS",
            },
            observed_sources={"DALFOX"},
            evidence_refs=["sig_dlf_01"],
            confidence=0.8,
        )
    )
    graph.add_entity(
        SIREntity(
            entity_id="sink_low_079",
            entity_type=SIREntityType.SINK,
            name="BOLA Candidate on /orders",
            attributes={"vuln_class": "BOLA"},
            observed_sources={"NUCLEI"},
            evidence_refs=["sig_nuc_01"],
            confidence=0.79,
        )
    )
    graph.add_entity(
        SIREntity(
            entity_id="ep_low_050",
            entity_type=SIREntityType.ENDPOINT,
            name="GET /health",
            confidence=0.50,
        )
    )
    return graph


def test_threshold_filtering_with_duck_mock_court() -> None:
    graph = _build_mixed_confidence_graph()
    mock_court = _DuckMockCourt()

    judgments = submit_sir_to_court(graph, mock_court, threshold=0.8)

    assert len(judgments) == 2
    assert len(mock_court.received_claims) == 2
    assert all(isinstance(c, Claim) for c in mock_court.received_claims)
    assert all(isinstance(j, CourtJudgment) for j in judgments)

    vuln_classes = {c.vulnerability_class for c in mock_court.received_claims}
    assert vuln_classes == {"SQLI", "XSS"}
    scores = sorted(c.confidence_score for c in mock_court.received_claims)
    assert scores == [0.8, 0.95]


def test_magic_mock_court_receives_claim_directly() -> None:
    graph = _build_mixed_confidence_graph()
    magic_court = MagicMock()
    expected = CourtJudgment(vuln_class="SQLI", verdict=CourtVerdict.INCONCLUSIVE)
    magic_court.adjudicate.return_value = expected

    results = submit_sir_to_court(graph, magic_court, threshold=0.9)

    assert results == [expected]
    magic_court.adjudicate.assert_called_once()
    passed_arg = magic_court.adjudicate.call_args[0][0]
    assert isinstance(passed_arg, Claim)
    assert passed_arg.evidence_id == "sig_sqlm_01"
    assert passed_arg.vulnerability_class == "SQLI"
    assert passed_arg.confidence_score == pytest.approx(0.95)


def test_magic_mock_spec_evidence_court() -> None:
    graph = _build_mixed_confidence_graph()
    spec_court = MagicMock(spec=EvidenceCourt)
    spec_court.adjudicate.return_value = CourtJudgment(vuln_class="SQLI")

    results = submit_sir_to_court(graph, spec_court, threshold=0.9)

    assert len(results) == 1
    spec_court.adjudicate.assert_called_once()
    kwargs = spec_court.adjudicate.call_args.kwargs
    assert kwargs["target_url"] == "https://app.example.com/api/users"
    assert kwargs["parameter"] == "id"
    assert kwargs["vuln_class"] == "SQLI"
    assert kwargs["finder_claim"]["sir_entity_id"] == "sink_high_095"


def test_claim_conversion_fields_and_fallbacks() -> None:
    graph = SIRGraph(target_host="target.local")
    minimal = SIREntity(
        entity_id="ep_get_admin",
        entity_type=SIREntityType.ENDPOINT,
        name="GET /admin",
        confidence=0.88,
    )
    claim = sir_entity_to_claim(minimal, sir_graph=graph)

    assert isinstance(claim, Claim)
    assert claim.claim_id.startswith("CLM-")
    assert claim.evidence_id == "ep_get_admin"
    assert claim.vulnerability_class == "ENDPOINT"
    assert claim.confidence_score == pytest.approx(0.88)
    assert "ep_get_admin" in claim.rationale
    assert "target.local" in claim.rationale
    assert len(claim.provenance_hash_chain) == 16


def test_alternate_graph_with_nodes_list_and_dict() -> None:
    n_high = _AltNode(
        entity_id="n1",
        entity_type="SINK",
        name="SSRF Sink",
        confidence=0.85,
        attributes={"vuln_class": "SSRF"},
        evidence_refs=["ev_1"],
    )
    n_low = _AltNode(
        entity_id="n2",
        entity_type="SINK",
        name="Weak Signal",
        confidence=0.4,
        attributes={"vuln_class": "XSS"},
    )

    court_list = _DuckMockCourt()
    res_list = submit_sir_to_court(_AltNodesGraph([n_high, n_low]), court_list, threshold=0.8)
    assert len(res_list) == 1
    assert court_list.received_claims[0].vulnerability_class == "SSRF"

    court_dict = _DuckMockCourt()
    res_dict = submit_sir_to_court(
        _AltNodesGraph({"n1": n_high, "n2": n_low}), court_dict, threshold=0.8
    )
    assert len(res_dict) == 1
    assert court_dict.received_claims[0].evidence_id == "ev_1"


def test_empty_and_none_graphs_return_empty_list() -> None:
    court = _DuckMockCourt()
    assert submit_sir_to_court(None, court) == []
    assert submit_sir_to_court(SIRGraph(), court) == []
    assert court.received_claims == []


def test_real_evidence_court_end_to_end_unverified_and_confirmed() -> None:
    graph = SIRGraph(target_host="shop.example.com")
    # Unverified high-confidence entity (no verifier_result) -> INCONCLUSIVE (fail-closed)
    graph.add_entity(
        SIREntity(
            entity_id="sink_unverified",
            entity_type=SIREntityType.SINK,
            name="Unverified XSS",
            attributes={"url": "https://shop.example.com/comment", "parameter": "body", "vuln_class": "xss"},
            confidence=0.85,
        )
    )
    # Verified deterministic PoE entity -> CONFIRMED
    graph.add_entity(
        SIREntity(
            entity_id="sink_cmd_confirmed",
            entity_type=SIREntityType.SINK,
            name="Command Injection on /ping",
            attributes={
                "url": "https://shop.example.com/ping",
                "parameter": "host",
                "vuln_class": "command_injection",
                "verifier_result": {"reproduced": True, "confidence": 0.99},
                "proof_payload": {
                    "artifact_type": "command_injection",
                    "probed_expression": "53+19",
                    "expected_result": "72",
                    "response_text": "ping result: 72",
                    "baseline_text": "ping result: 0",
                },
            },
            observed_sources={"ACTIVE_VERIFIER"},
            evidence_refs=["evi_cmd_72"],
            confidence=0.97,
        )
    )
    # Below threshold -> excluded
    graph.add_entity(
        SIREntity(
            entity_id="sink_below_threshold",
            entity_type=SIREntityType.SINK,
            name="Low confidence noise",
            confidence=0.3,
        )
    )

    judgments = submit_sir_to_court(graph, EvidenceCourt, threshold=0.8)

    assert len(judgments) == 2
    assert all(isinstance(j, CourtJudgment) for j in judgments)

    by_param = {j.parameter: j for j in judgments}
    assert by_param["body"].verdict == CourtVerdict.INCONCLUSIVE
    assert by_param["body"].reportable is False

    confirmed = by_param["host"]
    assert confirmed.verdict == CourtVerdict.CONFIRMED
    assert confirmed.reportable is True
    assert confirmed.calibrated_severity == "Critical"
    assert confirmed.target_url == "https://shop.example.com/ping"
    assert confirmed.finder_claim["evidence_id"] == "evi_cmd_72"


def test_real_evidence_court_with_tool_normalizer_sir_relationships() -> None:
    sqlmap_out = (
        "Parameter: user_id (GET)\n"
        "Type: boolean-based blind\n"
        "sqlmap identified the following injection point: parameter 'user_id' is vulnerable\n"
        "back-end DBMS: PostgreSQL\n"
    )
    signals = ToolOutputNormalizer.normalize_sqlmap(
        sqlmap_out, target_url="https://api.example.com/v1/profile?user_id=1"
    )
    graph = ToolOutputNormalizer.ingest_to_sir(signals)

    judgments = submit_sir_to_court(graph, EvidenceCourt, threshold=0.8)

    # Endpoint, Parameter, and Sink each have source_fidelity=0.85
    assert len(judgments) == 3
    assert all(isinstance(j, CourtJudgment) for j in judgments)
    sink_judgments = [j for j in judgments if j.finder_claim.get("sir_entity_type") == "SINK"]
    assert len(sink_judgments) == 1
    assert sink_judgments[0].vuln_class == "SQLI"
    assert sink_judgments[0].target_url == "https://api.example.com/v1/profile"
    assert sink_judgments[0].parameter == "user_id"


def test_court_instances_and_duck_typed_v1_court() -> None:
    graph = _build_mixed_confidence_graph()

    # Real EvidenceCourt instance (not just class)
    inst_results = submit_sir_to_court(graph, EvidenceCourt(), threshold=0.9)
    assert len(inst_results) == 1
    assert isinstance(inst_results[0], CourtJudgment)

    # Real EvidenceCourtV2 instance
    v2_inst_results = submit_sir_to_court(graph, EvidenceCourtV2(), threshold=0.9)
    assert len(v2_inst_results) == 1
    assert isinstance(v2_inst_results[0], CourtJudgment)

    # Duck-typed multi-arg court mimicking EvidenceCourt.adjudicate
    class _DuckV1Court:
        def __init__(self) -> None:
            self.calls: List[Dict[str, Any]] = []

        def adjudicate(self, target_url: str, parameter: str, vuln_class: str, finder_claim=None):
            self.calls.append(
                {
                    "target_url": target_url,
                    "parameter": parameter,
                    "vuln_class": vuln_class,
                    "finder_claim": finder_claim,
                }
            )
            return CourtJudgment(target_url=target_url, parameter=parameter, vuln_class=vuln_class)

    duck_v1 = _DuckV1Court()
    duck_results = submit_sir_to_court(graph, duck_v1, threshold=0.9)
    assert len(duck_results) == 1
    assert duck_v1.calls[0]["target_url"] == "https://app.example.com/api/users"
    assert duck_v1.calls[0]["parameter"] == "id"
    assert duck_v1.calls[0]["vuln_class"] == "SQLI"


def test_real_evidence_court_v2_end_to_end() -> None:
    graph = SIRGraph(target_host="v2.example.com")
    graph.add_entity(
        SIREntity(
            entity_id="sink_v2_confirmed",
            entity_type=SIREntityType.SINK,
            name="CMD Injection",
            attributes={
                "url": "https://v2.example.com/exec",
                "parameter": "cmd",
                "vuln_class": "command_injection",
                "reproduced": True,
                "reproductions_count": 2,
                "causal_chain_verified": True,
                "proof_payload": {
                    "artifact_type": "command_injection",
                    "probed_expression": "53+19",
                    "expected_result": "72",
                    "response_text": "out=72",
                    "baseline_text": "out=0",
                },
            },
            confidence=0.95,
        )
    )

    judgments = submit_sir_to_court(graph, EvidenceCourtV2, threshold=0.8)

    assert len(judgments) == 1
    assert isinstance(judgments[0], CourtJudgment)
    assert judgments[0].verdict == CourtVerdict.CONFIRMED
    assert judgments[0].reportable is True
    assert judgments[0].target_url == "https://v2.example.com/exec"
