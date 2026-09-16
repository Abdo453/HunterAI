"""
HunterAI V22.0 Test Suite — The Autonomous Epistemic Investigation Triad
========================================================================
Certifies the 3 Core Architectural Pillars:
1. Unified Tool Output Normalizer (Subfinder, Httpx, Katana, Nuclei, FFUF, Sqlmap, Dalfox)
2. Normalization & Ingestion into Canonical SIR Graph (Endpoints, Parameters, Sinks)
3. Advanced Contradiction Engine & Conflict Resolver (Tool vs Wire Truth)
4. Counterfactual Probe Synthesis & Dispute Adjudication
5. Automatic Negative Knowledge Base Registration on Refutation
6. Active Information-Gain Scheduler & Priority Queue Optimization (ΔI / Cost)
7. AutonomousBrain V22.0 Triad Subsystems Attachment
8. Unified CLI Command Interface (normalize, schedule, resolve-conflict)
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from core.compiler.security_ir import SIRGraph, SIREntityType
from core.evidence.evidence_level import EvidenceLevel
from core.normalizer import ToolOutputNormalizer, NormalizedSecuritySignal
from core.reasoning import (
    ContradictionResolver,
    ConflictCase,
    ConflictType,
    ConflictVerdict,
    ResolutionRuling,
)
from core.optimization import (
    InformationGainScheduler,
    ScheduledInspectionTarget,
)
from core.memory.negative_knowledge_base import NegativeKnowledgeBase
from core.brain.autonomous_brain import AutonomousBrain
from cli.hunter_cli import build_parser


class TestToolOutputNormalizer:
    """Tests 1 - 6: Ingestion of external tool outputs into Canonical SIR"""

    def test_subfinder_normalization(self):
        raw = "api.corp.local\nauth.corp.local\n# comment\ninternal.corp.local\n"
        signals = ToolOutputNormalizer.normalize_subfinder(raw, target_domain="corp.local")
        assert len(signals) == 3
        assert signals[0].source_tool == "subfinder"
        assert signals[0].initial_evidence_level == EvidenceLevel.E0_OBSERVATION
        assert signals[0].asset == "api.corp.local"

    def test_httpx_normalization(self):
        raw = (
            '{"url":"https://api.corp.local/v1/health","status_code":200,"title":"Health API","technologies":["Express","Node.js"]}\n'
            '{"url":"https://api.corp.local/v1/docs","status_code":403,"title":"Swagger UI","technologies":["Swagger"]}\n'
        )
        signals = ToolOutputNormalizer.normalize_httpx(raw)
        assert len(signals) == 2
        assert signals[0].source_tool == "httpx"
        assert signals[0].endpoint == "/v1/health"
        assert signals[0].raw_evidence["status_code"] == 200
        assert "Express" in signals[0].raw_evidence["technologies"]

    def test_katana_crawler_normalization(self):
        raw = (
            '{"request":{"endpoint":"https://shop.local/api/items?cat=books&sort=desc","method":"GET"}}\n'
            'https://shop.local/api/cart/add\n'
        )
        signals = ToolOutputNormalizer.normalize_katana(raw)
        assert len(signals) == 2
        assert signals[0].source_tool == "katana"
        assert signals[0].endpoint == "/api/items"
        assert signals[0].parameter == "cat"
        assert signals[1].endpoint == "/api/cart/add"

    def test_nuclei_vulnerability_normalization(self):
        raw = json.dumps([
            {
                "template-id": "cwe-89-sqli-error",
                "info": {"name": "SQL Injection in Search", "severity": "high"},
                "matched-at": "https://api.local/search?q=test",
                "curl-command": "curl 'https://api.local/search?q=test'",
            },
            {
                "template-id": "cwe-639-bola-basket",
                "info": {"name": "BOLA on Cart ID", "severity": "critical"},
                "matched-at": "https://api.local/cart/42",
            }
        ])
        signals = ToolOutputNormalizer.normalize_nuclei(raw)
        assert len(signals) == 2
        assert signals[0].signal_type == "SQLI"
        assert signals[0].initial_evidence_level == EvidenceLevel.E1_DIFFERENTIAL_SIGNAL
        assert signals[0].source_fidelity == 0.55  # Requires corroboration
        assert signals[1].signal_type == "BOLA"

    def test_sqlmap_and_fuzzers_normalization(self):
        sqlmap_raw = (
            "GET parameter 'user_id' is vulnerable.\n"
            "Type: boolean-based blind\n"
            "back-end DBMS: MySQL >= 8.0\n"
        )
        signals = ToolOutputNormalizer.normalize_sqlmap(sqlmap_raw, target_url="https://api.local/users?user_id=1")
        assert len(signals) == 1
        assert signals[0].source_tool == "sqlmap"
        assert signals[0].signal_type == "SQLI"
        assert signals[0].parameter == "user_id"
        assert signals[0].initial_evidence_level == EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR

        ffuf_raw = json.dumps({
            "results": [
                {"url": "https://api.local/admin", "status": 403, "words": 12},
                {"url": "https://api.local/metrics", "status": 200, "words": 405}
            ]
        })
        ffuf_sigs = ToolOutputNormalizer.normalize_ffuf(ffuf_raw)
        assert len(ffuf_sigs) == 2
        assert ffuf_sigs[0].endpoint == "/admin"

        dalfox_raw = '{"url":"https://api.local/view?msg=test","param":"msg","poc":"<script>alert(1)</script>","evidence":"reflected"}\n'
        dalfox_sigs = ToolOutputNormalizer.normalize_dalfox(dalfox_raw)
        assert len(dalfox_sigs) == 1
        assert dalfox_sigs[0].signal_type == "XSS"

    def test_ingest_normalized_signals_into_sir_graph(self):
        signals = [
            NormalizedSecuritySignal(
                signal_id="sig_01",
                source_tool="katana",
                source_fidelity=0.9,
                initial_evidence_level=EvidenceLevel.E0_OBSERVATION,
                entity_type=SIREntityType.ENDPOINT,
                asset="api.local",
                endpoint="/api/v1/users",
                method="GET",
                parameter="id",
                signal_type="CRAWLED_ENDPOINT",
            ),
            NormalizedSecuritySignal(
                signal_id="sig_02",
                source_tool="nuclei",
                source_fidelity=0.55,
                initial_evidence_level=EvidenceLevel.E1_DIFFERENTIAL_SIGNAL,
                entity_type=SIREntityType.ENDPOINT,
                asset="api.local",
                endpoint="/api/v1/users",
                method="GET",
                parameter="id",
                signal_type="BOLA",
            )
        ]
        graph = ToolOutputNormalizer.ingest_to_sir(signals)
        assert len(graph.entities) >= 3  # Endpoint + Parameter + SINK
        endpoints = graph.get_endpoints()
        assert len(endpoints) == 1
        assert "KATANA" in endpoints[0].observed_sources
        assert "NUCLEI" in endpoints[0].observed_sources

        sinks = graph.find_by_type(SIREntityType.SINK)
        assert len(sinks) == 1
        assert sinks[0].attributes["vuln_class"] == "BOLA"


class TestContradictionResolver:
    """Tests 7 - 9: Tool vs Wire Reality Conflict Detection and Adjudication"""

    def test_detect_conflict_nuclei_vs_burp_wire(self):
        resolver = ContradictionResolver()
        claim = {
            "source_tool": "nuclei",
            "signal_type": "BOLA",
            "endpoint": "/api/v1/invoices/100",
        }
        wire_telemetry = {
            "status_code": 403,
            "body": "Access Denied: Forbidden by Tenant Isolation Policy",
        }
        conflict = resolver.detect_conflict(claim, wire_telemetry=wire_telemetry)
        assert conflict is not None
        assert conflict.conflict_type == ConflictType.DEFENSIVE_CONTROL_ACTIVE
        assert conflict.counter_source == "BURP_WIRE_SENSOR"

    def test_resolve_conflict_refuted_saves_to_negative_kb(self):
        kb = NegativeKnowledgeBase()
        resolver = ContradictionResolver(negative_kb=kb)
        conflict = ConflictCase(
            conflict_id="cnf_test_01",
            target_endpoint="/api/v1/checkout",
            claimed_vuln="SQLI",
            claimant_source="nuclei",
            counter_source="BURP_WIRE_SENSOR",
            conflict_type=ConflictType.DEFENSIVE_CONTROL_ACTIVE,
            claim_evidence={},
            counter_evidence={"status_code": 400},
            recommended_probe="Arithmetic nonce test"
        )
        # Retest verifies server returned 400 and rejected syntax corruption
        retest_res = {"status_code": 400, "defensive_control_verified": True}
        ruling = resolver.adjudicate_conflict(conflict, retest_res)

        assert ruling.verdict == ConflictVerdict.REFUTED_DEFENSIVE_CONTROL_ACTIVE
        assert ruling.confidence == 1.0
        assert ruling.recorded_negative_kb is True
        assert kb.count() >= 1
        assert kb.has_negative_proof("/api/v1/checkout", "GET", "SQLI")

    def test_resolve_conflict_confirmed_when_defensive_control_fails(self):
        resolver = ContradictionResolver()
        conflict = ConflictCase(
            conflict_id="cnf_test_02",
            target_endpoint="/api/v1/users/42",
            claimed_vuln="BOLA",
            claimant_source="nuclei",
            counter_source="BURP_WIRE_SENSOR",
            conflict_type=ConflictType.DEFENSIVE_CONTROL_ACTIVE,
            claim_evidence={},
            counter_evidence={},
            recommended_probe="Cross-tenant token replay"
        )
        # Controlled re-test bypassed the check and confirmed invariant violation
        retest_res = {
            "invariant_violated": True,
            "defensive_control_verified": False,
            "proof": "Cross-tenant access confirmed for User B"
        }
        ruling = resolver.adjudicate_conflict(conflict, retest_res)
        assert ruling.verdict == ConflictVerdict.CONFIRMED_VULN
        assert ruling.evidence_level_awarded == EvidenceLevel.E3_INVARIANT_VIOLATION


class TestInformationGainScheduler:
    """Test 10: Mathematical Information-Gain Prioritization (ΔI / Cost)"""

    def test_information_gain_ranking(self):
        scheduler = InformationGainScheduler()
        endpoints = [
            {"path": "/static/about.html", "method": "GET", "auth_required": False, "params": []},
            {"path": "/api/v1/users/42", "method": "GET", "auth_required": True, "params": ["id"]},
            {"path": "/api/v1/orders/99", "method": "DELETE", "auth_required": True, "params": ["id"]},
            {"path": "/api/search", "method": "GET", "auth_required": False, "params": ["q"]},
        ]
        ranked = scheduler.schedule_inspection(endpoints, asset="app.local")
        assert len(ranked) == 4

        # Rank 1 must be high-entropy mutating / authenticated object path
        assert ranked[0].priority_rank == 1
        assert ranked[0].efficiency_score > ranked[-1].efficiency_score

        # Static about page must be ranked last with lowest score
        assert ranked[-1].path == "/static/about.html"
        assert ranked[-1].efficiency_score <= 1.0


class TestAutonomousBrainAndCliV22:
    """Tests 11 & 12: AutonomousBrain Integration & CLI Parsers"""

    def test_brain_v22_investigation_triad_attached(self):
        brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
        assert hasattr(brain, "tool_normalizer")
        assert brain.tool_normalizer is not None
        assert hasattr(brain, "contradiction_resolver")
        assert brain.contradiction_resolver is not None
        assert hasattr(brain, "info_gain_scheduler")
        assert brain.info_gain_scheduler is not None

    def test_cli_v22_subcommands_parsed(self):
        parser = build_parser()

        # Normalize command
        parsed_norm = parser.parse_args(["normalize", "--tool", "nuclei", "--demo", "--json"])
        assert parsed_norm.command == "normalize"
        assert parsed_norm.tool == "nuclei"
        assert parsed_norm.demo is True
        assert parsed_norm.json is True

        # Schedule command
        parsed_sch = parser.parse_args(["schedule", "--domain", "api.corp.local", "--demo"])
        assert parsed_sch.command == "schedule"
        assert parsed_sch.domain == "api.corp.local"
        assert parsed_sch.demo is True

        # Resolve conflict command
        parsed_res = parser.parse_args(["resolve-conflict", "--demo"])
        assert parsed_res.command == "resolve-conflict"
        assert parsed_res.demo is True