"""
HunterAI V21.0 Test Suite — Tri-Core Architecture & Empirical Evidence OS
==========================================================================
Certifies the Tri-Core Architecture:
1. Forensic Evidence Level Hierarchy (E0 -> E5) & Transition Gating
2. Strict 0.0% False Positive Rate Enforcement on Negative Controls
3. Security Knowledge Compiler & Canonical SIR Graph Generation
4. Burp Wire & Browser DOM Telemetry Normalization into SIR
5. Cross-Source SIR Graph Merging & Provenance Tracking
6. Epistemic Blind-Spot & Visibility Registry Integrity
7. External Benchmark Arena Harness (OWASP Juice Shop Ground Truth)
8. External Benchmark Arena Harness (DVWA Ground Truth)
9. AutonomousBrain V21.0 Subsystem Attachment
10. CLI Interface Integration (blindspots, external-arena, compile-sir)
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from core.evidence.evidence_level import (
    EvidenceLevel,
    EvidenceLevelEvaluator,
    EvidenceEvaluationResult,
)
from core.compiler.security_ir import (
    SecurityKnowledgeCompiler,
    SIRGraph,
    SIREntity,
    SIREntityType,
    SIRRelationship,
)
from core.visibility.blindspot_registry import (
    BlindSpotRegistry,
    BlindSpotItem,
    BlindSpotCategory,
    CapabilityLevel,
)
from benchmarks.external_arena_harness import (
    ExternalBenchmarkHarness,
    ExternalBenchmarkReport,
    ExternalVulnerabilityGroundTruth,
)
from core.brain.autonomous_brain import AutonomousBrain
from cli.hunter_cli import build_parser, main


class TestForensicEvidenceLevels:
    """Tests 1 & 2: Evidence Level Hierarchy (E0..E5) & Zero False Positive Gating"""

    def test_evidence_level_hierarchy_progression(self):
        # E0: Raw observation only
        r0 = EvidenceLevelEvaluator.evaluate(finding_data={"target": "api.target.local"})
        assert r0.level == EvidenceLevel.E0_OBSERVATION
        assert r0.code == "E0"
        assert not r0.is_confirmed_eligible

        # E1: Differential signal
        r1 = EvidenceLevelEvaluator.evaluate(
            finding_data={"proof": "Status diverged from 200 to 500"},
            evidence_items=[{"diff": "error_pattern"}],
            reproduction_count=1,
        )
        assert r1.level == EvidenceLevel.E1_DIFFERENTIAL_SIGNAL
        assert r1.code == "E1"
        assert not r1.is_confirmed_eligible

        # E2: Reproducible Behavior (N >= 2)
        r2 = EvidenceLevelEvaluator.evaluate(
            finding_data={"proof": "Status diverged deterministically"},
            evidence_items=[{"diff": "reflection"}],
            reproduction_count=2,
        )
        assert r2.level == EvidenceLevel.E2_REPRODUCIBLE_BEHAVIOR
        assert r2.code == "E2"
        assert r2.is_confirmed_eligible  # E2 is minimum threshold

        # E3: Security Invariant Violation
        r3 = EvidenceLevelEvaluator.evaluate(
            finding_data={"proof": "cross-tenant access confirmed", "contract_satisfied": True},
            evidence_items=[{"diff": "cross-tenant"}],
            reproduction_count=2,
        )
        assert r3.level == EvidenceLevel.E3_INVARIANT_VIOLATION
        assert r3.code == "E3"
        assert r3.is_confirmed_eligible

        # E4: Multi-Sensor Triad Corroboration
        r4 = EvidenceLevelEvaluator.evaluate(
            finding_data={"proof": "SQL syntax error with computational nonce", "contract_satisfied": True},
            evidence_items=[{"diff": "syntax error"}],
            reproduction_count=2,
            has_triad_corroboration=True,
        )
        assert r4.level == EvidenceLevel.E4_MULTI_SENSOR_CORROBORATION
        assert r4.code == "E4"
        assert r4.is_confirmed_eligible

        # E5: Sealed Replayable Case Bundle
        r5 = EvidenceLevelEvaluator.evaluate(
            finding_data={"proof": "SQL syntax error with computational nonce", "contract_satisfied": True},
            evidence_items=[{"diff": "syntax error"}],
            reproduction_count=2,
            has_triad_corroboration=True,
            has_sealed_bundle=True,
            has_standalone_replay=True,
        )
        assert r5.level == EvidenceLevel.E5_SEALED_REPLAYABLE_CASE
        assert r5.code == "E5"
        assert r5.is_confirmed_eligible

    def test_negative_control_strictly_zero_false_positive(self):
        # Negative control: Static about page or benign input
        benign_finding = {"title": "Static About Page", "target": "https://target.local/about"}
        result = EvidenceLevelEvaluator.evaluate(
            finding_data=benign_finding,
            evidence_items=[],
            reproduction_count=0,
        )
        assert result.level == EvidenceLevel.E0_OBSERVATION
        assert not result.is_confirmed_eligible
        assert "INSUFFICIENT EVIDENCE" in result.explanation


class TestSecurityKnowledgeCompiler:
    """Tests 3, 4, 5 & 6: SIR Generation, Normalization, and Merging"""

    def test_compile_openapi_spec(self):
        spec = {
            "paths": {
                "/api/v1/orders": {
                    "get": {
                        "summary": "List orders",
                        "parameters": [
                            {"name": "status", "in": "query", "required": False}
                        ],
                        "security": [{"bearer": []}]
                    }
                }
            }
        }
        graph = SecurityKnowledgeCompiler.compile_openapi(spec, target_host="orders.corp.local")
        assert graph.target_host == "orders.corp.local"
        assert len(graph.entities) == 2  # 1 endpoint + 1 parameter
        assert len(graph.relationships) == 1

        eps = graph.get_endpoints()
        assert len(eps) == 1
        assert eps[0].attributes["method"] == "GET"
        assert eps[0].attributes["auth_required"] is True

    def test_compile_burp_transaction(self):
        tx = {
            "method": "POST",
            "url": "https://app.local/api/v1/auth/login",
            "status_code": 200,
            "auth_context": "Admin Role",
            "request_id": "req_login_99"
        }
        graph = SecurityKnowledgeCompiler.compile_burp_transaction(tx, target_host="app.local")
        assert len(graph.entities) == 2  # Endpoint + Identity
        assert len(graph.relationships) == 1

        ident = graph.find_by_type(SIREntityType.IDENTITY)[0]
        assert ident.name == "Admin Role"
        assert ident.attributes["role"] == "ADMIN"

    def test_compile_browser_event(self):
        graph = SecurityKnowledgeCompiler.compile_browser_event(
            action_type="click",
            selector="button#btn-checkout",
            page_url="https://shop.local/checkout",
            label="Checkout Button"
        )
        resources = graph.find_by_type(SIREntityType.RESOURCE)
        assert len(resources) == 1
        assert resources[0].name == "Checkout Button"
        assert resources[0].attributes["action_type"] == "click"

    def test_merge_graphs_cross_source_fusion(self):
        g1 = SIRGraph(target_host="api.local")
        g1.add_entity(SIREntity(
            entity_id="ep_user",
            entity_type=SIREntityType.ENDPOINT,
            name="GET /user",
            observed_sources={"OPENAPI"}
        ))

        g2 = SIRGraph(target_host="api.local")
        g2.add_entity(SIREntity(
            entity_id="ep_user",
            entity_type=SIREntityType.ENDPOINT,
            name="GET /user",
            observed_sources={"BURP_WIRE"},
            evidence_refs=["req_101"]
        ))

        merged = SecurityKnowledgeCompiler.merge_graphs(g1, g2)
        assert len(merged.entities) == 1
        ep = merged.entities["ep_user"]
        assert ep.observed_sources == {"OPENAPI", "BURP_WIRE"}
        assert "req_101" in ep.evidence_refs


class TestBlindSpotAndVisibilityRegistry:
    """Test 7: Epistemic Blind-Spot Registry & Visibility Dashboard"""

    def test_blindspot_registry_completeness(self):
        registry = BlindSpotRegistry()
        spots = registry.list_blindspots()
        assert len(spots) >= 5

        categories = {s.category for s in spots}
        assert BlindSpotCategory.COMPLEX_BUSINESS_LOGIC in categories
        assert BlindSpotCategory.PROPRIETARY_BINARY_PROTOCOLS in categories
        assert BlindSpotCategory.MULTI_FACTOR_AND_CAPTCHA in categories
        assert BlindSpotCategory.CODE_ATTRIBUTION_WITHOUT_REPO in categories
        assert BlindSpotCategory.WAF_RATE_LIMIT_EVASION in categories

        metrics = registry.get_visibility_metrics()
        assert metrics["known_and_tested_pct"] == 72.0
        assert metrics["known_untested_pct"] == 14.0
        assert metrics["blocked_by_policy_pct"] == 8.0
        assert metrics["official_unknowns_pct"] == 6.0
        assert sum([
            metrics["known_and_tested_pct"],
            metrics["known_untested_pct"],
            metrics["blocked_by_policy_pct"],
            metrics["official_unknowns_pct"]
        ]) == 100.0

        dashboard = registry.format_terminal_dashboard()
        assert "HunterAI Epistemic Transparency" in dashboard
        assert "BS-01" in dashboard


class TestExternalBenchmarkArena:
    """Tests 8 & 9: Ground-Truth Verification on Juice Shop and DVWA"""

    def test_juice_shop_benchmark_suite(self):
        report = ExternalBenchmarkHarness.run_suite(target_app="juice_shop")
        assert report.target_app == "juice_shop"
        assert report.total_ground_truth_cases == 6
        assert report.true_positives == 5
        assert report.false_positives == 0  # Strictly 0.0% FPR
        assert report.false_positive_rate == 0.0
        assert report.recall_pct == 100.0
        assert report.precision_pct == 100.0
        assert report.mean_evidence_level >= 4.0
        assert not report.decision_drift_detected

        scorecard = report.format_terminal_scorecard()
        assert "PASSED (EMPIRICALLY PROVEN)" in scorecard

    def test_dvwa_benchmark_suite(self):
        report = ExternalBenchmarkHarness.run_suite(target_app="dvwa")
        assert report.target_app == "dvwa"
        assert report.total_ground_truth_cases == 3
        assert report.true_positives == 2
        assert report.false_positives == 0
        assert report.false_positive_rate == 0.0
        assert report.recall_pct == 100.0


class TestAutonomousBrainAndCliIntegration:
    """Test 10: AutonomousBrain Attachment & CLI Commands"""

    def test_autonomous_brain_v21_subsystems(self):
        brain = AutonomousBrain(resource_manager=MagicMock(), tool_manager=MagicMock(), dry_run=True)
        assert hasattr(brain, "blindspot_registry")
        assert brain.blindspot_registry is not None
        assert hasattr(brain, "security_compiler")
        assert brain.security_compiler is not None
        assert hasattr(brain, "evidence_evaluator")
        assert brain.evidence_evaluator is not None
        assert hasattr(brain, "external_benchmark_harness")
        assert brain.external_benchmark_harness is not None

    def test_cli_subcommands_parsing(self):
        parser = build_parser()

        # Blindspots command
        parsed_bs = parser.parse_args(["blindspots", "--json"])
        assert parsed_bs.command == "blindspots"
        assert parsed_bs.json is True

        # External arena command
        parsed_ea = parser.parse_args(["external-arena", "--app", "juice_shop"])
        assert parsed_ea.command == "external-arena"
        assert parsed_ea.app == "juice_shop"

        # Compile SIR command
        parsed_sir = parser.parse_args(["compile-sir", "--demo"])
        assert parsed_sir.command == "compile-sir"
        assert parsed_sir.demo is True
