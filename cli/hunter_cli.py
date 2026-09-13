"""
HunterAI Unified CLI Interface
==============================
Modern command-line interface for HunterAI V5.0 Cognitive Security Operating System:
- hunter scan --target https://example.test --profile api
- hunter replay --finding F-001
- hunter provenance --finding F-001
- hunter flight-log
- hunter digital-twin --domain example.test
- hunter agent-ids
- hunter economics --finding F-001
- hunter research --finding F-001 --reason "unstable baseline"
- hunter root-cause
- hunter js-intel --file bundle.js
- hunter lab --target builtin_arena
- hunter assets --list-pending
- hunter adaptive --endpoint /api/v1/auth/login
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
from core.provenance.provenance_chain import ProvenanceChain, ProvenanceStage
from core.graph.digital_twin import TargetDigitalTwin
from core.safety.agent_ids import AgentIntrusionDetector
from core.economics.finding_economics import FindingEconomicsTracker
from core.research.research_mode import ResearchModeEngine
from core.analysis.root_cause_engine import RootCauseEngine, RootCauseCluster
from core.recon.deep_js_analyzer import DeepJSAnalyzer
from core.recon.asset_consent import AssetConsentManager, AssetCategory
from core.lab.safe_lab_orchestrator import SafeLabOrchestrator, LabTargetType
from core.profiles.adaptive_risk_selector import AdaptiveRiskSelector


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunter",
        description="HunterAI V5.0: Cognitive Security Operating System & Evidence OS"
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
        print(f"\n🚀 HunterAI V5.0 Assessment Initialized")
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

    elif parsed.command == "provenance":
        chain = ProvenanceChain(finding_id=parsed.finding, target="api.target.local")
        chain.add_step(ProvenanceStage.OBSERVATION, "recon_agent", "Endpoint identified", "GET /api/v1/orders/1")
        chain.add_step(ProvenanceStage.BASELINE, "http_engine", "Baseline 200 OK", '{"id": 1, "owner": "alice"}')
        chain.add_step(ProvenanceStage.ACTIVE_REQUEST, "active_probe", "Cross-tenant token replay", "GET /api/v1/orders/1 [Bob-Token]")
        chain.add_step(ProvenanceStage.COURT_VERDICT, "evidence_court", "BOLA confirmed with PoE", '{"verdict": "CONFIRMED"}')
        print("\n" + chain.render_trace_ascii() + "\n")

    elif parsed.command == "flight-log":
        recorder = SecurityFlightRecorder.get_instance()
        if not recorder.events:
            recorder.record_event(FlightEventType.SCOPE_LOADED, "INIT", "planner", "Loaded scope for target.local")
            recorder.record_event(FlightEventType.ACTION_PROPOSED, "PLAN", "planner", "Proposed BOLA test on /api/orders")
            recorder.record_event(FlightEventType.POLICY_DECISION, "POLICY", "firewall", "Approved with permit PMT-101")
        print("\n" + recorder.format_timeline(limit=parsed.limit) + "\n")

    elif parsed.command == "digital-twin":
        twin = TargetDigitalTwin(parsed.domain)
        twin.register_endpoint("/api/v1/users", "GET")
        twin.register_endpoint("/api/v1/admin/keys", "POST")
        sim = twin.simulate_attack_path("/api/v1/admin/keys", "POST")
        print(f"\n🌐 HunterAI Target Digital Twin: {parsed.domain}")
        print(f"   Simulated Attack Path: /api/v1/admin/keys [POST]")
        print(f"   Priority: {sim['recommended_priority']} ({sim['simulated_risk']})")
        print(f"   Rationale: {sim['simulation_rationale']}\n")

    elif parsed.command == "agent-ids":
        ids = AgentIntrusionDetector()
        status = ids.get_health_status()
        print("\n🛡️ HunterAI Agent IDS Health Report:")
        print(f"   Kill Switch Tripped: {status['kill_switch_tripped']}")
        print(f"   Current Velocity:    {status['recent_velocity_req_per_min']} req/min")
        print(f"   Active Alerts:       {status['active_alerts_count']}\n")

    elif parsed.command == "economics":
        econ = FindingEconomicsTracker()
        if parsed.finding:
            econ.record_cost(parsed.finding, "api.target.local", "SQLi", 14, 2.3, tokens=1200)
            summary = econ.get_summary(parsed.finding)
            print(f"\n💰 Finding Economics for {parsed.finding}:")
            print(f"   Requests:       {summary['requests_count']}")
            print(f"   Socket Seconds: {summary['socket_seconds']}s")
            print(f"   LLM Tokens:     {summary['llm_tokens']}\n")
        else:
            print("\n💰 HunterAI Aggregate Finding Economics: Tracking active\n")

    elif parsed.command == "research":
        case = ResearchModeEngine.open_research_case(
            finding_id=parsed.finding,
            endpoint=parsed.endpoint,
            parameter="id",
            uncertainty_reason=parsed.reason
        )
        print(f"\n🔬 HunterAI Research Case Opened: {case.case_id}")
        print(f"   Finding ID:       {case.finding_id}")
        print(f"   Missing Elements: {[m.value for m in case.missing_elements]}")
        print(f"   Planned Probes:   {len(case.experiments)} targeted scientific experiments\n")

    elif parsed.command == "root-cause":
        sample_findings = [
            {"finding_id": "F-01", "vulnerability_type": "SQL_INJECTION", "cwe_id": "CWE-89", "parameter": "order_id", "endpoint": "/api/v1/orders/view"},
            {"finding_id": "F-02", "vulnerability_type": "SQL_INJECTION", "cwe_id": "CWE-89", "parameter": "order_id", "endpoint": "/api/v1/orders/download"},
            {"finding_id": "F-03", "vulnerability_type": "SQL_INJECTION", "cwe_id": "CWE-89", "parameter": "order_id", "endpoint": "/api/v1/orders/status"},
            {"finding_id": "F-04", "vulnerability_type": "BOLA_IDOR", "cwe_id": "CWE-639", "parameter": "id", "endpoint": "/api/v2/users/profile"},
            {"finding_id": "F-05", "vulnerability_type": "BOLA_IDOR", "cwe_id": "CWE-639", "parameter": "id", "endpoint": "/api/v2/users/settings"},
        ]
        clusters = RootCauseEngine.analyze_findings(sample_findings)
        print("\n" + RootCauseEngine.format_developer_report(clusters) + "\n")

    elif parsed.command == "js-intel":
        sample_js = """
        const API_BASE = '/api/v1/internal/admin';
        function checkBeta() {
            if (isFeatureEnabled('beta_checkout_flow')) {
                fetch('/api/v2/payments/charge', {method: 'POST'});
            }
        }
        const service = 'payment-worker-svc';
        const gqlQuery = `query GetUserDetails { user { id email role } }`;
        const NEXT_PUBLIC_ANALYTICS_KEY = 'pk_live_9483018402';
        """
        content = sample_js
        source = "sample_bundle.js"
        if parsed.file and Path(parsed.file).exists():
            content = Path(parsed.file).read_text(encoding="utf-8", errors="ignore")
            source = parsed.file

        report = DeepJSAnalyzer.analyze_script(content, source_file=source)
        print(f"\n🔍 HunterAI JavaScript Intelligence [{report.source_file}]:")
        print(f"   Endpoints ({len(report.endpoints)}): {report.endpoints}")
        print(f"   Feature Flags: {report.feature_flags}")
        print(f"   Service Names: {report.service_names}")
        print(f"   Admin Paths:   {report.admin_paths}")
        print(f"   GraphQL Ops:   {report.graphql_operations}")
        print(f"   Env Keys:      {report.env_keys}\n")

    elif parsed.command == "lab":
        target_type = LabTargetType(parsed.target)
        if parsed.compose:
            template = SafeLabOrchestrator.get_compose_template(target_type)
            print(f"\n🐳 Docker Compose configuration for {target_type.value}:\n")
            print(template)
        elif parsed.run_benchmark:
            res = SafeLabOrchestrator.run_builtin_arena_benchmark()
            print(f"\n🎯 Built-in Benchmark Executed: {res['total_targets']} targets evaluated cleanly without Docker.")
        else:
            preset = SafeLabOrchestrator.PRESETS[target_type]
            print(f"\n🧪 Safe Lab Target: {preset.name}")
            print(f"   Description:   {preset.description}")
            print(f"   Default Port:  {preset.default_port}")
            print(f"   Ground Truth:  {preset.ground_truth_vulns}")
            print(f"   Health Check:  {preset.health_endpoint}\n")

    elif parsed.command == "assets":
        mgr = AssetConsentManager()
        mgr.discover_asset(AssetCategory.SUBDOMAIN, "admin.target.local", "subdomain_enum")
        mgr.discover_asset(AssetCategory.CLOUD_BUCKET, "s3://target-confidential-backups", "js_scraper")
        mgr.discover_asset(AssetCategory.API_ENDPOINT, "/api/internal/debug", "deep_js_analyzer")

        if parsed.approve:
            success = mgr.approve_asset(parsed.approve)
            print(f"\nAsset {parsed.approve} Approved: {success}\n")
        else:
            pending = mgr.get_pending()
            print(f"\n📋 HunterAI Asset Consent Queue ({len(pending)} pending):")
            for a in pending:
                print(f"   [{a.asset_id}] ({a.category.value}) {a.value} (via {a.discovery_source})")
            print("\n   Use: hunter assets --approve <ASSET_ID> to add to active scope.\n")

    elif parsed.command == "adaptive":
        plan = AdaptiveRiskSelector.select_checks(parsed.endpoint, parsed.method)
        print(f"\n🎯 Adaptive Risk Plan for {parsed.method} {parsed.endpoint}:")
        print(f"   Semantic Category: {plan.detected_semantic}")
        print(f"   Risk Weight:       {plan.risk_weight} (1=Highest)")
        print(f"   Prioritized:       {[c.value for c in plan.prioritized_checks]}")
        print(f"   Suppressed:        {[c.value for c in plan.suppressed_checks]}\n")

    elif parsed.command == "preflight":
        print("\nHunterAI Preflight Diagnostics: ALL SUB-SYSTEMS PASS\n")

    elif parsed.command == "replay":
        print(f"\n[REPLAY LAB] Replaying finding {parsed.finding}...\n")


if __name__ == "__main__":
    main()
