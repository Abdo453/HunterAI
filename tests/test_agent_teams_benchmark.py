"""
HunterAI Multi-Agent Teams Benchmark & Rigorous Negative Verification Suite
===========================================================================
Validates:
  1. Accuracy Benchmark across all 5 specialized agent squads
  2. Negative Cases & Counterexamples (Command syntax echo, HTTP jitter, WAF error pages)
  3. Strict Anti-Self-Grading invariants
  4. Full Causal Pipeline: Recon -> Web -> API -> JS -> Verification -> EvidenceCourt
  5. Honest Coverage Ledger accounting (Discovered, Analyzed, Untestable, Blindspots)
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.contracts import (
    AgentTeam,
    EvidenceSignificance,
    TaskContract,
    TaskLifecycleStatus,
)
from core.coverage import AssetType, CoverageLedger, UntestableReason
from core.system.task_scheduler import TaskScheduler
from core.teams import (
    APIDiscoveryAgent,
    APIReviewAgent,
    AssetDiscoveryAgent,
    CausalVerificationAgent,
    ContentDiscoveryAgent,
    CounterexampleAgent,
    DNSIntelligenceAgent,
    EvidenceCourtReviewer,
    HTTPAnalysisAgent,
    JSReviewAgent,
    NetworkDiscoveryAgent,
    NetworkReviewAgent,
    ParameterIntelligenceAgent,
    ReconReviewAgent,
    ReproductionAgent,
    RouteExtractionAgent,
    SecretTriageAgent,
    ServiceAnalysisAgent,
    WebReviewAgent,
)


def run_benchmark():
    print("\n" + "=" * 70)
    print(" HUNTERAI MULTI-AGENT TEAMS BENCHMARK & NEGATIVE VERIFICATION")
    print("=" * 70 + "\n")

    ledger = CoverageLedger(persistence_file="data/benchmark_coverage_ledger.json")
    sched = TaskScheduler(
        tasks_file="config/tasks_benchmark.json",
        logs_dir="task_logs",
        state_file="data/benchmark_sched_state.json",
    )

    passed = 0
    failed = 0

    def check(name: str, fn):
        nonlocal passed, failed
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {name}: {type(e).__name__} -> {e}")
            failed += 1

    # ── Test 1: Recon Team Accuracy & Ledger Ingestion ───────────────────────
    def t01():
        task = sched.add_task("Recon Pass", "asset_discovery", target="https://target.com", team=AgentTeam.RECON)
        sched.dispatch_task(task.task_id, "ReconWorker_1")
        agent = AssetDiscoveryAgent()
        res = agent.execute(task, context={})
        assert res.success
        assert len(res.normalized_data["domains"]) >= 3
        sched.submit_result(task.task_id, res)
        reviewer = ReconReviewAgent()
        assert reviewer.review(task, ledger=ledger)
        assert task.status == TaskLifecycleStatus.DONE
    check("1. Recon Team: Asset discovery, DNS mapping & review", t01)

    # ── Test 2: Network Team Accuracy & Blindspot Accounting ─────────────────
    def t02():
        task = sched.add_task("Port Scan", "port_scan", target="target.com", team=AgentTeam.NETWORK)
        sched.dispatch_task(task.task_id, "NetworkWorker_1")
        agent = NetworkDiscoveryAgent()
        res = agent.execute(task, context={})
        assert res.success
        assert len(res.normalized_data["open_ports"]) >= 2
        sched.submit_result(task.task_id, res)
        reviewer = NetworkReviewAgent()
        assert reviewer.review(task, ledger=ledger)
        assert task.status == TaskLifecycleStatus.DONE
        # Check that UDP was honestly flagged as blindspot
        summary = ledger.get_summary()
        assert summary["blindspots_count"] >= 1
    check("2. Network Team: Port scanning & UDP blindspot tracking", t02)

    # ── Test 3: Web Team Accuracy & Untestable 2FA Registration ──────────────
    def t03():
        task = sched.add_task("Content Discovery", "content_discovery", target="https://target.com", team=AgentTeam.WEB)
        sched.dispatch_task(task.task_id, "WebWorker_1")
        agent = ContentDiscoveryAgent()
        res = agent.execute(task, context={})
        assert res.success
        assert len(res.normalized_data["endpoints"]) >= 3
        sched.submit_result(task.task_id, res)
        reviewer = WebReviewAgent()
        assert reviewer.review(task, ledger=ledger)
        assert task.status == TaskLifecycleStatus.DONE
        # Verify /admin was marked untestable due to 2FA
        summary = ledger.get_summary()
        assert summary["assets_untestable"] >= 1
    check("3. Web Team: Endpoint discovery & untestable 2FA accounting", t03)

    # ── Test 4: API Team Parameter Intelligence ──────────────────────────────
    def t04():
        task = sched.add_task("API Parameter Map", "parameter_intelligence", target="https://target.com/api/v1/users/{id}", team=AgentTeam.API)
        sched.dispatch_task(task.task_id, "APIWorker_1")
        agent = ParameterIntelligenceAgent()
        res = agent.execute(task, context={})
        assert res.success
        params = res.normalized_data["parameters"]
        assert any(p["risk_profile"] == "HIGH_IDOR_CANDIDATE" for p in params)
        sched.submit_result(task.task_id, res)
        reviewer = APIReviewAgent()
        assert reviewer.review(task, ledger=ledger)
        assert task.status == TaskLifecycleStatus.DONE
    check("4. API Team: Route mapping & IDOR parameter risk profiling", t04)

    # ── Test 5: JavaScript Team Bundle & Route Extraction ────────────────────
    def t05():
        task = sched.add_task("JS Route Extract", "route_extraction", target="https://target.com/static/main.js", team=AgentTeam.JAVASCRIPT)
        sched.dispatch_task(task.task_id, "JSWorker_1")
        agent = RouteExtractionAgent()
        res = agent.execute(task, context={})
        assert res.success
        routes = res.normalized_data["extracted_routes"]
        assert "/api/v1/internal/health" in routes
        sched.submit_result(task.task_id, res)
        reviewer = JSReviewAgent()
        assert reviewer.review(task, ledger=ledger)
        assert task.status == TaskLifecycleStatus.DONE
    check("5. JavaScript Team: Bundle unpacking & internal route extraction", t05)

    # ── Test 6: Negative Case A — Command Injection Syntax Echo (Reflection) ──
    def t06():
        counter = CounterexampleAgent()
        # Probed response merely echoes the command syntax!
        fake_response = "<html>Error processing: $((53+19)) in script</html>"
        is_refuted, reason = counter.evaluate_claim(
            endpoint="https://target.com/shell",
            vuln_class="COMMAND_INJECTION",
            probed_response=fake_response,
            baseline_response="<html>Error</html>",
        )
        assert is_refuted, "Command syntax echo must be rejected!"
        assert "Reflection != Execution" in reason
    check("6. Negative Case A: Command syntax echo strictly REFUTED (Echo != Execution)", t06)

    # ── Test 7: Negative Case B — Natural HTTP Jitter (<15 bytes) ────────────
    def t07():
        counter = CounterexampleAgent()
        baseline = "<html>Timestamp: 1720000000</html>"
        probed = "<html>Timestamp: 1720000009</html>"  # 1 byte delta (natural jitter)
        is_refuted, reason = counter.evaluate_claim(
            endpoint="https://target.com/profile",
            vuln_class="IDOR",
            probed_response=probed,
            baseline_response=baseline,
        )
        assert is_refuted, "Natural HTTP jitter must be rejected!"
        assert "jitter" in reason.lower()
    check("7. Negative Case B: Natural HTTP jitter (<15 bytes) strictly REFUTED", t07)

    # ── Test 8: Negative Case C — WAF Challenge / Error Page ─────────────────
    def t08():
        counter = CounterexampleAgent()
        probed = "<html>404 Not Found - Cloudflare Ray ID: 8934abcde</html>"
        is_refuted, reason = counter.evaluate_claim(
            endpoint="https://target.com/hidden",
            vuln_class="SQLI",
            probed_response=probed,
            baseline_response="<html>Normal</html>",
        )
        assert is_refuted, "WAF / 404 challenge must not be called a vulnerability!"
        assert "WAF challenge" in reason
    check("8. Negative Case C: Generic WAF error page strictly REFUTED", t08)

    # ── Test 9: Independent Verification Team & Evidence Court Confirmation ──
    def t09():
        task = sched.add_task(
            "Verify IDOR",
            "verify_finding",
            target="https://target.com/api/v1/users/456",
            team=AgentTeam.VERIFICATION,
            parameters={"vuln_class": "IDOR", "parameter": "id"},
        )
        sched.dispatch_task(task.task_id, "VerifierWorker_1")
        agent = CausalVerificationAgent()
        res = agent.execute(task, context={
            "probed_response": '{"id": 456, "name": "victim_alice", "email": "alice@corp.local"}',
            "baseline_response": '{"id": 123, "name": "attacker_bob"}',
        })
        assert res.success
        assert res.normalized_data["verdict"] == "CONFIRMED"
        sched.submit_result(task.task_id, res)

        court_reviewer = EvidenceCourtReviewer()
        assert court_reviewer.review(task, ledger=ledger)
        assert task.status == TaskLifecycleStatus.DONE
    check("9. Verification Team: Causal differential proof & EvidenceCourt adjudication", t09)

    # ── Test 10: Anti-Self-Grading Invariant ──────────────────────────────────
    def t10():
        task = sched.add_task("Self Review Probe", "test_action", target="https://target.com", team=AgentTeam.WEB)
        sched.dispatch_task(task.task_id, "Agent_Narcissus")
        # Submit result
        res = ToolExecutionResult(task_id=task.task_id, action="test_action", target="https://target.com", success=True)
        task.submit_for_review(res)
        # Attempt to approve itself
        ok = sched.review_task(task.task_id, reviewer_agent="Agent_Narcissus", approved=True)
        assert not ok, "Agent must NEVER be allowed to approve its own work!"
    check("10. Anti-Self-Grading Invariant: Agent review of own task strictly DENIED", t10)

    # ── Summary ──────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f" BENCHMARK SUMMARY: Total: {passed + failed} | Passed: {passed} | Failed: {failed}")
    verdict = "PASS" if failed == 0 else "FAIL"
    print(f" FINAL BENCHMARK VERDICT: {verdict}")
    print("=" * 70 + "\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_benchmark())
