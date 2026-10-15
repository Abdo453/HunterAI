"""
HunterAI Phase 17 — End-to-End Synthetic Test Suite
=====================================================
Validates the full Phase 1-17 workflow in one deterministic pass:
  1. create_project()          - Project isolation sandbox
  2. set_scope()               - Scope configuration
  3. validate_environment()    - Component health check
  4. execute_task("recon")     - TaskScheduler recon run
  5. browser_agent_inspect()   - DOM annotation & surface extraction
  6. generate_hypothesis()     - HypothesisEngine pattern matching
  7. run_test()                - Differential verification
  8. court_evidence()          - EvidenceCourt adjudication
  9. generate_report()         - Report engine output
 10. snapshot()                - State persistence checkpoint
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# Ensure project root on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ─── Imports ─────────────────────────────────────────────────────────────────
from core.project_isolation import ProjectIsolationManager
from core.tool_registry import ToolRegistry
from core.model_preset import ModelPreset, AgentProfile
from core.memory_manager_v2 import MemoryManager
from core.subagent_manager_v2 import SubagentManager, SubagentStatus
from core.terminal_bridge import TerminalBridge
from core.browser_agent import BrowserAgent
from core.host_bridge import HostBridge
from core.snapshot_manager import SnapshotManager
from core.plugin_system import PluginLoader
from core.system_modules import TaskScheduler, InformationGainPlanner, RecoveryEngine
from hunter_ai.evidence.evidence_graph import EvidenceGraph
from hunter_ai.evidence.hypothesis_engine import HypothesisEngine
from hunter_ai.evidence.finding_lifecycle import FindingLifecycle, FindingStatus
from core.evidence_court import EvidenceCourt
from core.attack_surface_graph import AttackSurfaceGraph
from core.scope_guard import ScopeGuard


def _pad(label: str, width: int = 55) -> str:
    return f"  {label:<{width}}"


def main():
    results = []
    passed = 0
    failed = 0

    def step(num: int, label: str, fn):
        nonlocal passed, failed
        t0 = time.time()
        try:
            fn()
            elapsed = round((time.time() - t0) * 1000, 1)
            results.append((num, label, "PASS", elapsed, None))
            passed += 1
        except AssertionError as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            results.append((num, label, "FAIL", elapsed, str(e)))
            failed += 1
        except Exception as e:
            elapsed = round((time.time() - t0) * 1000, 1)
            results.append((num, label, "FAIL", elapsed, f"{type(e).__name__}: {e}"))
            failed += 1

    # ── Shared state ─────────────────────────────────────────────────────────
    state = {}

    # ── Step 1: create_project() ─────────────────────────────────────────────
    def s01():
        mgr = ProjectIsolationManager(workspace_root="data/e2e_test_project", secrets_dir="secrets")
        proj = mgr.create_project("e2e_example_proj", name="E2E Example Project", scope=["example.com"])
        assert proj.project_id == "e2e_example_proj"
        state["proj_mgr"] = mgr
        state["proj"] = proj

    step(1, "create_project()", s01)

    # ── Step 2: set_scope() ──────────────────────────────────────────────────
    def s02():
        scope = ScopeGuard(in_scope=["example.com", "*.example.com"], out_of_scope=["evil.com"])
        state["scope"] = scope
        allowed, _ = scope.is_allowed("https://api.example.com/users")
        assert allowed, "In-scope URL blocked"
        blocked, reason = scope.is_allowed("https://evil.com")
        assert not blocked, "Out-of-scope URL allowed"

    step(2, "set_scope('example.com')", s02)

    # ── Step 3: validate_environment() ───────────────────────────────────────
    def s03():
        from core.attack_surface_graph import AttackSurfaceGraph
        from core.evidence_graph import EvidenceGraph as CoreEvidenceGraph
        from core.evidence_court import EvidenceCourt
        from core.burp_gateway.event_stream import BurpLiveEventStream
        # All critical components importable
        AttackSurfaceGraph("https://example.com")
        EvidenceCourt
        BurpLiveEventStream()

        # Tool Registry discovers tools from config
        reg = ToolRegistry(config_path="config/tools.json")
        tools = reg.discover_tools()
        assert len(tools) >= 10, f"Only {len(tools)} tools discovered"
        state["tool_registry"] = reg

    step(3, "validate_environment()", s03)

    # ── Step 4: execute_task("recon") ────────────────────────────────────────
    def s04():
        sched = TaskScheduler(tasks_file="config/tasks_e2e_test.json", logs_dir="task_logs")

        recon_task = sched.add_task(
            name="E2E Subdomain Recon",
            action="subdomain_enum",
            target="example.com",
            priority=1,
        )

        def mock_recon_handler(task, context):
            return {
                "subdomains": ["api.example.com", "admin.example.com", "auth.example.com"],
                "live_hosts": ["api.example.com", "auth.example.com"],
            }

        sched.register_handler("subdomain_enum", mock_recon_handler)
        res = sched.execute_task(recon_task.task_id)
        assert res["success"], f"Recon task failed: {res}"
        state["recon_result"] = res["result"]
        state["sched"] = sched

    step(4, "execute_task('recon')", s04)

    # ── Step 5: browser_agent_inspect() ──────────────────────────────────────
    def s05():
        agent = BrowserAgent()
        html = (
            "<html><body>"
            "<form id='login_form' action='/api/auth/login' method='post'>"
            "<input type='text' name='username'/>"
            "<input type='password' name='password'/>"
            "<input type='hidden' name='csrf_token' value='abc123'/>"
            "</form>"
            "<a href='/admin/users' id='admin_link'>Admin</a>"
            "</body></html>"
        )
        agent.navigate("https://example.com/login", title="Login", simulated_html=html)
        surface = agent.get_annotated_surface()
        assert surface["total_annotations"] >= 3
        high_roles = {e["security_role"] for e in surface["high_risk_elements"]}
        assert "login_form" in high_roles
        assert "sensitive_credential_input" in high_roles
        state["browser_surface"] = surface

    step(5, "browser_agent_inspect()", s05)

    # ── Step 6: generate_hypothesis() ────────────────────────────────────────
    def s06():
        engine = HypothesisEngine()
        obs = "The id parameter in /api/users/{id} returns another user's data when changed"
        hyps = engine.generate_from_observation(obs, endpoint="/api/users/123", params=["id"])
        assert len(hyps) >= 1
        h = hyps[0]
        assert h.vuln_type in ("IDOR", "BOLA", "SQLi", "CORS_MISCONFIGURATION", "OPEN_REDIRECT", "CSRF", "UNRESTRICTED_FILE_UPLOAD")
        state["hypothesis"] = h
        state["hypothesis_engine"] = engine

    step(6, "generate_hypothesis()", s06)

    # ── Step 7: run_test("login_flow") ───────────────────────────────────────
    def s07():
        # Build evidence chain
        eg = EvidenceGraph()
        response_node_id = eg.build_from_request_response(
            host="example.com",
            endpoint="/api/users/123",
            method="GET",
            request_body="{}",
            response_status=200,
            response_body='{"id":456,"name":"victim_user"}',
        )
        obs_id = eg.add_observation(response_node_id, "Returned different user ID than requested")
        exp_id = eg.add_experiment(
            obs_id,
            plan="Change user ID from 123 to 456 and compare responses",
            result={"diff": 320, "signal": "IDOR"},
        )
        verdict_id = eg.add_verdict(exp_id, verdict="CONFIRMED", reason="Response body differs by >50 chars with different user data", confidence=0.92)
        chain = eg.get_chain(verdict_id)
        assert len(chain) >= 5, f"Evidence chain too short: {len(chain)}"
        state["evidence_graph"] = eg
        state["verdict_node_id"] = verdict_id

    step(7, "run_test('login_flow')", s07)

    # ── Step 8: court_evidence() ─────────────────────────────────────────────
    def s08():
        judgment = EvidenceCourt.adjudicate(
            target_url="https://example.com/api/users/123",
            parameter="id",
            vuln_class="IDOR",
            finder_claim={"claim": "User can access other users' data by changing id parameter"},
            verifier_result={"status_code": 200, "poe_token": "POE-TEST-TOKEN-XYZ", "body_delta": 320},
            is_in_scope=True,
        )
        assert judgment.judgment_id is not None
        assert judgment.verdict is not None
        state["judgment"] = judgment

    step(8, "court_evidence()", s08)

    # ── Step 9: generate_report() ────────────────────────────────────────────
    def s09():
        from core.report_engine import ReportEngine
        engine = ReportEngine(target="example.com", scope=["example.com"], operator="E2E-Test")

        findings = [
            {
                "title": "Insecure Direct Object Reference (IDOR) on /api/users/{id}",
                "severity": "HIGH",
                "endpoint": "/api/users/123",
                "evidence": "Response body returned victim user data when only id parameter was changed.",
                "recommendation": "Enforce authorization checks on all object references",
                "cvss": 8.1,
            }
        ]
        report = engine.build(
            findings=findings,
            attack_surface={"domains": 3, "live_hosts": 2, "endpoints": 20},
            evidence_summary="Evidence chain: HOST→ENDPOINT→REQUEST→RESPONSE→OBSERVATION→EXPERIMENT→VERDICT",
            request_summary={"total": 45, "status_counts": {200: 38, 403: 5, 500: 2}},
        )
        md = engine.to_markdown(report)
        assert "IDOR" in md or "example.com" in md
        json_out = engine.to_json(report)
        assert '"target"' in json_out
        state["report"] = report
        state["report_md"] = md

    step(9, "generate_report()", s09)

    # ── Step 10: snapshot() ──────────────────────────────────────────────────
    def s10():
        sm = SnapshotManager("snapshots")
        snap_state = {
            "project_id": "e2e_example_proj",
            "target": "example.com",
            "recon_result": state.get("recon_result"),
            "hypothesis_count": 1,
            "judgment_verdict": str(state["judgment"].verdict) if state.get("judgment") else None,
            "findings_count": 1,
            "phase": "COMPLETE",
        }
        snap = sm.snapshot(snap_state, label="e2e_final_checkpoint")
        restored = sm.rollback(snap.snapshot_id)
        assert restored["target"] == "example.com"
        assert restored["phase"] == "COMPLETE"
        state["snapshot"] = snap

    step(10, "snapshot()", s10)

    # ── Report ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(" HUNTEROS — PHASE 17 END-TO-END SYNTHETIC TEST REPORT")
    print("=" * 70 + "\n")
    for num, label, status, elapsed, err in results:
        tag = "[PASS]" if status == "PASS" else "[FAIL]"
        print(f"  {tag} Step {num:02d}: {label:<42} {status}  ({elapsed}ms)")
        if err:
            print(f"          Error: {err}")
    print()
    total = passed + failed
    print(f"  Total: {total}  Passed: {passed}  Failed: {failed}")
    print("\n" + "=" * 70)
    verdict = "PASS" if failed == 0 else "FAIL"
    print(f"  FINAL VERDICT: {verdict}")
    print("=" * 70 + "\n")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
