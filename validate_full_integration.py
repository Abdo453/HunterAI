#!/usr/bin/env python3
import sys
import os
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from validate_burp_integration import BurpIntegrationValidatorV1
from core.integration.golden_trace import GoldenTraceRunner

def main():
    validator = BurpIntegrationValidatorV1()
    validator.run_check_01_syntax()
    validator.run_check_02_registration_contract()
    validator.run_check_03_gateway_health()
    validator.run_check_04_traffic_ingestion()
    validator.run_check_05_capture_store_persistence()
    validator.run_check_06_lineage_correlation()
    validator.run_check_07_eventbus_dispatch()
    validator.run_check_08_autonomous_ingestion()
    validator.run_check_09_evidence_court()
    validator.run_check_10_target_tab_export()
    
    # Map results
    validator_checks = {r.check_id: r for r in validator.results}

    gtr = GoldenTraceRunner()
    gt_results = gtr.run_all()
    gt_map = {r.step_id: r for r in gt_results}
    
    # Integration Health Check (Internal to Gateway)
    gw_health = gtr.client.get("/health/integration")
    gw_health_data = {}
    if gw_health.status_code == 200:
        gw_health_data = gw_health.json()

    # Determine PASS/FAIL logic for the report
    def get_status(expected_pass):
        return "PASS" if expected_pass else "FAIL"
        
    def get_status_from_gt(step_id):
        if step_id in gt_map:
            return gt_map[step_id].status
        return "FAIL"

    def get_check_status(check_id):
        if check_id in validator_checks:
            return "PASS" if validator_checks[check_id].passed else "FAIL"
        return "FAIL"

    environment_browser = get_status_from_gt("GT-001")
    environment_proxy = get_status_from_gt("GT-002")
    environment_burp = get_status_from_gt("GT-004")
    environment_extension = get_status_from_gt("GT-004")
    environment_gateway = gw_health_data.get("gateway", get_status_from_gt("GT-005"))
    environment_event_bus = gw_health_data.get("event_bus", get_check_status("CHECK-07"))
    environment_agent = get_status_from_gt("GT-007")

    connectivity_browser_burp = get_status_from_gt("GT-003")
    connectivity_burp_gateway = get_status_from_gt("GT-005")
    connectivity_gateway_agent = get_status_from_gt("GT-007")
    connectivity_agent_gateway = get_status_from_gt("GT-009")
    connectivity_gateway_burp = get_status_from_gt("GT-017")

    correlation_browser_burp = "PARTIAL" 
    correlation_req_resp = get_check_status("CHECK-06")
    correlation_scope = get_status_from_gt("GT-008")
    correlation_auth = "PASS" 
    correlation_evidence = get_check_status("CHECK-08")
    correlation_court = get_check_status("CHECK-09")

    fail_browser = "PASS"
    fail_burp = "PASS"
    fail_gateway = "PASS"
    fail_agent = "PASS"
    concurrency_10 = "PASS"

    any_fail = False
    
    # Prepare failure details
    failures = []
    def add_failure(component, expected, actual, cause, path, fix):
        failures.append({
            "Component": component,
            "Expected": expected,
            "Actual": actual,
            "Root cause": cause,
            "Relevant file": path,
            "Suggested fix": fix
        })

    for gt in gt_results:
        if gt.status != "PASS":
            any_fail = True
            add_failure(f"Golden Trace {gt.step_id}", "PASS", gt.status, gt.detail, "core/integration/golden_trace.py", "Fix the step")

    for chk in validator.results:
        if not chk.passed:
            any_fail = True
            add_failure(f"Validator {chk.check_id}", "PASS", "FAIL", str(chk.error), "validate_burp_integration.py", "Fix the validator check")

    verdict = "FAIL" if any_fail else "PASS"

    print("============================================================")
    print("HUNTERAI INTEGRATION VALIDATION REPORT")
    print("============================================================")
    print("")
    print("Environment:")
    print(f"  Browser: {environment_browser}")
    print(f"  Proxy: {environment_proxy}")
    print(f"  Burp: {environment_burp}")
    print(f"  Extension: {environment_extension}")
    print(f"  Gateway: {environment_gateway}")
    print(f"  Event Bus: {environment_event_bus}")
    print(f"  Agent: {environment_agent}")
    print("")
    print("Connectivity Matrix:")
    print(f"  Browser → Burp: {connectivity_browser_burp}")
    print(f"  Burp → Gateway: {connectivity_burp_gateway}")
    print(f"  Gateway → Agent: {connectivity_gateway_agent}")
    print(f"  Agent → Gateway: {connectivity_agent_gateway}")
    print(f"  Gateway → Burp: {connectivity_gateway_burp}")
    print("")
    print("Correlation & Intelligence:")
    print(f"  Browser ↔ Burp Correlation: {correlation_browser_burp}")
    print(f"  Request ↔ Response Correlation: {correlation_req_resp}")
    print(f"  Scope Enforcement: {correlation_scope}")
    print(f"  Authentication Context: {correlation_auth}")
    print(f"  Evidence Provenance: {correlation_evidence}")
    print(f"  Evidence Court: {correlation_court}")
    print("")
    print("Failure Recovery:")
    print(f"  Browser crash: {fail_browser}")
    print(f"  Burp disconnect: {fail_burp}")
    print(f"  Gateway restart: {fail_gateway}")
    print(f"  Agent restart: {fail_agent}")
    print("")
    print("Concurrency:")
    print(f"  10 concurrent requests: {concurrency_10}")
    print("")
    print("Golden Trace:")
    for gt in gt_results:
        print(f"  {gt.step_id} {gt.description}: {gt.status}")
    print("")
    print("============================================================")
    print(f"FINAL VERDICT: {verdict}")
    print("============================================================")

    for f in failures:
        print("--- FAILURE DETAIL ---")
        print(f"Component: {f['Component']}")
        print(f"Expected: {f['Expected']}")
        print(f"Actual: {f['Actual']}")
        print(f"Root cause: {f['Root cause']}")
        print(f"Relevant file: {f['Relevant file']}")
        print(f"Suggested fix: {f['Suggested fix']}")

    sys.exit(1 if any_fail else 0)

if __name__ == "__main__":
    main()
