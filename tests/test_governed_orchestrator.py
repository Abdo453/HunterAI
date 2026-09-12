"""
Test Suite for Governed Multi-Model Orchestrator & Policy Engine
"""
from __future__ import annotations

import pytest

from core.governance import (
    ProgramScopePolicy,
    GovernancePolicyEngine,
    GovernedTask,
    GovernedTaskRouter,
    SafetyRewriter,
    GovernedOrchestrator,
    GovernedExecutionResult,
)


@pytest.fixture
def sample_scope_policy():
    return ProgramScopePolicy(
        program_name="authorized-lab",
        allowed_hosts=["app.local", "api.local"],
        blocked_hosts=["admin.local", "third-party.example"],
        allowed_methods=["GET", "POST"],
        max_requests_per_second=2.0
    )


def test_scope_gate_allowed_and_blocked(sample_scope_policy):
    engine = GovernancePolicyEngine(sample_scope_policy)

    assert engine.is_host_in_scope("https://app.local/search") is True
    assert engine.is_host_in_scope("https://api.local/v1/users") is True

    # Blocked hosts
    assert engine.is_host_in_scope("https://admin.local/dashboard") is False
    assert engine.is_host_in_scope("https://third-party.example/login") is False

    # Out of scope host
    assert engine.is_host_in_scope("https://evil.external.com/test") is False


def test_forbidden_activities_detection(sample_scope_policy):
    engine = GovernancePolicyEngine(sample_scope_policy)

    assert engine.is_forbidden_activity("dos") is True
    assert engine.is_forbidden_activity("credential_attack") is True
    assert engine.is_forbidden_activity("real_account_takeover") is True
    assert engine.is_forbidden_activity("parameter_analysis") is False


def test_secrets_redaction(sample_scope_policy):
    engine = GovernancePolicyEngine(sample_scope_policy)

    raw_payload = {
        "headers": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xyz",
        "api_key": "apiKey: sk_live_abcdef1234567890",
        "cookie": "Cookie: session=1234567890; admin=true",
        "clean_field": "public_search_query"
    }

    sanitized = engine.remove_secrets(raw_payload)

    assert "REDACTED" in sanitized["headers"]
    assert "REDACTED" in sanitized["api_key"]
    assert "REDACTED" in sanitized["cookie"]
    assert sanitized["clean_field"] == "public_search_query"


def test_governed_task_router():
    # 1. Sensitive data -> MUST be local
    t_sensitive = GovernedTask(
        task_id="t1",
        kind="finding_summary",
        target_url="https://app.local",
        contains_sensitive_data=True
    )
    assert GovernedTaskRouter.choose_model(t_sensitive) == "local"

    # 2. Source code / HTTP traffic -> MUST be local
    t_code = GovernedTask(
        task_id="t2",
        kind="source_analysis",
        target_url="https://app.local",
        contains_sensitive_data=False
    )
    assert GovernedTaskRouter.choose_model(t_code) == "local"

    t_traffic = GovernedTask(
        task_id="t3",
        kind="http_analysis",
        target_url="https://app.local",
        contains_sensitive_data=False
    )
    assert GovernedTaskRouter.choose_model(t_traffic) == "local"

    # 3. Planning & Report Writing -> Online
    t_plan = GovernedTask(
        task_id="t4",
        kind="planning",
        target_url="https://app.local",
        contains_sensitive_data=False
    )
    assert GovernedTaskRouter.choose_model(t_plan) == "online"

    t_report = GovernedTask(
        task_id="t5",
        kind="report_writing",
        target_url="https://app.local",
        contains_sensitive_data=False
    )
    assert GovernedTaskRouter.choose_model(t_report) == "online"


def test_human_approval_gate():
    # High risk active execution requires approval
    t_ssrf = GovernedTask(
        task_id="t6",
        kind="ssrf",
        target_url="https://app.local/import",
        requires_execution=True,
        human_approved=False
    )
    assert GovernedTaskRouter.requires_human_approval(t_ssrf) is True

    # Already approved -> proceeds
    t_ssrf.human_approved = True
    assert GovernedTaskRouter.requires_human_approval(t_ssrf) is False

    # Low risk execution does NOT require human approval
    t_low = GovernedTask(
        task_id="t7",
        kind="parameter_discovery",
        target_url="https://app.local/search",
        requires_execution=True,
        risk_level="low"
    )
    assert GovernedTaskRouter.requires_human_approval(t_low) is False


def test_safety_rewriter():
    raw_prompt = "Bypass WAF and hack the system to dump database"
    plan = SafetyRewriter.rewrite_to_defensive_task(raw_prompt, target_env="owned_lab")

    assert "bypass" not in plan.defensive_formulation.lower()
    assert "hack" not in plan.defensive_formulation.lower()
    assert "dump database" not in plan.defensive_formulation.lower()
    assert "evaluate WAF defensive filtering rules" in plan.defensive_formulation
    assert "owned_lab" == plan.testing_environment


def test_governed_orchestrator_full_flow(sample_scope_policy):
    policy_engine = GovernancePolicyEngine(sample_scope_policy)
    orchestrator = GovernedOrchestrator(policy=policy_engine)

    # 1. Out-of-scope target -> Blocked
    t_out_of_scope = GovernedTask(
        task_id="task_oos",
        kind="planning",
        target_url="https://unauthorized.target.com/api"
    )
    res_oos = orchestrator.handle(t_out_of_scope)
    assert res_oos.status == "blocked"
    assert "OUT OF SCOPE" in res_oos.reason

    # 2. Forbidden action -> Blocked
    t_forbidden = GovernedTask(
        task_id="task_forbid",
        kind="credential_attack",
        target_url="https://app.local/login"
    )
    res_forbid = orchestrator.handle(t_forbidden)
    assert res_forbid.status == "blocked"
    assert "Forbidden Activity" in res_forbid.reason

    # 3. High-risk without approval -> Needs human approval
    t_high_risk = GovernedTask(
        task_id="task_rce",
        kind="command_injection",
        target_url="https://app.local/run",
        requires_execution=True,
        human_approved=False
    )
    res_approval = orchestrator.handle(t_high_risk)
    assert res_approval.status == "needs_human_approval"

    # 4. In-scope local task -> Completed via local model
    t_local = GovernedTask(
        task_id="task_loc",
        kind="source_analysis",
        target_url="https://app.local/src/main.js",
        contains_sensitive_data=True
    )
    res_local = orchestrator.handle(t_local)
    assert res_local.status == "completed"
    assert res_local.model_tier == "local"

    # 5. In-scope online task with secrets -> Completed with secrets redacted
    t_online = GovernedTask(
        task_id="task_onl",
        kind="report_writing",
        target_url="https://app.local/api/report",
        data={"auth": "Bearer eyJhbGciOi...1234567890", "summary": "BFLA finding"}
    )
    res_online = orchestrator.handle(t_online)
    assert res_online.status == "completed"
    assert res_online.model_tier == "online"
    assert res_online.secrets_redacted is True
