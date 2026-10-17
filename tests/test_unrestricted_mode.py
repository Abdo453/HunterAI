"""Owner full-permissions execution mode.

The platform DEFAULTS to unrestricted execution (the operator owns the machine
and grants the agent full permissions). The security test-suite forces governed
mode via ``tests/conftest.py``; this file flips the switch explicitly and — most
importantly — proves the switch does NOT weaken result integrity.
"""
from __future__ import annotations

import pytest

from core.security_mode import unrestricted_mode
from core.gateway.policy_engine import PolicyEngine
from core.gateway.schemas import ActionProposal
from core.scope_engine import ScopePolicy, StrictScopeEngine
from core.control_plane.policy_gate import ActionCategory, ActionRequest, PolicyGate
from core.execution_modes import (
    ExecutionMode,
    HighRiskActionType,
    HumanApprovalGate,
    ModeManager,
)
from core.governance.task_router import GovernedTask, GovernedTaskRouter
from core.scope_guard import ScopeGuard as LegacyScopeGuard
from hunter_ai.pipeline.qualification_gate import FindingQualificationGate


@pytest.fixture
def unrestricted(monkeypatch):
    monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")
    yield


# ── the switch itself ────────────────────────────────────────────────────────

def test_default_mode_is_unrestricted(monkeypatch):
    monkeypatch.delenv("HUNTER_UNRESTRICTED", raising=False)
    assert unrestricted_mode() is True


def test_governed_mode_when_explicitly_disabled(monkeypatch):
    monkeypatch.setenv("HUNTER_UNRESTRICTED", "0")
    assert unrestricted_mode() is False


# ── full execution permissions ───────────────────────────────────────────────

def test_policy_engine_grants_full_permissions(unrestricted):
    engine = PolicyEngine()
    prop = ActionProposal(
        target="http://169.254.169.254/latest/meta-data/",
        tool_name="curl",
        command_args="rm -rf /",
    )
    verdict = engine.evaluate_proposal(prop)
    assert verdict.allowed is True
    assert verdict.status == "APPROVED"


def test_scope_engine_allows_every_target(unrestricted):
    engine = StrictScopeEngine(ScopePolicy(allowed_targets=["example.com"]))
    for host in ("127.0.0.1", "169.254.169.254", "10.0.0.5", "2130706433", "anything.evil.example"):
        assert engine.is_allowed(host)[0] is True, host


def test_legacy_scope_guard_allows_loopback(unrestricted):
    guard = LegacyScopeGuard(in_scope=["example.com"])
    assert guard.is_in_scope("127.0.0.1")[0] is True
    assert guard.is_in_scope("169.254.169.254")[0] is True


def test_policy_gate_allows_destructive_command(unrestricted):
    gate = PolicyGate(
        scope_policy=ScopePolicy(allowed_targets=["example.com"]),
        authorized=False,
        allow_destructive=False,
    )
    req = ActionRequest(category=ActionCategory.TERMINAL_COMMAND, command="rm -rf /", target="local_terminal")
    assert gate.evaluate(req).allowed is True


def test_human_approval_gate_auto_approves(unrestricted):
    gate = HumanApprovalGate(interactive=False)
    assert gate.request_approval(HighRiskActionType.ACTIVE_SQLI, "target.com", {}) is True


def test_passive_mode_shield_does_not_block(unrestricted):
    mgr = ModeManager(initial_mode=ExecutionMode.PASSIVE)
    mgr.assert_active_allowed("SQL injection payload")  # must not raise


def test_governed_task_router_skips_approval(unrestricted):
    task = GovernedTask(
        task_id="T-1",
        kind="sqli",
        target_url="https://target.com",
        risk_level="critical",
        requires_execution=True,
    )
    assert GovernedTaskRouter.requires_human_approval(task) is False


# ── result integrity is NOT affected by full permissions ─────────────────────

def test_unproven_findings_are_still_rejected_in_unrestricted_mode(unrestricted):
    """Full execution permissions never mean unproven findings get confirmed."""
    is_q, finding, rationale = FindingQualificationGate.evaluate_candidate(
        title="Nuclei: possible SQL injection",
        asset="target.local",
        endpoint="https://target.local/download",
        vuln_type="SQLi",
        raw_evidence="[sqli] possible injection at param id",
        source_tool="nuclei",
        verifier_result={"reproduced": True, "is_reflection": False},
        proof_payload=None,
    )
    assert is_q is False
    assert finding is None
    assert "Evidence Court" in rationale


def test_secret_sanitization_still_applies_in_unrestricted_mode(unrestricted):
    from core.secret_sanitizer import SecretSanitizer

    scrubbed = SecretSanitizer.sanitize_text("key=AKIAIOSFODNN7EXAMPLE")
    assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed
    assert "AKIAIOSF" in scrubbed  # prefix preserved


def test_pipeline_orchestrator_forces_full_permissions(unrestricted):
    """The pipeline itself overrides authorization/destructive flags in owner mode."""
    from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator

    orch = HunterPipelineOrchestrator(
        target="https://target.com",
        session_id="test_unrestricted_sess",
        in_scope=["target.com"],
        authorized=False,
        no_destructive_tests=True,
        require_human_approval=True,
        workflow="full",
    )
    assert orch.authorized is True
    assert orch.no_destructive_tests is False
    assert orch.require_human_approval is False
    assert orch.allow_no_ai is True
