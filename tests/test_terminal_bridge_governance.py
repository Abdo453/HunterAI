"""
Integration Tests: TerminalBridge ↔ Inviolable PolicyGate
==========================================================
Proves that the terminal execution layer is subordinate to the security
policy layer (Scope -> Policy -> Execution -> Audit) and cannot bypass it.

Covered invariants:
  1. Catastrophic commands are denied by the PolicyGate.
  2. Cloud metadata / loopback destinations embedded in a command are denied.
  3. Out-of-scope domains embedded in a command are denied.
  4. Local, benign commands pass and execute.
  5. Every execution record carries the mandatory audit fields.
  6. The bridge fails CLOSED if the policy gate raises.
  7. Without a gate, the defense-in-depth signature check still blocks bombs.
"""
from __future__ import annotations

import pytest

from core.scope_engine import ScopePolicy
from core.control_plane.policy_gate import PolicyGate
from core.system.terminal_bridge import TerminalBridge

BENIGN_CMD = "echo hunterai_governed_test"


@pytest.fixture
def governed_bridge() -> TerminalBridge:
    policy = ScopePolicy(allowed_targets=["app.local"])
    gate = PolicyGate(scope_policy=policy, authorized=True)
    return TerminalBridge(policy_gate=gate)


# ── 1. Catastrophic command ──────────────────────────────────────────────────
def test_destructive_command_denied(governed_bridge: TerminalBridge):
    result = governed_bridge.execute_command("rm -rf /", project_id="proj_a")
    assert result["status"] == "DENIED_POLICY"
    assert result["authorization"] == "DENIED"
    assert result["returncode"] == -1
    # It must never have executed: nothing written to stdout.
    assert result["stdout"] == ""


# ── 2. Cloud metadata (inviolable, non-overridable) ──────────────────────────
def test_cloud_metadata_command_denied(governed_bridge: TerminalBridge):
    result = governed_bridge.execute_command(
        "curl http://169.254.169.254/latest/meta-data/",
        project_id="proj_a",
    )
    assert result["status"] == "DENIED_POLICY"
    assert result["authorization"] == "DENIED"


def test_loopback_command_denied(governed_bridge: TerminalBridge):
    result = governed_bridge.execute_command("curl http://127.0.0.1/admin")
    assert result["status"] == "DENIED_POLICY"
    assert result["authorization"] == "DENIED"


# ── 3. Out-of-scope domain ───────────────────────────────────────────────────
def test_out_of_scope_domain_denied(governed_bridge: TerminalBridge):
    result = governed_bridge.execute_command("curl http://evil.example.com/steal")
    assert result["status"] == "DENIED_POLICY"
    assert result["authorization"] == "DENIED"


# ── 4. Benign local command passes and executes ──────────────────────────────
def test_benign_command_allowed_and_executes(governed_bridge: TerminalBridge):
    result = governed_bridge.execute_command(BENIGN_CMD, project_id="proj_a", tool_id="echo")
    assert result["authorization"] == "ALLOWED"
    assert result["status"] == "SUCCESS"
    assert result["returncode"] == 0
    assert "hunterai_governed_test" in result["stdout"]


# ── 5. Mandatory audit fields ────────────────────────────────────────────────
def test_audit_record_contains_governance_fields(governed_bridge: TerminalBridge):
    governed_bridge.execute_command(BENIGN_CMD, project_id="proj_audit", tool_id="echo", agent_id="recon_agent")
    record = governed_bridge.execution_history[-1]

    for field in (
        "project_id",
        "tool_id",
        "action",
        "agent_id",
        "timestamp",
        "authorization",
        "authorization_decision",
        "status",
        "returncode",
    ):
        assert field in record, f"missing audit field: {field}"

    assert record["project_id"] == "proj_audit"
    assert record["tool_id"] == "echo"
    assert record["action"] == "terminal_command"
    assert record["agent_id"] == "recon_agent"
    assert isinstance(record["timestamp"], float)
    assert record["authorization"] in ("ALLOWED", "DENIED", "NOT_EVALUATED")


def test_denied_execution_is_still_audited(governed_bridge: TerminalBridge):
    governed_bridge.execute_command("rm -rf /", project_id="proj_audit")
    record = governed_bridge.execution_history[-1]
    assert record["status"] == "DENIED_POLICY"
    assert record["authorization"] == "DENIED"
    assert "authorization_decision" in record and record["authorization_decision"]


# ── 6. Fail closed on gate error ─────────────────────────────────────────────
class _BrokenGate:
    def evaluate(self, req):  # noqa: D401
        raise RuntimeError("simulated gate failure")


def test_fails_closed_on_gate_error():
    bridge = TerminalBridge(policy_gate=_BrokenGate())
    result = bridge.execute_command(BENIGN_CMD)
    assert result["status"] == "DENIED_POLICY_ERROR"
    assert result["authorization"] == "DENIED"
    assert result["stdout"] == ""


# ── 7. Defense-in-depth without a gate ───────────────────────────────────────
def test_fallback_signature_check_without_gate():
    bridge = TerminalBridge()  # no gate, no scope engine
    result = bridge.execute_command("rm -rf /")
    assert result["status"] == "DENIED"
    assert result["authorization"] == "DENIED"


def test_fallback_benign_command_without_gate():
    bridge = TerminalBridge()
    result = bridge.execute_command(BENIGN_CMD)
    assert result["status"] == "SUCCESS"
    assert result["authorization"] == "NOT_EVALUATED"
