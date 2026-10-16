"""
Governance tests for ToolManager — closes the S1 gap.

Any security-sensitive tool execution routed through ``ToolManager.execute`` must
pass the authoritative ``PolicyGate`` (fail-closed) and be auditable with:
project_id, tool_id, action, timestamp, authorization decision and result.
"""
import pytest

from core.control_plane.policy_gate import PolicyGate
from core.scope_engine import ScopePolicy
from tools.tool_manager import ToolManager


def _gate(targets=("example.com",), authorized=True):
    return PolicyGate(
        scope_policy=ScopePolicy(allowed_targets=list(targets)),
        authorized=authorized,
    )


# ── Decision-point (_govern) ────────────────────────────────────────────────

def test_govern_allows_in_scope_url(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path), policy_gate=_gate())
    assert tm._govern("nikto", "nikto -h https://example.com") is None
    last = tm.governance_audit[-1]
    assert last["authorization"] == "ALLOWED"
    assert last["tool_id"] == "nikto"
    assert last["project_id"] == "default"
    assert last["action"] == "tool_execute"
    assert "timestamp" in last


def test_govern_allows_local_command_without_destination(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path), policy_gate=_gate())
    # No extractable network destination => treated as local execution.
    assert tm._govern("python", 'python -c "print(1)"') is None


def test_govern_denies_out_of_scope_destination(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path), policy_gate=_gate())
    denial = tm._govern("curl", "curl https://evil.example.net/secret")
    assert denial is not None
    assert denial.error_category == "POLICY_DENIED"
    assert denial.returncode == -1
    assert tm.governance_audit[-1]["authorization"] == "DENIED"


def test_govern_denies_cloud_metadata(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path), policy_gate=_gate())
    denial = tm._govern("curl", "curl http://169.254.169.254/latest/meta-data/")
    assert denial is not None
    assert denial.error_category == "POLICY_DENIED"


def test_govern_denies_catastrophic_command(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path), policy_gate=_gate())
    denial = tm._govern("sh", "rm -rf /")
    assert denial is not None
    assert denial.error_category == "POLICY_DENIED"


def test_govern_fail_closed_on_gate_error(tmp_path):
    class BoomGate:
        def evaluate(self, req):
            raise RuntimeError("gate exploded")

    tm = ToolManager(output_dir=str(tmp_path), policy_gate=BoomGate())
    denial = tm._govern("nmap", "nmap example.com")
    assert denial is not None
    assert denial.error_category == "POLICY_ERROR"
    assert tm.governance_audit[-1]["decision"] == "DENIED_POLICY_ERROR"


# ── End-to-end through execute() ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_execute_denied_before_running(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path), policy_gate=_gate())
    res = await tm.execute("curl https://evil.example.net/secret")
    assert res.error_category == "POLICY_DENIED"
    assert res.returncode == -1
    assert res.stdout == ""


@pytest.mark.asyncio
async def test_execute_allows_in_scope_local_run(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path), policy_gate=_gate())
    res = await tm.execute('python -c "print(456)"')
    assert res.error_category is None
    assert "456" in res.stdout
    assert any(e["authorization"] == "ALLOWED" for e in tm.governance_audit)


@pytest.mark.asyncio
async def test_execute_without_gate_still_runs(tmp_path):
    # Isolation mode (e.g. unit tests of the raw process wrapper) is unchanged.
    tm = ToolManager(output_dir=str(tmp_path))
    res = await tm.execute('python -c "print(123)"')
    assert res.returncode == 0
    assert "123" in res.stdout


@pytest.mark.asyncio
async def test_attach_policy_gate_activates_governance(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path))  # no gate initially
    res = await tm.execute('python -c "print(7)"')
    assert res.error_category != "POLICY_DENIED"  # not yet governed

    tm.attach_policy_gate(_gate(), project_id="proj-1")
    res2 = await tm.execute("curl https://evil.example.net/secret")
    assert res2.error_category == "POLICY_DENIED"
    assert tm.governance_audit[-1]["project_id"] == "proj-1"
