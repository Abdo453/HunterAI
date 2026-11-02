"""Tests for the HunterAI root controller.

Covers the three guarantees the controller makes:

* hierarchy -- downward capability inheritance, bounded depth, parent control;
* shared memory -- persistence, hash-chain integrity, secret redaction;
* permission gate -- fail-closed without a grant, scope-bound with one.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict

import pytest

from core.policy.red_team import (
    AuthorizationGrant,
    Profile,
    ScopeTarget,
    save_grant,
)
from core.root_controller import (
    AgentHierarchy,
    AgentStatus,
    Arsenal,
    HierarchyError,
    Namespace,
    PermissionPolicy,
    PermissionSet,
    PlaybookRunner,
    RootController,
    SharedMemory,
    redact_secrets,
)
from core.tool_registry import Tool, ToolDefinition, ToolError, ToolRegistry, ToolResult

SECRET = b"unit-test-secret"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_grant(
    tmp_path: Path,
    *,
    scope=("example.com",),
    profiles=(Profile.RED_TEAM,),
    grant_id: str = "ENG-unit-test",
) -> str:
    now = time.time()
    grant = AuthorizationGrant.sign(
        SECRET,
        grant_id=grant_id,
        authorized_by="Unit Test Signer (SOW #1)",
        scope=[ScopeTarget(kind="domain", value=value) for value in scope],
        not_before=now - 60,
        not_after=now + 3600,
        profiles=list(profiles),
    )
    path = tmp_path / "authorization_grant.json"
    save_grant(grant, str(path))
    return str(path)


class _FakeSubfinder(Tool):
    """Stands in for a registry tool the playbook can drive."""

    def __init__(self) -> None:
        super().__init__(
            ToolDefinition(
                tool_id="subfinder",
                name="fake subfinder",
                description="returns a fixed host list",
                input_schema={
                    "type": "object",
                    "required": ["target"],
                    "properties": {"target": {"type": "string"}},
                },
                required_permissions=["recon"],
                risk_level="low",
            )
        )

    def describe(self) -> ToolDefinition:
        return self.defn

    def validate_input(self, arguments: Dict[str, Any]) -> None:
        if not arguments.get("target"):
            raise ToolError("target is required", category="VALIDATION", tool_id=self.defn.tool_id)

    def authorize(self, ctx: Any, arguments: Dict[str, Any]) -> None:
        if "recon" not in list(ctx.granted_permissions):
            raise ToolError("worker lacks recon", category="AUTHZ", tool_id=self.defn.tool_id)

    async def execute(self, arguments: Dict[str, Any], ctx: Any) -> ToolResult:
        return ToolResult(
            ok=True,
            tool_id=self.defn.tool_id,
            output={"host": arguments.get("target"), "subdomains": ["www.example.com"]},
        )

    async def cancel(self, run_id: str) -> bool:
        return False

    async def health_check(self) -> bool:
        return True


def make_controller(tmp_path: Path, **kwargs) -> RootController:
    hierarchy = AgentHierarchy(
        root_capabilities=["recon", "scan", "active_testing", "exploit_verify"],
        max_depth=kwargs.pop("max_depth", 3),
        max_children=kwargs.pop("max_children", 3),
    )
    memory = SharedMemory(str(tmp_path / "memory.jsonl"))
    policy = kwargs.pop("policy", None) or PermissionPolicy()
    return RootController(
        hierarchy=hierarchy, memory=memory, policy=policy, **kwargs
    )


class _FakeProbe(Tool):
    """Hermetic tool: proves the dispatch path without touching the network."""

    def __init__(self) -> None:
        super().__init__(
            ToolDefinition(
                tool_id="fake.probe",
                name="fake probe",
                description="returns a fixed marker for the requested target",
                input_schema={
                    "type": "object",
                    "required": ["target"],
                    "properties": {"target": {"type": "string"}},
                },
                required_permissions=["recon"],
                risk_level="low",
            )
        )

    def describe(self) -> ToolDefinition:
        return self.defn

    def validate_input(self, arguments: Dict[str, Any]) -> None:
        if not arguments.get("target"):
            raise ToolError("target is required", category="VALIDATION", tool_id=self.defn.tool_id)

    def authorize(self, ctx: Any, arguments: Dict[str, Any]) -> None:
        if "recon" not in list(ctx.granted_permissions):
            raise ToolError("worker lacks recon", category="AUTHZ", tool_id=self.defn.tool_id)

    async def execute(self, arguments: Dict[str, Any], ctx: Any) -> ToolResult:
        return ToolResult(
            ok=True,
            tool_id=self.defn.tool_id,
            output={"marker": "probe", "target": arguments.get("target")},
        )

    async def cancel(self, run_id: str) -> bool:
        return False

    async def health_check(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# hierarchy
# ---------------------------------------------------------------------------

def test_child_inherits_parent_capabilities():
    hierarchy = AgentHierarchy(root_capabilities=["recon", "scan"])
    child = hierarchy.add_child("root", "recon", "map the estate")
    assert child.capabilities == ["recon", "scan"]
    assert child.depth == 1
    assert child.parent_id == "root"


def test_capability_escalation_is_rejected():
    hierarchy = AgentHierarchy(root_capabilities=["recon"])
    with pytest.raises(HierarchyError) as excinfo:
        hierarchy.add_child("root", "hunter", "hunt", capabilities=["exploit_verify"])
    assert "escalation" in str(excinfo.value)


def test_root_can_grant_capability():
    hierarchy = AgentHierarchy(root_capabilities=["recon"])
    child = hierarchy.add_child("root", "hunter", "hunt")
    hierarchy.grant_capability(child.agent_id, "exploit_verify")
    assert "exploit_verify" in hierarchy.get(child.agent_id).capabilities
    assert "exploit_verify" in hierarchy.get(child.agent_id).metadata["granted_capabilities"]


def test_depth_limit_is_enforced():
    hierarchy = AgentHierarchy(root_capabilities=["recon"], max_depth=2)
    first = hierarchy.add_child("root", "recon", "level 1")
    second = hierarchy.add_child(first.agent_id, "endpoint_mapper", "level 2")
    with pytest.raises(HierarchyError):
        hierarchy.add_child(second.agent_id, "too_deep", "level 3")


def test_child_limit_is_enforced():
    hierarchy = AgentHierarchy(root_capabilities=["recon"], max_children=2)
    hierarchy.add_child("root", "a", "one")
    hierarchy.add_child("root", "b", "two")
    with pytest.raises(HierarchyError):
        hierarchy.add_child("root", "c", "three")


def test_kill_terminates_subtree():
    hierarchy = AgentHierarchy(root_capabilities=["recon"])
    parent = hierarchy.add_child("root", "recon", "level 1")
    child = hierarchy.add_child(parent.agent_id, "endpoint_mapper", "level 2")
    killed = hierarchy.kill(parent.agent_id, "operator stop")
    assert set(killed) == {parent.agent_id, child.agent_id}
    assert hierarchy.get(child.agent_id).status is AgentStatus.KILLED
    assert hierarchy.get(parent.agent_id).metadata["kill_reason"] == "operator stop"


def test_replace_transfers_children():
    hierarchy = AgentHierarchy(root_capabilities=["recon"])
    parent = hierarchy.add_child("root", "recon", "level 1")
    child = hierarchy.add_child(parent.agent_id, "endpoint_mapper", "level 2")
    replacement = hierarchy.replace(parent.agent_id, "recon")
    assert hierarchy.get(parent.agent_id).status is AgentStatus.REPLACED
    assert replacement.children == [child.agent_id]
    assert hierarchy.get(child.agent_id).parent_id == replacement.agent_id


def test_only_ancestors_may_command():
    hierarchy = AgentHierarchy(root_capabilities=["recon"])
    parent = hierarchy.add_child("root", "recon", "level 1")
    other = hierarchy.add_child("root", "hunter", "level 1")
    assert hierarchy.may_command("root", parent.agent_id)
    assert hierarchy.may_command(parent.agent_id, other.agent_id) is False


def test_hierarchy_round_trips_through_disk(tmp_path: Path):
    hierarchy = AgentHierarchy(root_capabilities=["recon"])
    hierarchy.add_child("root", "recon", "map")
    path = tmp_path / "hierarchy.json"
    hierarchy.save(str(path))
    restored = AgentHierarchy.load(str(path))
    assert len(restored.nodes()) == len(hierarchy.nodes())
    assert restored.root.capabilities == hierarchy.root.capabilities


# ---------------------------------------------------------------------------
# shared memory
# ---------------------------------------------------------------------------

def test_memory_persists_across_instances(tmp_path: Path):
    path = str(tmp_path / "memory.jsonl")
    first = SharedMemory(path)
    first.write(Namespace.LEAD, "idor-invoice", {"title": "IDOR"}, agent_id="recon-1")
    second = SharedMemory(path)
    assert second.read(Namespace.LEAD, "idor-invoice") == {"title": "IDOR"}
    assert second.stats()["records"] == 1


def test_memory_hash_chain_detects_tampering(tmp_path: Path):
    path = tmp_path / "memory.jsonl"
    memory = SharedMemory(str(path))
    memory.write(Namespace.LEAD, "lead-1", "value")
    memory.write(Namespace.LEAD, "lead-2", "value")
    assert memory.verify_chain() is True

    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["value"] = "edited"
    lines[0] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert SharedMemory(str(path)).verify_chain() is False


def test_memory_redacts_secrets():
    payload = {
        "note": "found key AKIAIOSFODNN7EXAMPLE in bucket config",
        "token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    }
    redacted = redact_secrets(payload)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(redacted)
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in json.dumps(redacted)
    assert "redacted" in redacted["note"]


def test_memory_write_redacts_before_storage(tmp_path: Path):
    memory = SharedMemory(str(tmp_path / "memory.jsonl"))
    memory.write(Namespace.CREDENTIAL_FINDING, "aws", {"key": "AKIAIOSFODNN7EXAMPLE"})
    stored = memory.read(Namespace.CREDENTIAL_FINDING, "aws")
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(stored)


def test_memory_search_finds_leads(tmp_path: Path):
    memory = SharedMemory(str(tmp_path / "memory.jsonl"))
    memory.write(Namespace.LEAD, "ssrf-metadata", "SSRF to 169.254.169.254")
    memory.write(Namespace.NOTE, "misc", "nothing interesting")
    hits = memory.search("169.254", namespaces=[Namespace.LEAD])
    assert len(hits) == 1
    assert hits[0]["key"] == "ssrf-metadata"


# ---------------------------------------------------------------------------
# permission gate
# ---------------------------------------------------------------------------

def test_policy_denies_everything_without_a_grant(tmp_path: Path):
    controller = make_controller(tmp_path)
    decision = controller.policy.check(
        controller.hierarchy.root, "https://example.com/", "read_only"
    )
    assert decision.allowed is False
    assert "fail-closed" in decision.reason


def test_policy_allows_in_scope_target_with_signed_grant(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    controller = make_controller(tmp_path, policy=policy)
    decision = controller.policy.check(
        controller.hierarchy.root, "https://api.example.com/login", "active_test"
    )
    assert decision.allowed is True
    assert decision.audit_id


def test_policy_denies_out_of_scope_target(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    controller = make_controller(tmp_path, policy=policy)
    decision = controller.policy.check(
        controller.hierarchy.root, "https://example.org/", "read_only"
    )
    assert decision.allowed is False
    assert "scope" in decision.reason.lower()


def test_policy_denies_agent_without_required_capability(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    controller = make_controller(tmp_path, policy=policy)
    child = controller.spawn("reporter", "write the report", capabilities=["recon"])
    decision = controller.policy.check(
        child, "https://api.example.com/", "exploit_proof"
    )
    assert decision.allowed is False
    assert "capability" in decision.reason


def test_policy_denies_hard_invariant_operation(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    controller = make_controller(tmp_path, policy=policy)
    decision = controller.policy.check(
        controller.hierarchy.root,
        "https://api.example.com/",
        "active_test",
        operation="upload webshell to the document endpoint",
    )
    assert decision.allowed is False
    assert "invariant" in decision.reason


def test_permission_set_algebra():
    parent = PermissionSet.from_iterable(["recon", "scan"])
    child = PermissionSet.from_iterable(["recon"])
    assert child.is_subset_of(parent)
    assert parent.intersect(child).to_list() == ["recon"]
    assert "scan" in parent
    assert len(parent.union(child)) == 2


# ---------------------------------------------------------------------------
# controller behaviour
# ---------------------------------------------------------------------------

def test_spawn_records_an_event_in_shared_memory(tmp_path: Path):
    controller = make_controller(tmp_path)
    node = controller.spawn("recon", "map the estate")
    events = controller.memory.history(Namespace.EVENT)
    assert any(
        event.get("key") == "agent_spawned"
        and event.get("value", {}).get("agent_id") == node.agent_id
        for event in events
    )


def test_controller_denies_tool_call_without_a_grant(tmp_path: Path):
    controller = make_controller(tmp_path)
    result = controller.run_tool_sync(
        "root",
        "httpx",
        {"target": "https://example.com"},
        target="https://example.com",
        action_class="read_only",
    )
    assert result.ok is False
    assert result.error_category == "POLICY_DENIED"


def test_grant_capability_is_audited(tmp_path: Path):
    controller = make_controller(tmp_path)
    child = controller.spawn("recon", "map", capabilities=["recon"])
    controller.grant_capability(child.agent_id, "exploit_verify", reason="signed grant ENG-1")
    events = controller.memory.history(Namespace.EVENT)
    assert any(event.get("key") == "capability_granted" for event in events)


def test_export_state_writes_hierarchy_and_memory(tmp_path: Path):
    controller = make_controller(tmp_path)
    controller.spawn("recon", "map the estate")
    controller.record_lead("recon", "lead-1", "detail", target="https://example.com")
    path = controller.export_state(str(tmp_path / "state.json"))
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    assert "hierarchy" in payload
    assert payload["memory"]["lead"]["lead-1"]["title"] == "lead-1"


# ---------------------------------------------------------------------------
# end-to-end dispatch
# ---------------------------------------------------------------------------

def test_run_tool_dispatches_when_the_policy_allows(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    registry = ToolRegistry(policy_engine=policy.engine)
    registry.register(_FakeProbe())
    controller = make_controller(tmp_path, policy=policy, registry=registry)

    result = controller.run_tool_sync(
        "root",
        "fake.probe",
        {"target": "https://api.example.com"},
        target="https://api.example.com",
        action_class="read_only",
    )
    assert result.ok is True
    assert "probe" in str(result.output)
    assert "api.example.com" in str(result.output)


def test_run_tool_is_blocked_out_of_scope_even_with_a_grant(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    registry = ToolRegistry(policy_engine=policy.engine)
    registry.register(_FakeProbe())
    controller = make_controller(tmp_path, policy=policy, registry=registry)

    result = controller.run_tool_sync(
        "root",
        "fake.probe",
        {"target": "https://example.org/"},
        target="https://example.org/",
        action_class="read_only",
    )
    assert result.ok is False
    assert result.error_category == "POLICY_DENIED"


def test_run_tool_records_the_execution_in_shared_memory(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    registry = ToolRegistry(policy_engine=policy.engine)
    registry.register(_FakeProbe())
    controller = make_controller(tmp_path, policy=policy, registry=registry)

    controller.run_tool_sync(
        "root",
        "fake.probe",
        {"target": "https://api.example.com"},
        target="https://api.example.com",
        action_class="read_only",
    )
    events = controller.memory.history(Namespace.EVENT)
    assert any(event.get("key") == "tool_executed" for event in events)


# ---------------------------------------------------------------------------
# arsenal coverage
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_arsenal_coverage_counts_installed_tools(tmp_path: Path):
    manifest = tmp_path / "tools_mcp.json"
    manifest.write_text(
        json.dumps(
            {
                "tiers": {
                    "recon": {
                        "risk": "low",
                        "action_class": "read_only",
                        "requires_authorization": False,
                        "tools": ["httpx", "subfinder"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    arsenal = Arsenal.load(
        str(manifest),
        probe=lambda name: "/usr/bin/" + name if name == "httpx" else None,
    )
    coverage = arsenal.coverage()
    assert coverage["total"] == 2
    assert coverage["installed"] == 1
    assert coverage["missing"] == 1
    assert coverage["coverage_pct"] == 50.0


def test_arsenal_plan_lists_install_packages():
    arsenal = Arsenal.load(
        str(REPO_ROOT / "tools_mcp.json"), probe=lambda name: None
    )
    plan = arsenal.plan()
    assert "nmap" in plan["apt"]
    assert "metasploit-framework" in plan["apt"] or "sqlmap" in plan["apt"]
    assert "zigbee2mqtt" in plan["npm"]


def test_arsenal_surfaces_tier_constraints():
    arsenal = Arsenal.load(
        str(REPO_ROOT / "tools_mcp.json"), probe=lambda name: None
    )
    constraints = arsenal.coverage()["tiers"]["credential_review"]["constraints"]
    assert any("wordlists" in item for item in constraints)
    assert any("credential_dump" in item for item in constraints)


def test_arsenal_reports_installed_paths():
    arsenal = Arsenal.load(
        str(REPO_ROOT / "tools_mcp.json"),
        probe=lambda name: f"/usr/bin/{name}" if name == "nmap" else None,
    )
    entry = next(e for e in arsenal.entries if e.name == "nmap")
    assert entry.installed is True
    assert entry.path == "/usr/bin/nmap"
    assert entry.package == "nmap"


# ---------------------------------------------------------------------------
# playbook planning and execution
# ---------------------------------------------------------------------------

def test_playbook_plan_renders_commands_with_context():
    runner = PlaybookRunner(probe=lambda name: f"/usr/bin/{name}")
    steps = runner.plan("example.com", stage_keys=["passive_subdomains"])
    assert steps
    first = steps[0]
    assert first.tool == "subfinder"
    assert first.action_class == "read_only"
    assert "subfinder -d example.com" in first.command
    assert first.ready is True


def test_playbook_plan_blocks_missing_binaries_and_env():
    runner = PlaybookRunner(probe=lambda name: None, env={})
    steps = runner.plan("example.com", stage_keys=["passive_subdomains"])
    subfinder_step = next(s for s in steps if s.key == "subfinder_basic")
    assert subfinder_step.ready is False
    assert "subfinder" in subfinder_step.missing_binaries
    chaos_step = next(s for s in steps if s.key == "chaos")
    assert "PDCP_API_KEY" in chaos_step.missing_env


def test_playbook_execution_denies_out_of_scope_target(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    controller = make_controller(tmp_path, policy=policy)
    runner = PlaybookRunner(probe=lambda name: f"/usr/bin/{name}")
    steps = runner.plan("example.org", stage_keys=["passive_subdomains"])

    outcomes = asyncio.run(
        runner.execute(controller, "root", steps, target="example.org", dry_run=False)
    )
    assert outcomes
    assert all(outcome["status"] == "denied" for outcome in outcomes)
    assert all("scope" in outcome["reason"].lower() for outcome in outcomes)


def test_playbook_execution_runs_a_registered_tool(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    registry = ToolRegistry(policy_engine=policy.engine)
    registry.register(_FakeSubfinder())
    controller = make_controller(tmp_path, policy=policy, registry=registry)
    runner = PlaybookRunner(probe=lambda name: f"/usr/bin/{name}")
    steps = runner.plan("example.com", stage_keys=["passive_subdomains"])

    outcomes = asyncio.run(
        runner.execute(controller, "root", steps, target="example.com", dry_run=False)
    )
    statuses = {outcome["key"]: outcome["status"] for outcome in outcomes}
    assert statuses["subfinder_basic"] == "executed"
    assert statuses["subfinder_deep"] == "executed"


def test_playbook_execution_hands_unregistered_tools_to_the_operator(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    registry = ToolRegistry(policy_engine=policy.engine)
    controller = make_controller(tmp_path, policy=policy, registry=registry)
    runner = PlaybookRunner(probe=lambda name: f"/usr/bin/{name}")
    steps = runner.plan("example.com", stage_keys=["passive_subdomains"])

    outcomes = asyncio.run(
        runner.execute(controller, "root", steps, target="example.com", dry_run=False)
    )
    statuses = {outcome["key"]: outcome["status"] for outcome in outcomes}
    # assetfinder is catalogued by the playbook but not registered in the
    # registry, so the operator gets the rendered command instead of a run.
    assert statuses["assetfinder"] == "manual"
    assert "not registered" in next(
        o["reason"] for o in outcomes if o["key"] == "assetfinder"
    )


def test_playbook_execution_marks_blocked_steps(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    controller = make_controller(tmp_path, policy=policy)
    runner = PlaybookRunner(probe=lambda name: None)
    steps = runner.plan("example.com", stage_keys=["passive_subdomains"])

    outcomes = asyncio.run(
        runner.execute(controller, "root", steps, target="example.com", dry_run=False)
    )
    statuses = {outcome["key"]: outcome["status"] for outcome in outcomes}
    assert statuses["subfinder_basic"] == "blocked"
    assert "missing binaries" in next(
        o["reason"] for o in outcomes if o["key"] == "subfinder_basic"
    )


def test_playbook_steps_are_recorded_in_shared_memory(tmp_path: Path):
    grant_path = make_grant(tmp_path)
    policy = PermissionPolicy.from_grant(grant_path, Profile.RED_TEAM, secret=SECRET)
    controller = make_controller(tmp_path, policy=policy)
    runner = PlaybookRunner(probe=lambda name: None)
    steps = runner.plan("example.com", stage_keys=["passive_subdomains"])
    asyncio.run(runner.execute(controller, "root", steps, target="example.com", dry_run=False))

    events = controller.memory.history(Namespace.EVENT)
    assert any(event.get("key") == "playbook_step" for event in events)
