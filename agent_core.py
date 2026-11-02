#!/usr/bin/env python3
"""agent_core.py — entry point for the HunterAI root controller.

Loads the controller artifacts from the repository root:

    agent_config.json    runtime configuration
    hierarchy.json       role catalogue and tree rules
    permissions.json    capability catalogue and profile map
    tools_mcp.json      tool / MCP surface manifest
    rules.txt           operating rules injected into agent context
    system_prompt.md    the root controller's own prompt

and drives ``core.root_controller.RootController``: the single root that owns
the recursive agent hierarchy, the shared memory, and the permission gate in
front of every tool execution.

Usage
-----
    python agent_core.py status
    python agent_core.py tree
    python agent_core.py spawn --role recon --objective "map api.example.com"
    python agent_core.py delegate --parent recon-ab12cd34 --role endpoint_mapper --objective "..."
    python agent_core.py grant --agent recon-ab12cd34 --capability exploit_verify --reason "signed grant ENG-1"
    python agent_core.py run --agent recon-ab12cd34 --tool httpx --target https://api.example.com
    python agent_core.py lead --agent recon-ab12cd34 --title "IDOR on /api/invoice" --target https://api.example.com
    python agent_core.py check --target https://api.example.com --action-class exploit_proof
    python agent_core.py export --out data/root_controller/state.json

Python 3.11.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(REPO_ROOT / ".env")
except Exception:
    pass

from core.policy.red_team import Profile  # noqa: E402
from core.root_controller import (  # noqa: E402
    AgentHierarchy,
    HierarchyError,
    PermissionPolicy,
    RootController,
    SharedMemory,
)

CONFIG_PATH = REPO_ROOT / "agent_config.json"


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def load_config(path: Path = CONFIG_PATH) -> Dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"missing controller configuration: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def resolve(path_value: str) -> Path:
    candidate = Path(path_value)
    return candidate if candidate.is_absolute() else REPO_ROOT / candidate


def load_role_catalogue(config: Dict[str, Any]) -> Dict[str, Any]:
    hierarchy_file = resolve(config.get("paths", {}).get("hierarchy", "hierarchy.json"))
    if not hierarchy_file.exists():
        return {}
    return json.loads(hierarchy_file.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Controller assembly
# ---------------------------------------------------------------------------

def build_controller(
    config: Dict[str, Any],
    *,
    grant_path: Optional[str] = None,
    profile_name: str = "red_team",
    with_registry: bool = True,
) -> RootController:
    """Assemble the controller from config plus (optionally) a signed grant."""
    catalogue = load_role_catalogue(config)
    root_spec = catalogue.get("root", {})
    tree_rules = config.get("hierarchy", {})

    hierarchy = AgentHierarchy(
        root_role=config.get("root_role", "root_controller"),
        root_objective=root_spec.get("objective", "Own the engagement."),
        root_capabilities=root_spec.get(
            "capabilities", tree_rules.get("default_child_capabilities", [])
        ),
        max_depth=int(tree_rules.get("max_depth", 4)),
        max_children=int(tree_rules.get("max_children", 6)),
    )

    state_file = resolve(
        config.get("state", {}).get("hierarchy_state", "data/root_controller/hierarchy.json")
    )
    if state_file.exists():
        try:
            hierarchy = AgentHierarchy.load(str(state_file))
        except (ValueError, KeyError, OSError):
            pass  # corrupt state must not silently widen the tree; start clean

    memory = SharedMemory(
        str(resolve(config.get("memory", {}).get("path", "data/root_controller/memory.jsonl")))
    )

    policy_config = config.get("policy", {})
    profile = Profile(profile_name)
    engine = None
    effective_grant = grant_path or policy_config.get("grant_path")
    if effective_grant:
        policy = PermissionPolicy.from_grant(
            str(resolve(effective_grant)),
            profile,
            audit_log=None,
        )
        engine = policy.engine
    else:
        policy = PermissionPolicy(
            profile=profile,
            capabilities=policy_config.get("capabilities"),
            fail_closed=bool(policy_config.get("fail_closed", True)),
        )

    registry = None
    if with_registry:
        from core.tool_registry import ToolRegistry

        registry = ToolRegistry(policy_engine=engine)

    paths = config.get("paths", {})
    return RootController(
        hierarchy=hierarchy,
        memory=memory,
        policy=policy,
        registry=registry,
        rules_path=str(resolve(paths.get("rules", "rules.txt"))),
        prompt_path=str(resolve(paths.get("system_prompt", "system_prompt.md"))),
    )


def save_state(controller: RootController, config: Dict[str, Any]) -> None:
    state_file = resolve(
        config.get("state", {}).get("hierarchy_state", "data/root_controller/hierarchy.json")
    )
    controller.hierarchy.save(str(state_file))


def resolve_agent_id(controller: RootController, value: str) -> str:
    """Resolve an agent id, or a unique role name, to a concrete agent id."""
    if not value:
        return "root"
    try:
        controller.hierarchy.get(value)
        return value
    except HierarchyError:
        pass
    matches = [
        node.agent_id
        for node in controller.hierarchy.active_nodes()
        if node.role == value
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise SystemExit(f"no active agent matches '{value}'")
    raise SystemExit(
        f"'{value}' matches several active agents; use the full id: "
        + ", ".join(matches)
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    print("=== HunterAI root controller ===")
    print(f"profile        : {controller.policy.profile.value}")
    print(f"grant bound    : {controller.policy.bound} {controller.policy.grant_id()}")
    print(f"scope          : {', '.join(controller.policy.scope_targets()) or '(none)'}")
    print(f"root caps      : {', '.join(controller.hierarchy.root.capabilities)}")
    print()
    print(controller.render_tree())
    print()
    print(json.dumps(controller.memory.stats(), indent=2))
    return 0


def cmd_tree(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    print(controller.render_tree())
    return 0


def cmd_spawn(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    catalogue = load_role_catalogue(config)
    role_spec = next(
        (r for r in catalogue.get("roles", []) if r.get("role") == args.role), {}
    )
    node = controller.spawn(
        args.role,
        args.objective,
        parent_id=resolve_agent_id(controller, args.parent),
        capabilities=args.capabilities or role_spec.get("capabilities"),
        tool_ids=role_spec.get("tools"),
        model=config.get("model", ""),
        metadata={"playbook": role_spec["playbook"]} if role_spec.get("playbook") else None,
    )
    save_state(controller, config)
    print(f"spawned {node.agent_id} role={node.role} depth={node.depth}")
    print(f"capabilities: {', '.join(node.capabilities) or '(none)'}")
    return 0


def cmd_delegate(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    catalogue = load_role_catalogue(config)
    role_spec = next(
        (r for r in catalogue.get("roles", []) if r.get("role") == args.role), {}
    )
    node = controller.delegate(
        resolve_agent_id(controller, args.parent),
        args.role,
        args.objective,
        capabilities=args.capabilities or role_spec.get("capabilities"),
        tool_ids=role_spec.get("tools"),
        model=config.get("model", ""),
    )
    save_state(controller, config)
    print(f"delegated {node.agent_id} role={node.role} parent={node.parent_id} depth={node.depth}")
    return 0


def cmd_grant(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    node = controller.grant_capability(
        resolve_agent_id(controller, args.agent),
        args.capability,
        reason=args.reason or "operator instruction",
    )
    save_state(controller, config)
    print(f"{node.agent_id} capabilities: {', '.join(node.capabilities)}")
    return 0


def cmd_retask(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    node = controller.retask(resolve_agent_id(controller, args.agent), args.objective)
    save_state(controller, config)
    print(f"retasked {node.agent_id}: {node.objective}")
    return 0


def cmd_terminate(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    killed = controller.terminate(
        resolve_agent_id(controller, args.agent), args.reason or "operator instruction"
    )
    save_state(controller, config)
    print("terminated: " + ", ".join(killed))
    return 0


def cmd_replace(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    node = controller.replace(resolve_agent_id(controller, args.agent), args.role)
    save_state(controller, config)
    print(f"replaced {args.agent} -> {node.agent_id} role={node.role}")
    return 0


def cmd_lead(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    controller.record_lead(
        resolve_agent_id(controller, args.agent),
        args.title,
        args.detail,
        target=args.target,
        tags=args.tag or (),
    )
    print(f"lead recorded: {args.title}")
    return 0


def cmd_evidence(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    payload: Any = args.detail
    if args.json:
        payload = json.loads(args.detail)
    controller.record_evidence(
        resolve_agent_id(controller, args.agent), args.key, payload, tags=args.tag or ()
    )
    print(f"evidence recorded: {args.key}")
    return 0


def cmd_run(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    arguments: Dict[str, Any] = json.loads(args.args) if args.args else {}
    arguments.setdefault("target", args.target)
    result = asyncio.run(
        controller.run_tool(
            resolve_agent_id(controller, args.agent),
            args.tool,
            arguments,
            target=args.target,
            action_class=args.action_class,
            risk_level=args.risk,
            operation=args.operation or f"{args.tool} on {args.target}",
        )
    )
    print(json.dumps(result.to_dict() if hasattr(result, "to_dict") else result.__dict__,
                     indent=2, default=str))
    return 0 if getattr(result, "ok", False) else 2


def cmd_check(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    agent = (
        controller.hierarchy.get(resolve_agent_id(controller, args.agent))
        if args.agent
        else controller.hierarchy.root
    )
    decision = controller.policy.check(
        agent,
        args.target,
        args.action_class,
        tool_id=args.tool or "",
        risk_level=args.risk,
        operation=args.operation or "policy pre-check",
    )
    print(json.dumps(decision.to_dict(), indent=2))
    return 0 if decision.allowed else 2


def cmd_tools(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    if controller.registry is None:
        print("no tool registry bound")
        return 1
    definitions = controller.registry.list_tools()
    for definition in definitions:
        print(
            f"{definition.tool_id:<28} risk={definition.risk_level:<8} "
            f"scope_relevant={definition.scope_relevant} enabled={definition.enabled}"
        )
    return 0


def cmd_arsenal(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    """Measure the tool surface: what is catalogued, what is installed, what is missing."""
    from core.root_controller import Arsenal

    manifest = resolve(config.get("paths", {}).get("tools", "tools_mcp.json"))
    arsenal = Arsenal.load(str(manifest))
    if args.wsl:
        arsenal.scan_wsl()
    if args.json:
        print(json.dumps(arsenal.rows(), indent=2, ensure_ascii=False))
        return 0
    if args.plan:
        plan = arsenal.plan()
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        if plan["apt"]:
            print("\napt install -y " + " ".join(plan["apt"]))
        if plan["pip"]:
            print("pip install " + " ".join(plan["pip"]))
        if plan["npm"]:
            print("npm install -g " + " ".join(plan["npm"]))
        return 0
    print(arsenal.render())
    return 0


def cmd_playbook(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    """Plan (and optionally run) a methodology playbook through the gate."""
    from core.root_controller import PlaybookRunner

    runner = PlaybookRunner()
    context: Dict[str, str] = {}
    for pair in args.context or []:
        if "=" not in pair:
            print(f"invalid --context entry (expected key=value): {pair}", file=sys.stderr)
            return 2
        key, value = pair.split("=", 1)
        context[key.strip()] = value.strip()

    try:
        steps = runner.plan(
            args.target,
            stage_keys=args.stage,
            wordlist=args.wordlist or "",
            resolvers=args.resolvers or "",
            out_dir=str(resolve(args.out)) if args.out else None,
            context=context,
        )
    except ValueError as exc:
        print(f"playbook error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([step.to_dict() for step in steps], indent=2, ensure_ascii=False))
        return 0

    print(runner.render_plan(steps))

    if not args.agent:
        return 0
    if not args.execute:
        print("\n(dry plan only — pass --execute with --agent to run the gate)")
        return 0

    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    agent_id = resolve_agent_id(controller, args.agent)
    outcomes = asyncio.run(
        runner.execute(
            controller,
            agent_id,
            steps,
            target=args.target,
            dry_run=False,
        )
    )
    print("\n=== execution ===")
    for outcome in outcomes:
        detail = outcome.get("reason") or outcome.get("error") or outcome.get("command") or ""
        print(f"{outcome['status']:<9} {outcome['key']:<22} {detail}")
    return 0


def cmd_rules(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    rules = controller.rules()
    for index, rule in enumerate(rules, start=1):
        print(f"{index:>2}. {rule}")
    return 0


def cmd_prompt(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    print(controller.system_prompt())
    return 0


def cmd_context(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    context = controller.context_for(resolve_agent_id(controller, args.agent))
    print(json.dumps(context, indent=2, default=str))
    return 0


def cmd_export(args: argparse.Namespace, config: Dict[str, Any]) -> int:
    controller = build_controller(config, grant_path=args.grant, profile_name=args.profile)
    path = controller.export_state(str(resolve(args.out)))
    print(f"state exported to {path}")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent_core.py", description="HunterAI root controller"
    )
    parser.add_argument("--grant", help="path to a signed authorization grant")
    parser.add_argument(
        "--profile",
        default="red_team",
        choices=[p.value for p in Profile],
        help="execution profile",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="show controller state").set_defaults(func=cmd_status)
    sub.add_parser("tree", help="print the agent tree").set_defaults(func=cmd_tree)
    sub.add_parser("rules", help="print the operating rules").set_defaults(func=cmd_rules)
    sub.add_parser("prompt", help="print the root controller prompt").set_defaults(func=cmd_prompt)

    playbook = sub.add_parser(
        "playbook", help="plan a methodology playbook and run it through the gate"
    )
    playbook.add_argument("--target", required=True, help="host, host:port, or base URL")
    playbook.add_argument("--stage", nargs="*", help="stage keys to include")
    playbook.add_argument("--wordlist", default="", help="operator wordlist path")
    playbook.add_argument("--resolvers", default="", help="resolver list path")
    playbook.add_argument("--out", default="", help="output directory for artifacts")
    playbook.add_argument(
        "--context", nargs="*", help="extra context values as key=value"
    )
    playbook.add_argument("--json", action="store_true", help="dump the plan as JSON")
    playbook.add_argument("--agent", default="", help="agent that will run the steps")
    playbook.add_argument(
        "--execute", action="store_true", help="run the plan through the permission gate"
    )
    playbook.set_defaults(func=cmd_playbook)
    sub.add_parser("tools", help="list registered tools").set_defaults(func=cmd_tools)

    arsenal = sub.add_parser(
        "arsenal", help="measure tool coverage against the installed arsenal"
    )
    arsenal.add_argument("--json", action="store_true", help="dump every tool entry")
    arsenal.add_argument("--plan", action="store_true", help="print the install plan")
    arsenal.add_argument(
        "--wsl", action="store_true", help="also probe a WSL Kali sidecar"
    )
    arsenal.set_defaults(func=cmd_arsenal)

    spawn = sub.add_parser("spawn", help="create a child agent under the root")
    spawn.add_argument("--role", required=True)
    spawn.add_argument("--objective", default="")
    spawn.add_argument("--parent", default="root")
    spawn.add_argument("--capabilities", nargs="*")
    spawn.set_defaults(func=cmd_spawn)

    delegate = sub.add_parser("delegate", help="create a child under another agent")
    delegate.add_argument("--parent", required=True)
    delegate.add_argument("--role", required=True)
    delegate.add_argument("--objective", default="")
    delegate.add_argument("--capabilities", nargs="*")
    delegate.set_defaults(func=cmd_delegate)

    grant = sub.add_parser("grant", help="widen an agent's capability set")
    grant.add_argument("--agent", required=True)
    grant.add_argument("--capability", required=True)
    grant.add_argument("--reason", default="")
    grant.set_defaults(func=cmd_grant)

    retask = sub.add_parser("retask", help="give an agent a new objective")
    retask.add_argument("--agent", required=True)
    retask.add_argument("--objective", required=True)
    retask.set_defaults(func=cmd_retask)

    terminate = sub.add_parser("terminate", help="kill an agent and its subtree")
    terminate.add_argument("--agent", required=True)
    terminate.add_argument("--reason", default="")
    terminate.set_defaults(func=cmd_terminate)

    replace = sub.add_parser("replace", help="replace an agent with a fresh node")
    replace.add_argument("--agent", required=True)
    replace.add_argument("--role", required=True)
    replace.set_defaults(func=cmd_replace)

    lead = sub.add_parser("lead", help="record a lead on the shared board")
    lead.add_argument("--agent", required=True)
    lead.add_argument("--title", required=True)
    lead.add_argument("--detail", default="")
    lead.add_argument("--target", default="")
    lead.add_argument("--tag", nargs="*")
    lead.set_defaults(func=cmd_lead)

    evidence = sub.add_parser("evidence", help="record evidence in shared memory")
    evidence.add_argument("--agent", required=True)
    evidence.add_argument("--key", required=True)
    evidence.add_argument("--detail", default="")
    evidence.add_argument("--json", action="store_true")
    evidence.add_argument("--tag", nargs="*")
    evidence.set_defaults(func=cmd_evidence)

    run = sub.add_parser("run", help="run a tool through the permission gate")
    run.add_argument("--agent", required=True)
    run.add_argument("--tool", required=True)
    run.add_argument("--target", required=True)
    run.add_argument("--args", default="")
    run.add_argument("--action-class", default="read_only")
    run.add_argument("--risk", default="low")
    run.add_argument("--operation", default="")
    run.set_defaults(func=cmd_run)

    check = sub.add_parser("check", help="policy pre-check for an action")
    check.add_argument("--target", required=True)
    check.add_argument("--action-class", default="read_only")
    check.add_argument("--agent", default="")
    check.add_argument("--tool", default="")
    check.add_argument("--risk", default="low")
    check.add_argument("--operation", default="")
    check.set_defaults(func=cmd_check)

    context = sub.add_parser("context", help="print an agent's working context")
    context.add_argument("--agent", required=True)
    context.set_defaults(func=cmd_context)

    export = sub.add_parser("export", help="export hierarchy and memory state")
    export.add_argument("--out", default="data/root_controller/state.json")
    export.set_defaults(func=cmd_export)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config()
    try:
        return int(args.func(args, config))
    except HierarchyError as exc:
        print(f"hierarchy error: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2
    except (FileNotFoundError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
