"""Playbook-driven roles for the root controller.

The repository already carries a recon methodology playbook with risk-labelled
executable stages (``core/playbooks/recon_methodology.py``).  This module binds
that playbook to the hierarchy: a role carries a playbook, the playbook's
stages become the agent's phases, and every command is planned against the
installed arsenal before anything is allowed to run.

Execution never bypasses the gate.  A step that the policy engine denies is
denied; a step whose binary, environment, or context is missing is blocked,
not faked; a step whose tool is not registered in the tool registry is handed
back to the operator as a rendered command line rather than shelled out.

Python 3.11, standard library only.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

__all__ = ["PlaybookRunner", "PlaybookStep", "TOOL_RISK"]

# Risk level per tool, used when the policy engine weighs an action.
TOOL_RISK: Dict[str, str] = {
    "assetfinder": "low",
    "arjun": "low",
    "dnsx": "low",
    "ffuf": "medium",
    "gau": "low",
    "httpx": "low",
    "katana": "low",
    "masscan": "medium",
    "naabu": "medium",
    "nmap": "medium",
    "nuclei": "high",
    "paramspider": "low",
    "sqlmap": "high",
    "subfinder": "low",
    "testssl.sh": "medium",
    "wafw00f": "low",
    "whatweb": "low",
}

_RISK_TO_ACTION_CLASS = {
    "safe": "read_only",
    "active": "active_test",
    "intrusive": "active_test",
}


@dataclass(frozen=True)
class PlaybookStep:
    """One planned command from a playbook stage."""

    stage_key: str
    stage_title: str
    stage_objective: str
    key: str
    tool: str
    purpose: str
    risk: str
    action_class: str
    risk_level: str
    command: str = ""
    requires: Tuple[str, ...] = ()
    missing_binaries: Tuple[str, ...] = ()
    requires_env: Tuple[str, ...] = ()
    missing_env: Tuple[str, ...] = ()
    requires_context: Tuple[str, ...] = ()
    missing_context: Tuple[str, ...] = ()
    ready: bool = False
    blocked_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage_key,
            "stage_title": self.stage_title,
            "key": self.key,
            "tool": self.tool,
            "purpose": self.purpose,
            "risk": self.risk,
            "action_class": self.action_class,
            "risk_level": self.risk_level,
            "command": self.command,
            "requires": list(self.requires),
            "missing_binaries": list(self.missing_binaries),
            "requires_env": list(self.requires_env),
            "missing_env": list(self.missing_env),
            "requires_context": list(self.requires_context),
            "missing_context": list(self.missing_context),
            "ready": self.ready,
            "blocked_reason": self.blocked_reason,
        }


@dataclass
class PlaybookRunner:
    """Plans and runs playbook stages through the controller's gate."""

    probe: Callable[[str], Optional[str]] = lambda name: shutil.which(name)
    env: Mapping[str, str] = field(default_factory=lambda: os.environ)
    stages_module: str = "core.playbooks.recon_methodology"

    # -- planning ----------------------------------------------------------
    def _module(self) -> Any:
        import importlib

        return importlib.import_module(self.stages_module)

    def stage_keys(self) -> List[str]:
        module = self._module()
        return [stage.key for stage in module.EXECUTABLE_STAGES]

    def plan(
        self,
        target: str,
        *,
        stage_keys: Optional[Iterable[str]] = None,
        wordlist: str = "",
        resolvers: str = "",
        out_dir: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> List[PlaybookStep]:
        """Build the step list for a target; nothing executes here."""
        module = self._module()
        ctx = module.build_context(
            target,
            out_dir=out_dir,
            wordlist=wordlist,
            resolvers=resolvers,
            **dict(context or {}),
        )
        steps: List[PlaybookStep] = []
        for stage in module.selected_stages(stage_keys):
            for command in stage.commands:
                steps.append(self._step(module, stage, command, ctx))
        return steps

    def _step(self, module: Any, stage: Any, command: Any, ctx: Dict[str, str]) -> PlaybookStep:
        missing_binaries = tuple(
            binary for binary in command.requires if not self.probe(binary)
        )
        missing_env = tuple(
            name for name in command.requires_env if not self.env.get(name)
        )
        missing_context = tuple(
            name for name in command.requires_context if not ctx.get(name)
        )
        rendered = ""
        render_error = ""
        try:
            rendered = module.render_command(command.template, ctx)
        except Exception as exc:  # noqa: BLE001 - surfaced as a blocked step
            render_error = str(exc)

        blockers: List[str] = []
        if missing_binaries:
            blockers.append("missing binaries: " + ", ".join(missing_binaries))
        if missing_env:
            blockers.append("missing env: " + ", ".join(missing_env))
        if missing_context:
            blockers.append("missing context: " + ", ".join(missing_context))
        if render_error:
            blockers.append(render_error)

        action_class = _RISK_TO_ACTION_CLASS.get(command.risk, "active_test")
        risk_level = TOOL_RISK.get(
            command.tool, "low" if command.risk == "safe" else "medium"
        )
        return PlaybookStep(
            stage_key=stage.key,
            stage_title=stage.title,
            stage_objective=stage.objective,
            key=command.key,
            tool=command.tool,
            purpose=command.purpose,
            risk=command.risk,
            action_class=action_class,
            risk_level=risk_level,
            command=rendered,
            requires=tuple(command.requires),
            missing_binaries=missing_binaries,
            requires_env=tuple(command.requires_env),
            missing_env=missing_env,
            requires_context=tuple(command.requires_context),
            missing_context=missing_context,
            ready=not blockers,
            blocked_reason="; ".join(blockers),
        )

    # -- rendering ---------------------------------------------------------
    def render_plan(self, steps: List[PlaybookStep]) -> str:
        lines: List[str] = []
        current_stage = ""
        for step in steps:
            if step.stage_key != current_stage:
                current_stage = step.stage_key
                lines.append("")
                lines.append(f"[{current_stage}] {step.stage_title}")
            mark = "ok " if step.ready else "blk"
            lines.append(
                f"  {mark} {step.key:<22} {step.tool:<18} "
                f"{step.action_class:<13} {step.risk_level:<7} {step.purpose}"
            )
            if step.blocked_reason:
                lines.append(f"       ! {step.blocked_reason}")
            if step.command:
                lines.append(f"       $ {step.command}")
        ready = sum(1 for step in steps if step.ready)
        lines.append("")
        lines.append(f"steps: {len(steps)}  ready: {ready}  blocked: {len(steps) - ready}")
        return "\n".join(lines)

    # -- execution ---------------------------------------------------------
    async def execute(
        self,
        controller: Any,
        agent_id: str,
        steps: List[PlaybookStep],
        *,
        target: str,
        dry_run: bool = True,
    ) -> List[Dict[str, Any]]:
        """Run planned steps through the controller's permission gate."""
        agent = controller.hierarchy.get(agent_id)
        outcomes: List[Dict[str, Any]] = []
        for step in steps:
            decision = controller.policy.check(
                agent,
                target,
                step.action_class,
                tool_id=step.tool,
                risk_level=step.risk_level,
                operation=step.command or step.purpose,
            )
            if not decision.allowed:
                outcome = {
                    "key": step.key,
                    "tool": step.tool,
                    "status": "denied",
                    "reason": decision.reason,
                    "audit_id": decision.audit_id,
                }
            elif dry_run:
                outcome = {
                    "key": step.key,
                    "tool": step.tool,
                    "status": "planned",
                    "command": step.command,
                }
            elif not step.ready:
                outcome = {
                    "key": step.key,
                    "tool": step.tool,
                    "status": "blocked",
                    "reason": step.blocked_reason,
                }
            elif controller.registry is None or controller.registry.get(step.tool) is None:
                outcome = {
                    "key": step.key,
                    "tool": step.tool,
                    "status": "manual",
                    "command": step.command,
                    "reason": "tool is not registered in the tool registry",
                }
            else:
                result = await controller.run_tool(
                    agent_id,
                    step.tool,
                    {"target": target},
                    target=target,
                    action_class=step.action_class,
                    risk_level=step.risk_level,
                    operation=step.command or step.purpose,
                )
                outcome = {
                    "key": step.key,
                    "tool": step.tool,
                    "status": "executed" if getattr(result, "ok", False) else "failed",
                    "error": getattr(result, "error", None),
                    "audit_id": getattr(result, "audit_event_id", None),
                }
            outcomes.append(outcome)
            controller.memory.record_event(
                "playbook_step", outcome, agent_id=agent_id
            )
        return outcomes
