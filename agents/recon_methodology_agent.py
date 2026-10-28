"""Recon Methodology Agent — the full operator playbook as an executable agent.

The agent exposes four modes:

- ``plan`` (default): load and expose the complete bundled methodology without
  running any external command.
- ``inventory``: list every recognized command line.
- ``dry_run``: render the selected executable commands without running them.
- ``run``: execute the selected, risk-filtered commands through ``ToolManager``.
  This requires an explicit authorization signal (``authorized=True``) or an
  attached policy gate, and intrusive commands additionally require
  ``allow_intrusive=True``.

The full raw methodology is always available; the executable layer is a
curated subset with placeholders, risk labels and tool availability checks.
No result is invented: a missing tool/context is reported as skipped.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict

from agents.base_agent import AgentResult, AgentTask, BaseAgent
from core.playbooks.recon_methodology import (
    RISK_ORDER,
    UnsafeValueError,
    build_context,
    command_inventory,
    executable_summary,
    load_methodology_text,
    methodology_summary,
    render_command,
    selected_stages,
)
from tools.tool_manager import ToolManager

_HOST_RE = re.compile(r"^(?:[a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key|password|authorization)"
    r"[\s:=]+['\"]?([A-Za-z0-9_\-./+=]{12,})"
)


class ReconMethodologyAgent(BaseAgent):
    """Executes or exposes the complete recon methodology under policy control."""

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "recon_methodology_agent",
            "Recon — full passive/active/URL/JS/parameter/port methodology",
            mgr,
            cb,
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
    async def run(self, task: AgentTask) -> AgentResult:
        target = (task.target or "").strip()
        result = AgentResult(agent_name=self.name, target=target)
        if not target:
            result.success = False
            result.errors.append("target is required")
            return result

        extra = dict(task.extra or {})
        mode = str(extra.get("mode") or "plan").strip().lower()
        if mode in ("methodology", "playbook"):
            mode = "plan"

        if mode == "plan":
            self._plan(result)
            return result
        if mode == "inventory":
            self._inventory(result)
            return result

        try:
            domain = build_context(target)["domain"]
        except Exception as exc:
            result.success = False
            result.errors.append(f"invalid target: {exc}")
            return result

        if mode not in ("dry_run", "run"):
            result.success = False
            result.errors.append(
                f"unknown mode {mode!r}; use plan, inventory, dry_run or run"
            )
            return result

        if mode == "run":
            policy_gate = getattr(self.mgr, "policy_gate", None)
            authorized = bool(extra.get("authorized", False))
            if not authorized and policy_gate is None:
                result.success = False
                result.errors.append(
                    "run mode requires authorized=True or an attached policy gate"
                )
                return result

        return await self._execute(result, task, extra, domain)

    # ------------------------------------------------------------------
    # Read-only modes
    # ------------------------------------------------------------------
    def _plan(self, result: AgentResult) -> None:
        summary = methodology_summary()
        executable = executable_summary()
        result.raw_output["methodology_text"] = load_methodology_text()
        result.raw_output["methodology_summary"] = json.dumps(summary, ensure_ascii=False)
        result.raw_output["executable_summary"] = json.dumps(executable, ensure_ascii=False)
        result.findings.append(
            {
                "type": "recon_methodology",
                "severity": "Info",
                "title": (
                    f"Recon methodology loaded: {summary['sections']} sections, "
                    f"{summary['commands']} commands, {executable['stages']} executable stages"
                ),
                "evidence": (
                    f"Bundled methodology: {summary['path']}\n"
                    f"Executable stages: {', '.join(executable['stage_keys'])}\n"
                    "Use mode=inventory to list every command, mode=dry_run to render "
                    "selected commands, or mode=run with authorized=True to execute."
                ),
                "tool": "recon_methodology",
            }
        )

    def _inventory(self, result: AgentResult) -> None:
        commands = command_inventory()
        result.raw_output["commands"] = "\n".join(commands)
        result.findings.append(
            {
                "type": "recon_methodology_inventory",
                "severity": "Info",
                "title": f"Recon methodology command inventory ({len(commands)})",
                "evidence": "\n".join(commands[:40])
                + ("\n..." if len(commands) > 40 else ""),
                "tool": "recon_methodology",
            }
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------
    async def _execute(
        self,
        result: AgentResult,
        task: AgentTask,
        extra: Dict[str, Any],
        domain: str,
    ) -> AgentResult:
        mode = str(extra.get("mode") or "run").strip().lower()
        max_risk = str(extra.get("max_risk") or "safe").strip().lower()
        if max_risk == "all":
            max_risk = "intrusive"
        if max_risk not in RISK_ORDER:
            result.success = False
            result.errors.append(f"unknown max_risk {max_risk!r}")
            return result

        allow_intrusive = bool(extra.get("allow_intrusive", False))
        if max_risk == "intrusive" and not allow_intrusive:
            result.success = False
            result.errors.append(
                "max_risk=intrusive requires allow_intrusive=True"
            )
            return result

        stage_keys = extra.get("stages") or "all"
        if isinstance(stage_keys, str) and stage_keys != "all":
            stage_keys = [s.strip() for s in stage_keys.split(",") if s.strip()]
        stages = selected_stages(stage_keys)
        if not stages:
            result.success = False
            result.errors.append(f"no matching stages for {stage_keys!r}")
            return result

        out_dir = Path(
            str(extra.get("out_dir") or Path("data") / "recon_methodology" / domain)
        )
        out_dir.mkdir(parents=True, exist_ok=True)

        wordlists = self._resolve_wordlists(extra)
        ctx = build_context(
            task.target,
            out_dir=str(out_dir),
            wordlist=wordlists["dns"],
            resolvers=str(extra.get("resolvers") or ""),
            **{
                key: extra.get(key, "")
                for key in (
                    "asn",
                    "cidr",
                    "ip",
                    "org",
                    "repo",
                    "api_key",
                    "github_token",
                    "headers_wordlist",
                    "wordlist1",
                    "wordlist2",
                    "usernames",
                    "passwords",
                    "dirs_wordlist",
                    "params_wordlist",
                )
            },
        )
        # Environment variables are operator-owned; never log their values.
        if not ctx.get("api_key"):
            ctx["api_key"] = os.getenv("PDCP_API_KEY", "")
        if not ctx.get("github_token"):
            ctx["github_token"] = os.getenv("GITHUB_TOKEN", "")

        # Keep target/domain/url normalized to forward slashes for shell use.
        for key in ("out", "wordlist", "resolvers"):
            if ctx.get(key):
                ctx[key] = ctx[key].replace("\\", "/")

        summary: Dict[str, Any] = {
            "mode": mode,
            "max_risk": max_risk,
            "stages": [s.key for s in stages],
            "executed": [],
            "skipped": [],
            "missing_tools": [],
            "missing_context": [],
            "errors": [],
        }

        for stage in stages:
            stage_wordlist = self._wordlist_for_stage(stage.key, wordlists)
            ctx["wordlist"] = stage_wordlist
            ctx["wordlist1"] = stage_wordlist
            ctx["wordlist2"] = stage_wordlist
            stage_executed = 0
            stage_skipped = 0
            for command in stage.commands:
                if RISK_ORDER[command.risk] > RISK_ORDER[max_risk]:
                    stage_skipped += 1
                    summary["skipped"].append(
                        {"command": command.key, "reason": f"risk {command.risk} > {max_risk}"}
                    )
                    continue

                missing_tools = [
                    tool for tool in command.requires if not self.mgr.is_available(tool)
                ]
                if missing_tools:
                    stage_skipped += 1
                    summary["missing_tools"].extend(missing_tools)
                    summary["skipped"].append(
                        {"command": command.key, "reason": "missing tools: " + ", ".join(missing_tools)}
                    )
                    continue

                missing_env = [
                    env for env in command.requires_env if not os.getenv(env)
                ]
                if missing_env:
                    stage_skipped += 1
                    summary["missing_context"].extend(missing_env)
                    summary["skipped"].append(
                        {"command": command.key, "reason": "missing env: " + ", ".join(missing_env)}
                    )
                    continue

                missing_context = [
                    key for key in command.requires_context if not ctx.get(key)
                ]
                if missing_context:
                    stage_skipped += 1
                    summary["missing_context"].extend(missing_context)
                    summary["skipped"].append(
                        {"command": command.key, "reason": "missing context: " + ", ".join(missing_context)}
                    )
                    continue

                try:
                    rendered = render_command(command.template, ctx)
                except (UnsafeValueError, ValueError) as exc:
                    stage_skipped += 1
                    summary["skipped"].append(
                        {"command": command.key, "reason": f"render error: {exc}"}
                    )
                    continue

                if mode == "dry_run":
                    stage_executed += 1
                    result.raw_output[command.key] = rendered
                    summary["executed"].append(
                        {"command": command.key, "stage": stage.key, "dry_run": True, "command": rendered}
                    )
                    continue

                await self.emit(
                    "tool_start",
                    {"tool": command.tool, "target": task.target, "command": command.key},
                )
                tool_result = await self.mgr.execute(rendered, timeout=command.timeout)
                stage_executed += 1
                result.raw_output[command.key] = tool_result.output
                summary["executed"].append(
                    {
                        "command": command.key,
                        "stage": stage.key,
                        "tool": command.tool,
                        "success": tool_result.success,
                        "output_file": tool_result.output_file,
                        "error": tool_result.error,
                    }
                )
                if tool_result.error:
                    summary["errors"].append(
                        {"command": command.key, "error": tool_result.error}
                    )
                    result.errors.append(f"{command.key}: {tool_result.error}")
                else:
                    self._extract_evidence(result, command.key, tool_result.output)
                await self.emit(
                    "tool_done",
                    {
                        "tool": command.tool,
                        "command": command.key,
                        "success": tool_result.success,
                        "output_file": tool_result.output_file,
                    },
                )

            result.findings.append(
                {
                    "type": "recon_methodology_stage",
                    "severity": "Info",
                    "title": f"Recon stage: {stage.title}",
                    "evidence": (
                        f"stage={stage.key}\n"
                        f"executed={stage_executed}\n"
                        f"skipped={stage_skipped}\n"
                        f"objective={stage.objective}"
                    ),
                    "tool": "recon_methodology",
                }
            )

        summary["missing_tools"] = sorted(set(summary["missing_tools"]))
        summary["missing_context"] = sorted(set(summary["missing_context"]))
        result.raw_output["execution_summary"] = json.dumps(summary, ensure_ascii=False, indent=2)
        await self.emit(
            "complete",
            {
                "findings": len(result.findings),
                "executed": len(summary["executed"]),
                "skipped": len(summary["skipped"]),
            },
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _wordlist_for_stage(stage_key: str, wordlists: Dict[str, str]) -> str:
        if stage_key in ("directory_discovery",):
            return wordlists.get("directories") or wordlists.get("dns") or ""
        if stage_key in ("hidden_parameters",):
            return wordlists.get("parameters") or wordlists.get("directories") or wordlists.get("dns") or ""
        return wordlists.get("dns") or ""

    def _resolve_wordlists(self, extra: Dict[str, Any]) -> Dict[str, str]:
        """Resolve wordlists without assuming Kali is installed."""
        explicit = extra.get("wordlist")
        if explicit:
            value = str(explicit).replace("\\", "/")
            return {"dns": value, "directories": value, "parameters": value}
        try:
            from core.wordlist_manager import WordlistManager

            wm = WordlistManager()
            profile = str(extra.get("profile") or "safe")
            return {
                "dns": wm.get_wordlist("dns", profile=profile).replace("\\", "/"),
                "directories": wm.get_wordlist("directories", profile=profile).replace("\\", "/"),
                "parameters": wm.get_wordlist("parameters", profile=profile).replace("\\", "/"),
            }
        except Exception:
            return {"dns": "", "directories": "", "parameters": ""}

    @staticmethod
    def _extract_evidence(result: AgentResult, source: str, output: str) -> None:
        """Add bounded, provenance-tagged evidence; never dump secret values."""
        lines = [line.strip() for line in (output or "").splitlines() if line.strip()]
        if not lines:
            return

        hosts = []
        urls = []
        ports = []
        secret_count = 0
        for line in lines[:5000]:
            first = line.split()[0] if line.split() else ""
            if _HOST_RE.match(first) and first not in hosts:
                hosts.append(first)
            if _URL_RE.match(first) and first not in urls:
                urls.append(first)
            if "/tcp" in line and "open" in line.lower():
                ports.append(line)
            secret_count += len(_SECRET_RE.findall(line))

        if hosts:
            result.findings.append(
                {
                    "type": "subdomains",
                    "severity": "Info",
                    "title": f"Subdomains discovered ({len(hosts)})",
                    "evidence": "\n".join(hosts[:30]),
                    "tool": source,
                }
            )
        if urls:
            result.findings.append(
                {
                    "type": "urls",
                    "severity": "Info",
                    "title": f"URLs discovered ({len(urls)})",
                    "evidence": "\n".join(urls[:30]),
                    "tool": source,
                }
            )
        if ports:
            result.findings.append(
                {
                    "type": "ports",
                    "severity": "Info",
                    "title": f"Open ports observed ({len(ports)})",
                    "evidence": "\n".join(ports[:30]),
                    "tool": source,
                }
            )
        if secret_count:
            result.findings.append(
                {
                    "type": "secret_candidate",
                    "severity": "High",
                    "title": f"Potential secret material observed ({secret_count})",
                    "evidence": (
                        f"{secret_count} candidate(s) matched in {source}. "
                        "Values are redacted; inspect the saved tool output locally."
                    ),
                    "tool": source,
                }
            )
