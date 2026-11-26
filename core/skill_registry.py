"""
Unified Skill Registry — اكتشاف وتنفيذ موحّد لكل Skills في المنصة
==================================================================
Unifies all 3 skill registries across HunterAI:
  1. Directory Skills (``skills/**/skill.yaml`` -> ``skills.base_skill.BaseSkill`` / ``execute(ctx)``)
  2. Agent Vulnerability Skills (``agents/skills/*.py`` -> ``agents.skills.base_skill.BaseSkill`` / ``run(target_url, param_name)``)
  3. Agent-Core Skill Registry facade (``skills/agent_core/skill_registry/skill.py``)

Provides:
  - ``_SkillContractAdapter``: bidirectional contract bridge
    ``execute(ctx: SkillContext)`` <-> ``run(target_url, param_name, **kwargs)``
  - ``SkillRegistry.list_skills(...)``: unified listing across directory & agent layers
  - ``SkillRegistry.dispatch_skill_execution(...)``: canonical single dispatcher
"""
from __future__ import annotations

import asyncio
import importlib
import importlib.util
import inspect
import logging
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, Union

import yaml

from skills.base_skill import BaseSkill, SkillContext, SkillResult

logger = logging.getLogger(__name__)

# Root of skills directory
SKILLS_ROOT = Path(__file__).parent.parent / "skills"
AGENTS_SKILLS_ROOT = Path(__file__).parent.parent / "agents" / "skills"

# Directories that are registry infrastructure rather than executable skills.
_EXCLUDED_SKILL_DIRS = {
    (Path("agent_core") / "skill_registry").as_posix(),
}


# ---------------------------------------------------------------------------
# Bidirectional Skill Contract Adapter: execute(ctx) <-> run(target_url, param)
# ---------------------------------------------------------------------------

class _SkillContractAdapter(BaseSkill):
    """Bidirectional adapter bridging the two HunterAI skill contracts:

    - Directory skill contract: ``async execute(ctx: SkillContext) -> skills.base_skill.SkillResult``
    - Agent vuln skill contract: ``async run(target_url: str, param_name: str, **kwargs) -> agents.skills.base_skill.SkillResult``

    An instance of ``_SkillContractAdapter`` satisfies BOTH interfaces cleanly.
    """

    def __init__(
        self,
        wrapped: Any,
        *,
        contract: str = "auto",
        skill_name: Optional[str] = None,
        category: str = "vulnerability",
        description: str = "",
        vuln_type: str = "generic",
        cwe: str = "CWE-000",
        owasp_top10: str = "A00:2021",
        default_severity: str = "Medium",
    ) -> None:
        self._wrapped = wrapped() if isinstance(wrapped, type) else wrapped
        if contract == "auto":
            contract = "directory" if isinstance(self._wrapped, BaseSkill) else "agent"
        self.contract = contract  # "directory" | "agent"
        self.name = skill_name or getattr(self._wrapped, "name", None) or type(self._wrapped).__name__
        self.category = getattr(self._wrapped, "category", category)
        self.description = getattr(self._wrapped, "description", description) or f"Adapted skill: {self.name}"
        self.vuln_type = getattr(self._wrapped, "vuln_type", vuln_type)
        self.cwe = getattr(self._wrapped, "cwe", cwe)
        self.owasp_top10 = getattr(self._wrapped, "owasp_top10", owasp_top10)
        self.default_severity = getattr(self._wrapped, "default_severity", default_severity)
        self.tools_required = list(getattr(self._wrapped, "tools_required", []) or [])
        self.fallback_tools = list(getattr(self._wrapped, "fallback_tools", []) or [])
        self.timeout_seconds = float(getattr(self._wrapped, "timeout_seconds", 180.0) or 180.0)
        self.max_retries = int(getattr(self._wrapped, "max_retries", 2) or 2)
        super().__init__()

    @classmethod
    def from_agent_skill(cls, skill_or_cls: Any, **meta: Any) -> "_SkillContractAdapter":
        return cls(skill_or_cls, contract="agent", **meta)

    @classmethod
    def from_directory_skill(cls, skill_or_cls: Any, **meta: Any) -> "_SkillContractAdapter":
        return cls(skill_or_cls, contract="directory", **meta)

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        fn = getattr(self._wrapped, "can_handle", None)
        if callable(fn):
            try:
                return float(fn(param_name, url=url, sample_value=sample_value) or 0.0)
            except TypeError:
                try:
                    return float(fn(param_name) or 0.0)
                except Exception:
                    return 0.0
            except Exception:
                return 0.0
        return 0.0

    # ── Directory contract: execute(ctx) -> skills.base_skill.SkillResult ──

    async def execute(self, ctx: SkillContext) -> SkillResult:
        if self.contract == "directory":
            return await self._wrapped.execute(ctx)

        t0 = time.time()
        param_name = str(ctx.extra.get("param_name") or ctx.extra.get("param") or "")
        target_url = str(ctx.extra.get("target_url") or ctx.target or "")
        run_kwargs = {
            k: v for k, v in (ctx.extra or {}).items()
            if k not in ("param_name", "param", "target_url")
        }

        res = SkillResult(skill_name=self.name, success=False, tool_used=self.name)
        try:
            agent_res = self._invoke_agent_run(target_url, param_name, **run_kwargs)
            if inspect.isawaitable(agent_res):
                agent_res = await agent_res
        except Exception as exc:
            res.duration = time.time() - t0
            res.add_error("runtime", str(exc), tool=self.name)
            return res

        res.duration = time.time() - t0
        if isinstance(agent_res, dict):
            res.success = True
            res.raw_output["result"] = str(agent_res)[:5000]
            res.metadata = dict(agent_res)
            for item in agent_res.get("findings") or []:
                if isinstance(item, dict):
                    res.add_finding(
                        title=str(item.get("title") or f"{self.name} finding"),
                        evidence=str(item.get("evidence") or item.get("signals") or ""),
                        severity=str(item.get("severity") or self.default_severity),
                        vuln_type=str(item.get("type") or self.vuln_type),
                        tool=self.name,
                        url=str(item.get("url") or item.get("endpoint") or target_url),
                        recommendation=str(item.get("recommendation") or ""),
                    )
            if agent_res.get("verified") and not res.findings:
                res.add_finding(
                    title=str(agent_res.get("title") or f"{self.name} verified"),
                    evidence=str(agent_res.get("evidence") or ""),
                    severity=str(agent_res.get("severity") or self.default_severity),
                    vuln_type=str(agent_res.get("vuln_type") or self.vuln_type),
                    tool=self.name,
                    url=target_url,
                )
            return res

        # agents.skills.base_skill.SkillResult object
        res.success = True
        verified = bool(getattr(agent_res, "verified", False))
        res.metadata = agent_res.to_dict() if hasattr(agent_res, "to_dict") else {"verified": verified}
        if verified or getattr(agent_res, "evidence", ""):
            res.add_finding(
                title=str(getattr(agent_res, "title", "") or f"{self.name} on {param_name or target_url}"),
                evidence=str(getattr(agent_res, "evidence", "")),
                severity=str(getattr(agent_res, "severity", self.default_severity)),
                vuln_type=str(getattr(agent_res, "vuln_type", self.vuln_type)),
                tool=str(getattr(agent_res, "tool", self.name)),
                url=str(getattr(agent_res, "endpoint", "") or target_url),
                recommendation=str(getattr(agent_res, "remediation", "")),
            )
        return res

    def _invoke_agent_run(self, target_url: str, param_name: str, **kwargs: Any) -> Any:
        run_fn = self._wrapped.run
        sig = inspect.signature(run_fn)
        params = list(sig.parameters.values())
        accepts_var_kw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params)
        filtered_kw = kwargs if accepts_var_kw else {k: v for k, v in kwargs.items() if k in sig.parameters}
        if len(params) >= 2 and params[1].name not in ("method",):
            return run_fn(target_url, param_name, **filtered_kw)
        if param_name and "parameters" in sig.parameters and "parameters" not in filtered_kw:
            filtered_kw["parameters"] = [{"name": param_name, "value": "", "location": "query"}]
        return run_fn(target_url, **filtered_kw)

    # ── Dual-dispatch run(): supports BOTH run(ctx) AND run(target_url, param_name) ──

    async def run(self, *args: Any, **kwargs: Any) -> Any:
        """Supports BOTH contracts transparently:
        - ``await adapter.run(ctx: SkillContext)`` -> ``skills.base_skill.SkillResult``
        - ``await adapter.run(target_url, param_name, **kwargs)`` -> ``agents.skills.base_skill.SkillResult``
        """
        if len(args) == 1 and isinstance(args[0], SkillContext):
            return await super().run(args[0])

        target_url = str(args[0] if len(args) >= 1 else kwargs.pop("target_url", ""))
        param_name = str(args[1] if len(args) >= 2 else kwargs.pop("param_name", ""))

        if self.contract == "agent":
            raw = self._invoke_agent_run(target_url, param_name, **kwargs)
            if inspect.isawaitable(raw):
                raw = await raw
            if isinstance(raw, dict):
                from agents.skills.base_skill import SkillResult as AgentSkillResult
                findings = raw.get("findings") or []
                verified = bool(raw.get("verified", False)) or (
                    raw.get("decision") == "confirmed_sqli_candidate"
                )
                return AgentSkillResult(
                    verified=verified,
                    status="VERIFIED" if verified else str(raw.get("decision", "UNVERIFIED")).upper(),
                    vuln_type=self.vuln_type,
                    title=str(raw.get("title") or (findings[0].get("title") if findings else self.name)),
                    severity=self.default_severity,
                    endpoint=target_url,
                    param_name=param_name,
                    evidence=str(raw.get("evidence") or (findings[0].get("signals") if findings else "")),
                    confidence=float(raw.get("confidence", 0.0) or 0.0),
                    tool=self.name,
                    cwe=self.cwe,
                    owasp_top10=self.owasp_top10,
                    extra=raw,
                )
            return raw

        # Directory skill invoked via agent contract: run(target_url, param_name, **kwargs)
        from agents.skills.base_skill import SkillResult as AgentSkillResult
        from core.workspace_manager import WorkspaceManager
        from tools.tool_manager import ToolManager

        ws = kwargs.pop("workspace", None) or WorkspaceManager(
            root=Path(tempfile.gettempdir()) / "hunterai_skill_adapter"
        )
        tm = kwargs.pop("tool_manager", None) or ToolManager()
        session_id = str(kwargs.pop("session_id", "adapter"))
        extra = dict(kwargs.pop("extra", {}) or {})
        extra.update(kwargs)
        if param_name:
            extra.setdefault("param_name", param_name)
        extra.setdefault("urls", [target_url] if target_url else [])

        ws.create_workspace(target_url or "target", session_id)
        ctx = SkillContext(
            target=target_url,
            session_id=session_id,
            workspace=ws,
            tool_manager=tm,
            extra=extra,
        )
        dir_res: SkillResult = await self._wrapped.run(ctx)
        top = dir_res.findings[0] if dir_res.findings else {}
        return AgentSkillResult(
            verified=bool(dir_res.success and dir_res.has_findings and top.get("verified", False)),
            status="COMPLETED" if dir_res.success else "FAILED",
            vuln_type=str(top.get("type") or self.vuln_type),
            title=str(top.get("title") or f"{self.name} execution on {target_url}"),
            severity=str(top.get("severity") or self.default_severity),
            endpoint=str(top.get("url") or target_url),
            param_name=param_name,
            evidence=str(top.get("evidence") or ""),
            remediation=str(top.get("recommendation") or ""),
            tool=dir_res.tool_used or self.name,
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            logs=list(dir_res.errors),
            extra={
                "success": dir_res.success,
                "findings": dir_res.findings,
                "output_files": dir_res.output_files,
                "metadata": dir_res.metadata,
                "duration": dir_res.duration,
            },
        )


class SkillMeta:
    """Metadata لكل Skill محمّلة من skill.yaml أو من agents/skills/registry.py"""

    def __init__(
        self,
        data: Dict[str, Any],
        skill_file: Path,
        *,
        source_layer: str = "directory",
        agent_cls: Optional[Type[Any]] = None,
    ):
        self.name: str = data["name"]
        self.category: str = data.get("category", "general")
        self.description: str = data.get("description", "")
        self.version: str = data.get("version", "1.0")
        self.input: List[str] = data.get("input", [])
        self.output: List[str] = data.get("output", [])
        self.depends_on: List[str] = data.get("depends_on", [])
        self.next_skills: List[str] = data.get("next_skills", [])
        self.fallback_skills: List[str] = data.get("fallback_skills", [])
        self.tools_required: List[str] = data.get("tools_required", [])
        self.fallback_tools: List[str] = data.get("fallback_tools", [])
        self.timeout_seconds: float = float(data.get("timeout_seconds", 180.0))
        self.max_retries: int = int(data.get("max_retries", 2))
        self.enabled: bool = data.get("enabled", True)
        self.skill_file: Path = skill_file
        self.source_layer: str = source_layer  # "directory" | "agent_vuln"
        self.vuln_type: str = data.get("vuln_type", "")
        self.cwe: str = data.get("cwe", "")
        self._agent_cls: Optional[Type[Any]] = agent_cls
        self._class_cache: Optional[Type[BaseSkill]] = None

    def load_class(self) -> Optional[Type[BaseSkill]]:
        """يحمّل الـ Python class من skill.py"""
        if self.source_layer == "agent_vuln" and self._agent_cls is not None:
            return self._agent_cls  # type: ignore[return-value]

        if self._class_cache is not None:
            return self._class_cache

        skill_py = self.skill_file.parent / "skill.py"
        if not skill_py.exists():
            logger.warning(f"[SkillRegistry] skill.py not found for: {self.name}")
            return None

        try:
            rel_pkg = self.skill_file.parent.relative_to(SKILLS_ROOT).as_posix().replace("/", ".")
            pkg_name = f"skills.{rel_pkg}"
            module_name = f"{pkg_name}.skill"

            try:
                importlib.import_module(pkg_name)
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"[SkillRegistry] parent package {pkg_name} not importable: {exc}")

            spec = importlib.util.spec_from_file_location(module_name, skill_py)
            if spec is None or spec.loader is None:
                return None
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                try:
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseSkill)
                        and attr is not BaseSkill
                    ):
                        self._class_cache = attr
                        return attr
                except TypeError:
                    continue

            logger.warning(f"[SkillRegistry] No BaseSkill subclass found in: {skill_py}")
        except Exception as exc:
            logger.error(f"[SkillRegistry] Failed to load {self.name}: {exc}")
        return None

    def instantiate(self) -> Optional[BaseSkill]:
        """ينشئ instance من الـ Skill (ملفوفاً بـ _SkillContractAdapter عند الحاجة)."""
        if self.source_layer == "agent_vuln" and self._agent_cls is not None:
            try:
                inst = self._agent_cls()
            except Exception:
                try:
                    inst = self._agent_cls(timeout=12.0)
                except Exception as exc:
                    logger.error(f"[SkillRegistry] Failed to instantiate agent skill {self.name}: {exc}")
                    return None
            return _SkillContractAdapter.from_agent_skill(
                inst,
                skill_name=self.name,
                category=self.category,
                description=self.description,
                vuln_type=self.vuln_type or self.name,
                cwe=self.cwe or "CWE-000",
            )

        cls = self.load_class()
        if cls is None:
            return None
        try:
            inst = cls()
            inst.timeout_seconds = self.timeout_seconds
            inst.max_retries = self.max_retries
            if self.fallback_tools and not inst.fallback_tools:
                inst.fallback_tools = self.fallback_tools
            if self.tools_required and not inst.tools_required:
                inst.tools_required = self.tools_required
            return inst
        except Exception as exc:
            logger.error(f"[SkillRegistry] Failed to instantiate {self.name}: {exc}")
            return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "source_layer": self.source_layer,
            "description": self.description,
            "version": self.version,
            "depends_on": self.depends_on,
            "next_skills": self.next_skills,
            "tools_required": self.tools_required,
            "fallback_tools": self.fallback_tools,
            "enabled": self.enabled,
            "skill_file": str(self.skill_file),
        }

    def __repr__(self) -> str:
        return f"<SkillMeta: {self.name} [{self.category}/{self.source_layer}]>"


class SkillRegistry:
    """
    Canonical Unified Skill Registry across directory skills (``skills/**/skill.yaml``)
    and agent vulnerability skills (``agents/skills/registry.py``).
    """

    def __init__(self, skills_root: Path = SKILLS_ROOT, include_agent_skills: bool = True):
        self.root = skills_root
        self.include_agent_skills = include_agent_skills
        self._registry: Dict[str, SkillMeta] = {}
        self._agent_registry: Dict[str, SkillMeta] = {}
        self._discovered = False

    def discover(self, force: bool = False) -> int:
        """يكتشف كل الـ Skills من مجلدات skills/**/skill.yaml ويسجل مهارات agents/skills/."""
        if self._discovered and not force:
            return len(self._registry)

        self._registry.clear()
        self._agent_registry.clear()
        count = 0

        if not self.root.exists():
            logger.warning(f"[SkillRegistry] Skills root not found: {self.root}")
        else:
            for yaml_file in sorted(self.root.rglob("skill.yaml")):
                try:
                    rel_dir = yaml_file.parent.relative_to(self.root).as_posix()
                    if rel_dir in _EXCLUDED_SKILL_DIRS:
                        continue

                    with open(yaml_file, "r", encoding="utf-8") as fh:
                        data = yaml.safe_load(fh)

                    if not data or "name" not in data:
                        logger.warning(f"[SkillRegistry] Invalid skill.yaml: {yaml_file}")
                        continue

                    meta = SkillMeta(data, yaml_file, source_layer="directory")
                    if not meta.enabled:
                        continue

                    self._registry[meta.name] = meta
                    count += 1
                    logger.debug(f"[SkillRegistry] Discovered: {meta.name} [{meta.category}]")
                except Exception as exc:
                    logger.error(f"[SkillRegistry] Error loading {yaml_file}: {exc}")

        if self.include_agent_skills:
            self._discover_agent_skills()

        self._discovered = True
        logger.info(
            "[SkillRegistry] Discovered %d directory skills + %d agent vuln skills",
            count,
            len(self._agent_registry),
        )
        return count

    def _discover_agent_skills(self) -> None:
        """Bridge built-in vulnerability skills from ``agents/skills/registry.py``."""
        try:
            from agents.skills.registry import bootstrap_builtin_skills
            agent_reg = bootstrap_builtin_skills()
        except Exception as exc:
            logger.debug("[SkillRegistry] Agent skills bootstrap skipped: %s", exc)
            return

        for ameta in agent_reg.all_skills():
            try:
                src_file = Path(inspect.getfile(ameta.cls)).resolve()
            except Exception:
                src_file = (AGENTS_SKILLS_ROOT / "registry.py").resolve()
            meta = SkillMeta(
                {
                    "name": ameta.name,
                    "category": "vulnerability",
                    "description": f"Vulnerability skill ({ameta.vuln_type}, {ameta.cwe})",
                    "version": "1.0",
                    "vuln_type": ameta.vuln_type,
                    "cwe": ameta.cwe,
                    "enabled": True,
                },
                src_file,
                source_layer="agent_vuln",
                agent_cls=ameta.cls,
            )
            self._agent_registry[ameta.name] = meta

    # ── Lookup ────────────────────────────────────────────────────

    def get_skill(self, name: str) -> Optional[SkillMeta]:
        self._ensure_discovered()
        if name in self._registry:
            return self._registry[name]
        if name in self._agent_registry:
            return self._agent_registry[name]
        low = name.strip().lower()
        for pool in (self._registry, self._agent_registry):
            for k, m in pool.items():
                if k.lower() == low or (m.vuln_type and m.vuln_type.lower() == low):
                    return m
        return None

    def get_by_category(self, category: str, *, include_agent_skills: bool = False) -> List[SkillMeta]:
        self._ensure_discovered()
        items = [m for m in self._registry.values() if m.category == category]
        if include_agent_skills:
            items.extend(m for m in self._agent_registry.values() if m.category == category)
        return items

    def get_all(self, *, include_agent_skills: bool = False) -> List[SkillMeta]:
        self._ensure_discovered()
        if include_agent_skills:
            combined = dict(self._agent_registry)
            combined.update(self._registry)
            return list(combined.values())
        return list(self._registry.values())

    def list_skills(
        self,
        category: Optional[str] = None,
        *,
        enabled_only: bool = True,
        include_agent_skills: bool = True,
    ) -> List[SkillMeta]:
        """Return sorted list of skills across directory and (optionally) agent layers."""
        self._ensure_discovered()
        pool: Dict[str, SkillMeta] = {}
        if include_agent_skills:
            pool.update(self._agent_registry)
        pool.update(self._registry)

        out = list(pool.values())
        if enabled_only:
            out = [m for m in out if m.enabled]
        if category:
            cat_l = category.lower()
            out = [m for m in out if m.category.lower() == cat_l or m.source_layer.lower() == cat_l]
        return sorted(out, key=lambda m: m.name)

    def list_names(self, *, include_agent_skills: bool = False) -> List[str]:
        self._ensure_discovered()
        if include_agent_skills:
            return sorted(set(self._registry.keys()) | set(self._agent_registry.keys()))
        return list(self._registry.keys())

    def list_categories(self, *, include_agent_skills: bool = False) -> List[str]:
        self._ensure_discovered()
        items = self.get_all(include_agent_skills=include_agent_skills)
        return sorted(set(m.category for m in items))

    # ── Dependency resolution ─────────────────────────────────────

    def get_initial_skills(self) -> List[SkillMeta]:
        self._ensure_discovered()
        return [m for m in self._registry.values() if not m.depends_on]

    def get_next_skills(
        self,
        completed: List[str],
        failed: List[str],
        skipped: List[str],
    ) -> List[SkillMeta]:
        self._ensure_discovered()
        done_set = set(completed)
        blocked_set = set(completed) | set(failed) | set(skipped)

        ready = []
        for meta in self._registry.values():
            if meta.name in blocked_set:
                continue
            if all(dep in done_set for dep in meta.depends_on):
                ready.append(meta)
        return ready

    def get_skills_unlocked_by(self, skill_name: str) -> List[SkillMeta]:
        self._ensure_discovered()
        meta = self._registry.get(skill_name)
        if not meta:
            return []
        unlocked: List[SkillMeta] = []
        for n in meta.next_skills:
            resolved = self.get_skill(n)
            if resolved is not None:
                unlocked.append(resolved)
        return unlocked

    def instantiate(self, skill_name: str) -> Optional[BaseSkill]:
        """ينشئ instance جاهز للتنفيذ (ملفوفاً بـ _SkillContractAdapter لمهارات agents/skills)."""
        meta = self.get_skill(skill_name)
        if meta is None:
            return None
        return meta.instantiate()

    async def dispatch_skill_execution(
        self,
        skill_name: str,
        *,
        target: str = "",
        param_name: str = "",
        ctx: Optional[SkillContext] = None,
        session_id: str = "dispatch",
        workspace: Optional[Any] = None,
        tool_manager: Optional[Any] = None,
        extra: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> SkillResult:
        """Canonical execution dispatcher across BOTH directory and agent vulnerability skills."""
        self._ensure_discovered()
        meta = self.get_skill(skill_name)
        if meta is None:
            res = SkillResult(skill_name=skill_name, success=False, tool_used=skill_name)
            res.add_error("unknown_skill", f"Skill '{skill_name}' is not registered")
            return res

        inst = meta.instantiate()
        if inst is None:
            res = SkillResult(skill_name=meta.name, success=False, tool_used=meta.name)
            res.add_error("instantiation_failed", f"Could not instantiate skill '{meta.name}'")
            return res

        if ctx is None:
            from core.workspace_manager import WorkspaceManager
            from tools.tool_manager import ToolManager

            ws = workspace or WorkspaceManager(
                root=Path(tempfile.gettempdir()) / "hunterai_skill_dispatch"
            )
            tm = tool_manager or ToolManager()
            merged_extra = dict(extra or {})
            merged_extra.update(kwargs)
            if param_name:
                merged_extra.setdefault("param_name", param_name)
            if target:
                merged_extra.setdefault("urls", [target])
            ws.create_workspace(target or "target", session_id)
            ctx = SkillContext(
                target=target,
                session_id=session_id,
                workspace=ws,
                tool_manager=tm,
                extra=merged_extra,
            )

        return await inst.run(ctx)

    def registry_summary(self) -> Dict[str, Any]:
        self._ensure_discovered()
        by_cat: Dict[str, List[str]] = {}
        for m in self._registry.values():
            by_cat.setdefault(m.category, []).append(m.name)
        return {
            "total": len(self._registry),
            "directory_total": len(self._registry),
            "agent_vuln_total": len(self._agent_registry),
            "unified_total": len(set(self._registry.keys()) | set(self._agent_registry.keys())),
            "categories": by_cat,
            "skills_root": str(self.root),
        }

    def _ensure_discovered(self) -> None:
        if not self._discovered:
            self.discover()


SKILL_REGISTRY = SkillRegistry()


async def dispatch_skill_execution(
    skill_name: str,
    *,
    target: str = "",
    param_name: str = "",
    ctx: Optional[SkillContext] = None,
    **kwargs: Any,
) -> SkillResult:
    """Module-level convenience wrapper around ``SKILL_REGISTRY.dispatch_skill_execution``."""
    return await SKILL_REGISTRY.dispatch_skill_execution(
        skill_name,
        target=target,
        param_name=param_name,
        ctx=ctx,
        **kwargs,
    )
