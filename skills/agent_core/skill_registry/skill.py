"""
Skill Registry — سجل المهارات الديناميكي (Facade delegated to core.skill_registry)
=================================================================================
Unified facade delegating discovery, contract adaptation, and execution dispatch
to ``core.skill_registry.SkillRegistry`` while preserving the legacy ``SkillSpec``
API (`list_skills()`, `get()`, `run()`, `dispatch_skill_execution()`, `summary()`).
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from core.skill_registry import SkillRegistry as CoreSkillRegistry
from core.skill_registry import _SkillContractAdapter
from skills.base_skill import BaseSkill, SkillContext, SkillResult

SKILLS_ROOT = Path(__file__).resolve().parent.parent.parent  # skills/


@dataclass
class SkillSpec:
    name: str
    category: str
    description: str
    version: str
    module_path: str
    class_name: str
    tools_required: List[str] = field(default_factory=list)
    fallback_tools: List[str] = field(default_factory=list)
    timeout_seconds: float = 180.0
    max_retries: int = 2
    enabled: bool = True
    depends_on: List[str] = field(default_factory=list)
    next_skills: List[str] = field(default_factory=list)
    yaml_path: str = ""
    source_layer: str = "directory"


class SkillRegistry:
    """
    Agent-Core Skill Registry unified with ``core.skill_registry.SkillRegistry``:
      - list_skills() : list all directory (and optionally agent vuln) skills
      - get(name)     : return instantiated ``BaseSkill`` (adapted via ``_SkillContractAdapter`` if agent skill)
      - run(name, ctx): execute skill directly
      - dispatch_skill_execution(...): canonical unified dispatch
    """

    def __init__(self, core_registry: Optional[CoreSkillRegistry] = None):
        self._core = core_registry or CoreSkillRegistry(skills_root=SKILLS_ROOT)
        self._specs: Dict[str, SkillSpec] = {}
        self._instances: Dict[str, BaseSkill] = {}
        self._load_all()

    def _load_all(self) -> None:
        self._core.discover(force=True)
        self._specs.clear()
        for yaml_path in sorted(SKILLS_ROOT.rglob("skill.yaml")):
            try:
                data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                name = data.get("name") or yaml_path.parent.name
                module_path = (
                    f"skills.{yaml_path.parent.relative_to(SKILLS_ROOT).as_posix().replace('/', '.')}.skill"
                )
                if module_path == __name__:
                    continue
                spec = SkillSpec(
                    name=name,
                    category=data.get("category", "general"),
                    description=data.get("description", ""),
                    version=str(data.get("version", "1.0")),
                    module_path=module_path,
                    class_name=data.get("class", self._class_from_name(name)),
                    tools_required=data.get("tools_required", []) or [],
                    fallback_tools=data.get("fallback_tools", []) or [],
                    timeout_seconds=float(data.get("timeout_seconds", 180)),
                    max_retries=int(data.get("max_retries", 2)),
                    enabled=bool(data.get("enabled", True)),
                    depends_on=data.get("depends_on", []) or [],
                    next_skills=data.get("next_skills", []) or [],
                    yaml_path=str(yaml_path),
                    source_layer="directory",
                )
                self._specs[name] = spec
            except Exception as exc:
                print(f"[SkillRegistry] skip {yaml_path}: {exc}")

    @staticmethod
    def _class_from_name(name: str) -> str:
        return "".join(part.capitalize() for part in name.split("_")) + "Skill"

    def list_skills(
        self,
        category: Optional[str] = None,
        enabled_only: bool = True,
        include_agent_skills: bool = False,
    ) -> List[SkillSpec]:
        specs = list(self._specs.values())
        if include_agent_skills:
            for meta in self._core.list_skills(include_agent_skills=True):
                if meta.source_layer == "agent_vuln" and meta.name not in self._specs:
                    specs.append(
                        SkillSpec(
                            name=meta.name,
                            category=meta.category,
                            description=meta.description,
                            version=meta.version,
                            module_path="agents.skills",
                            class_name=meta.name,
                            enabled=meta.enabled,
                            yaml_path=str(meta.skill_file),
                            source_layer="agent_vuln",
                        )
                    )
        if enabled_only:
            specs = [s for s in specs if s.enabled]
        if category:
            specs = [s for s in specs if s.category == category]
        return sorted(specs, key=lambda s: s.name)

    def get(self, name: str) -> BaseSkill:
        if name in self._instances:
            return self._instances[name]
        spec = self._specs.get(name)
        if spec is None:
            # Fallback to unified core registry (covers agents/skills/* via _SkillContractAdapter)
            adapted = self._core.instantiate(name)
            if adapted is not None:
                self._instances[name] = adapted
                return adapted
            raise KeyError(f"Skill '{name}' not registered")

        mod = importlib.import_module(spec.module_path)
        cls = getattr(mod, spec.class_name, None)
        if cls is None:
            cls = self._discover_skill_class(mod, spec)
            if cls is None:
                raise KeyError(
                    f"Skill '{name}' declares class '{spec.class_name}' but "
                    f"{spec.module_path} exposes no BaseSkill subclass"
                )
        instance = cls()
        self._instances[name] = instance
        return instance

    @staticmethod
    def _discover_skill_class(mod: Any, spec: SkillSpec) -> Optional[Any]:
        candidates = []
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseSkill)
                and attr is not BaseSkill
                and attr.__module__ == mod.__name__
            ):
                candidates.append(attr)
        if len(candidates) == 1:
            return candidates[0]
        return None

    async def run(self, name: str, ctx: SkillContext) -> SkillResult:
        skill = self.get(name)
        return await skill.run(ctx)

    async def dispatch_skill_execution(
        self,
        skill_name: str,
        *,
        target: str = "",
        param_name: str = "",
        ctx: Optional[SkillContext] = None,
        **kwargs: Any,
    ) -> SkillResult:
        return await self._core.dispatch_skill_execution(
            skill_name,
            target=target,
            param_name=param_name,
            ctx=ctx,
            **kwargs,
        )

    def summary(self) -> Dict[str, Any]:
        cats: Dict[str, int] = {}
        for s in self._specs.values():
            cats[s.category] = cats.get(s.category, 0) + 1
        return {
            "total": len(self._specs),
            "enabled": sum(1 for s in self._specs.values() if s.enabled),
            "by_category": cats,
            "skills": [s.name for s in self.list_skills()],
            "unified_total": self._core.registry_summary()["unified_total"],
        }


SKILL_REGISTRY = SkillRegistry()
__all__ = ["SKILL_REGISTRY", "SkillRegistry", "SkillSpec", "_SkillContractAdapter"]
