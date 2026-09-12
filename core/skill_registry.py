"""
Skill Registry — اكتشاف تلقائي لكل Skills في مجلد skills/
إضافة Skill جديدة = مجلد + skill.yaml + skill.py فقط
"""
from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import yaml

from skills.base_skill import BaseSkill

logger = logging.getLogger(__name__)

# Root of skills directory
SKILLS_ROOT = Path(__file__).parent.parent / "skills"


class SkillMeta:
    """Metadata لكل Skill محمّلة من skill.yaml"""

    def __init__(self, data: Dict[str, Any], skill_file: Path):
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
        self._class_cache: Optional[Type[BaseSkill]] = None

    def load_class(self) -> Optional[Type[BaseSkill]]:
        """يحمّل الـ Python class من skill.py"""
        if self._class_cache is not None:
            return self._class_cache

        skill_py = self.skill_file.parent / "skill.py"
        if not skill_py.exists():
            logger.warning(f"[SkillRegistry] skill.py not found for: {self.name}")
            return None

        try:
            module_name = f"skills.{self.category}.{self.name}"
            spec = importlib.util.spec_from_file_location(module_name, skill_py)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            # Find first class that subclasses BaseSkill
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
        """ينشئ instance من الـ Skill مع إعدادات الـ Timeout والـ Retries"""
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
        return f"<SkillMeta: {self.name} [{self.category}]>"


class SkillRegistry:
    """
    يكتشف ويحمّل كل الـ Skills من مجلد skills/ تلقائياً.
    إضافة Skill جديدة = مجلد + skill.yaml + skill.py فقط.
    """

    def __init__(self, skills_root: Path = SKILLS_ROOT):
        self.root = skills_root
        self._registry: Dict[str, SkillMeta] = {}
        self._discovered = False

    def discover(self, force: bool = False) -> int:
        """يكتشف كل الـ Skills من مجلدات skills/**/*.yaml"""
        if self._discovered and not force:
            return len(self._registry)

        self._registry.clear()
        count = 0

        if not self.root.exists():
            logger.warning(f"[SkillRegistry] Skills root not found: {self.root}")
            return 0

        for yaml_file in sorted(self.root.rglob("skill.yaml")):
            try:
                with open(yaml_file, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)

                if not data or "name" not in data:
                    logger.warning(f"[SkillRegistry] Invalid skill.yaml: {yaml_file}")
                    continue

                meta = SkillMeta(data, yaml_file)
                if not meta.enabled:
                    continue

                self._registry[meta.name] = meta
                count += 1
                logger.info(f"[SkillRegistry] Discovered: {meta.name} [{meta.category}]")

            except Exception as exc:
                logger.error(f"[SkillRegistry] Error loading {yaml_file}: {exc}")

        self._discovered = True
        logger.info(f"[SkillRegistry] Total skills discovered: {count}")
        return count

    # ── Lookup ────────────────────────────────────────────────────

    def get_skill(self, name: str) -> Optional[SkillMeta]:
        self._ensure_discovered()
        return self._registry.get(name)

    def get_by_category(self, category: str) -> List[SkillMeta]:
        self._ensure_discovered()
        return [m for m in self._registry.values() if m.category == category]

    def get_all(self) -> List[SkillMeta]:
        self._ensure_discovered()
        return list(self._registry.values())

    def list_names(self) -> List[str]:
        self._ensure_discovered()
        return list(self._registry.keys())

    def list_categories(self) -> List[str]:
        self._ensure_discovered()
        return sorted(set(m.category for m in self._registry.values()))

    # ── Dependency resolution ─────────────────────────────────────

    def get_initial_skills(self) -> List[SkillMeta]:
        """يرجع الـ Skills اللي مش معتمدة على أي Skill تانية (entry points)"""
        self._ensure_discovered()
        return [m for m in self._registry.values() if not m.depends_on]

    def get_next_skills(
        self,
        completed: List[str],
        failed: List[str],
        skipped: List[str],
    ) -> List[SkillMeta]:
        """
        يرجع الـ Skills الجاهزة للتنفيذ بناءً على:
        - كل depends_on مكتملة
        - مش في completed أو failed أو skipped
        """
        self._ensure_discovered()
        done_set = set(completed)
        blocked_set = set(completed) | set(failed) | set(skipped)

        ready = []
        for meta in self._registry.values():
            if meta.name in blocked_set:
                continue
            # Check all dependencies are satisfied
            if all(dep in done_set for dep in meta.depends_on):
                ready.append(meta)

        return ready

    def get_skills_unlocked_by(self, skill_name: str) -> List[SkillMeta]:
        """يرجع الـ Skills المحددة في next_skills لـ skill معينة"""
        self._ensure_discovered()
        meta = self._registry.get(skill_name)
        if not meta:
            return []
        return [self._registry[n] for n in meta.next_skills if n in self._registry]

    def instantiate(self, skill_name: str) -> Optional[BaseSkill]:
        """ينشئ instance جاهز للتنفيذ"""
        meta = self.get_skill(skill_name)
        if meta is None:
            return None
        return meta.instantiate()

    def registry_summary(self) -> Dict[str, Any]:
        self._ensure_discovered()
        by_cat: Dict[str, List[str]] = {}
        for m in self._registry.values():
            by_cat.setdefault(m.category, []).append(m.name)
        return {
            "total": len(self._registry),
            "categories": by_cat,
            "skills_root": str(self.root),
        }

    def _ensure_discovered(self) -> None:
        if not self._discovered:
            self.discover()
