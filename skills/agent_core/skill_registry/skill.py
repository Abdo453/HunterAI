"""
Skill Registry — سجل المهارات الديناميكي
==========================================
يتيح للوكيل اكتشاف كل المهارات المتاحة تلقائيًا من ملفات skill.yaml،
وتحميلها وتنفيذها بالاسم، مع دعم التصفية حسب الفئة والأدوات المطلوبة.
"""
from __future__ import annotations

import importlib
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

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


class SkillRegistry:
    """
    يستخدمه الوكيل لـ:
      - list_skills() : عرض كل المهارات المتاحة
      - get(name)     : إعادة Instantiation لمهارة بالاسم
      - run(name, ctx): تنفيذ مهارة مباشرة وعودة النتيجة
    """

    def __init__(self):
        self._specs: Dict[str, SkillSpec] = {}
        self._instances: Dict[str, BaseSkill] = {}
        self._load_all()

    def _load_all(self) -> None:
        """يمشي على كل skills/*/skill.yaml ويسجل المواصفات."""
        for yaml_path in SKILLS_ROOT.rglob("skill.yaml"):
            try:
                data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
                name = data.get("name") or yaml_path.parent.name
                module_path = (
                    f"skills.{yaml_path.parent.relative_to(SKILLS_ROOT).as_posix().replace('/', '.')}.skill"
                )
                # هذا الملف هو السجل نفسه — ليس مهارة قابلة للتنفيذ.
                # تخطيه يمنع recursive self-registration و AttributeError عند get().
                if module_path == __name__:
                    continue
                spec = SkillSpec(
                    name=name,
                    category=data.get("category", "general"),
                    description=data.get("description", ""),
                    version=data.get("version", "1.0"),
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
                )
                self._specs[name] = spec
            except Exception as exc:
                # المهارة المعطلة لا تمنع تحميل البقية
                print(f"[SkillRegistry] skip {yaml_path}: {exc}")

    @staticmethod
    def _class_from_name(name: str) -> str:
        return "".join(part.capitalize() for part in name.split("_")) + "Skill"

    def list_skills(self, category: Optional[str] = None, enabled_only: bool = True) -> List[SkillSpec]:
        specs = list(self._specs.values())
        if enabled_only:
            specs = [s for s in specs if s.enabled]
        if category:
            specs = [s for s in specs if s.category == category]
        return sorted(specs, key=lambda s: s.name)

    def get(self, name: str) -> BaseSkill:
        if name in self._instances:
            return self._instances[name]
        spec = self._specs.get(name)
        if not spec:
            raise KeyError(f"Skill '{name}' not registered")
        mod = importlib.import_module(spec.module_path)
        cls = getattr(mod, spec.class_name, None)
        if cls is None:
            # drift بين skill.yaml والكلاس الفعلي (شائع مع الأسماء المختصرة:
            # SQLi/SSRF/XSS/IDOR/LLM) — نكتشف الكلاس الحقيقي بدل الفشل.
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
        """يجد الـ BaseSkill الوحيد داخل الوحدة كحل احتياطي لتعارض الاسم."""
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

    def summary(self) -> Dict[str, Any]:
        cats: Dict[str, int] = {}
        for s in self._specs.values():
            cats[s.category] = cats.get(s.category, 0) + 1
        return {
            "total": len(self._specs),
            "enabled": sum(1 for s in self._specs.values() if s.enabled),
            "by_category": cats,
            "skills": [s.name for s in self.list_skills()],
        }


# المثيل العام الذي يستورده الوكلاء والمشغلون
SKILL_REGISTRY = SkillRegistry()


if __name__ == "__main__":
    import json

    reg = SkillRegistry()
    print(json.dumps(reg.summary(), indent=2, ensure_ascii=False))
