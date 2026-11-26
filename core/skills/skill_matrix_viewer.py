"""
Unified Skills Viewer & Aggregator for PentestAI-Unified.

Consolidates all active skill layers across the platform dynamically
(no hardcoded counts; stays in 100% parity with ``core.skill_registry``):
1. Directory Skills (``skills/**/skill.yaml``, excluding ``agent_core/skill_registry``)
2. Hunter Vulnerability Skills (``agents/skills/registry.py``)
3. Kali Arsenal Tool Skills (``core/arsenal/kali_catalog.py``)
4. Central Project Skill (``.opencode/skills/MANIFEST.json`` / ``skills/registry.json``)
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_EXCLUDED_DIR_REL = {(Path("agent_core") / "skill_registry").as_posix()}


class SkillMatrixViewer:
    """Aggregates and formats all skills across the 4 platform layers."""

    @staticmethod
    def get_directory_skills(*, include_disabled: bool = False) -> List[Dict[str, Any]]:
        """Scans ``skills/**/skill.yaml`` matching ``core.skill_registry.SkillRegistry``."""
        skills_root = _REPO_ROOT / "skills"
        results: List[Dict[str, Any]] = []
        if not skills_root.is_dir():
            return results
        for yf in sorted(skills_root.rglob("skill.yaml")):
            try:
                rel_dir = yf.parent.relative_to(skills_root).as_posix()
                if rel_dir in _EXCLUDED_DIR_REL:
                    continue
                data = yaml.safe_load(yf.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or "name" not in data:
                    continue
                if not include_disabled and not data.get("enabled", True):
                    continue
                entry = dict(data)
                entry["layer"] = "directory"
                entry["filepath"] = str(yf.relative_to(_REPO_ROOT).as_posix())
                results.append(entry)
            except Exception:
                continue
        return sorted(results, key=lambda x: (str(x.get("category", "")), str(x.get("name", ""))))

    @staticmethod
    def get_hunter_skills() -> List[Dict[str, Any]]:
        """Retrieves specialized vulnerability hunting skills from ``agents.skills.registry``."""
        from agents.skills.registry import SkillRegistry, bootstrap_builtin_skills
        bootstrap_builtin_skills()
        reg = SkillRegistry.instance()
        results = []
        for meta in reg.all_skills():
            results.append({
                "name": meta.name,
                "layer": "hunter_vuln",
                "category": "vulnerability",
                "vuln_type": meta.vuln_type,
                "cwe": meta.cwe,
                "description": f"Autonomous verification & exploit generation for {meta.vuln_type}",
                "class": meta.cls.__name__ if meta.cls else meta.name,
            })
        return sorted(results, key=lambda x: x["name"])

    @staticmethod
    def get_kali_tool_skills() -> List[Dict[str, Any]]:
        """Retrieves Kali Tool Agent skills from ``KALI_TOOL_CATALOG``."""
        from core.arsenal.kali_catalog import KALI_TOOL_CATALOG
        results = []
        for _name, tool in KALI_TOOL_CATALOG.items():
            results.append({
                "name": tool.name,
                "layer": "kali_arsenal",
                "category": tool.category.value,
                "kali_package": tool.kali_package,
                "binary": tool.binary_name,
                "risk_level": tool.risk_level,
                "description": tool.description,
                "default_args": " ".join(tool.default_args),
            })
        return sorted(results, key=lambda x: (x["category"], x["name"]))

    @staticmethod
    def get_agentic_bug_hunter_skills() -> List[Dict[str, Any]]:
        """Compatibility alias; archived intake packs are not active skills."""
        return []

    @staticmethod
    def get_opencode_library_skills() -> List[Dict[str, Any]]:
        """Retrieves installed OpenCode project skills from ``.opencode/skills/MANIFEST.json``."""
        results = []
        manifest_path = _REPO_ROOT / ".opencode" / "skills" / "MANIFEST.json"
        if not manifest_path.is_file():
            return results
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
            for item in data.get("skills", []):
                name = item.get("name", "")
                results.append({
                    "name": name,
                    "layer": "opencode_library",
                    "category": item.get("kind", "project_skill"),
                    "description": (item.get("description") or "").replace("\n", " ").strip(),
                    "filepath": item.get("source", ""),
                })
        except Exception:
            pass
        return results

    @classmethod
    def list_all_skills(
        cls,
        category: Optional[str] = None,
        layer: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Returns consolidated list of all skills filtered optionally by category or layer."""
        all_skills: List[Dict[str, Any]] = []

        if not layer or layer == "directory":
            all_skills.extend(cls.get_directory_skills())
        if not layer or layer == "hunter_vuln":
            all_skills.extend(cls.get_hunter_skills())
        if not layer or layer == "kali_arsenal":
            all_skills.extend(cls.get_kali_tool_skills())
        if not layer or layer == "agentic_bug_hunter":
            all_skills.extend(cls.get_agentic_bug_hunter_skills())
        if not layer or layer == "opencode_library":
            all_skills.extend(cls.get_opencode_library_skills())

        if category:
            cat_lower = category.lower()
            all_skills = [
                s for s in all_skills
                if cat_lower in str(s.get("category", "")).lower()
                or cat_lower in str(s.get("layer", "")).lower()
            ]

        return all_skills

    @classmethod
    def get_skill_details(cls, skill_name: str) -> Optional[Dict[str, Any]]:
        name_lower = skill_name.strip().lower()
        for s in cls.list_all_skills():
            if str(s.get("name", "")).lower() == name_lower or str(s.get("class", "")).lower() == name_lower:
                return s
        return None

    @classmethod
    def get_summary_stats(cls) -> Dict[str, Any]:
        """Provides accurate dynamic breakdown statistics across all layers."""
        dir_skills = cls.get_directory_skills()
        hunter_skills = cls.get_hunter_skills()
        kali_skills = cls.get_kali_tool_skills()
        abh_skills = cls.get_agentic_bug_hunter_skills()
        opencode_skills = cls.get_opencode_library_skills()

        dir_cats: Dict[str, int] = {}
        for s in dir_skills:
            cat = str(s.get("category", "other"))
            dir_cats[cat] = dir_cats.get(cat, 0) + 1

        kali_cats: Dict[str, int] = {}
        for s in kali_skills:
            cat = str(s.get("category", "other"))
            kali_cats[cat] = kali_cats.get(cat, 0) + 1

        all_unique_names = {
            str(s.get("name", "")).lower()
            for s in (*dir_skills, *hunter_skills, *kali_skills, *abh_skills, *opencode_skills)
            if s.get("name")
        }

        return {
            "total_skills": len(dir_skills) + len(hunter_skills) + len(kali_skills) + len(abh_skills) + len(opencode_skills),
            "unique_skills_count": len(all_unique_names),
            "directory_skills_count": len(dir_skills),
            "directory_categories": dir_cats,
            "hunter_vuln_skills_count": len(hunter_skills),
            "kali_tool_skills_count": len(kali_skills),
            "kali_categories": kali_cats,
            "agentic_bug_hunter_skills_count": len(abh_skills),
            "opencode_library_skills_count": len(opencode_skills),
        }
