"""
Unified Skills Viewer & Aggregator for PentestAI-Unified.

Consolidates all 4 layers of skills across the platform:
1. Directory Skills (skills/**/skill.yaml) - 42 structured skills
2. Hunter Vulnerability Skills (agents/skills/*.py) - 29 specialized modules
3. Kali Arsenal Tool Skills (core/arsenal/kali_catalog.py) - 62 Dynamic Tool Agents
4. Learned Memory Skills (data/skills/*.txt) - Learned writeup heuristics
"""
from __future__ import annotations

import glob
import os
from typing import Any, Dict, List, Optional
import yaml


class SkillMatrixViewer:
    """Aggregates and formats all skills across the 4 platform layers."""

    @staticmethod
    def get_directory_skills() -> List[Dict[str, Any]]:
        """Scans skills/**/skill.yaml for autonomous operational skills."""
        results = []
        for yf in glob.glob("skills/**/skill.yaml", recursive=True):
            try:
                with open(yf, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        data["layer"] = "directory"
                        data["filepath"] = yf
                        results.append(data)
            except Exception:
                continue
        return sorted(results, key=lambda x: (x.get("category", ""), x.get("name", "")))

    @staticmethod
    def get_hunter_skills() -> List[Dict[str, Any]]:
        """Retrieves specialized vulnerability hunting skills from SkillRegistry."""
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
                "description": f"Autonomous verification & exploit generation for {meta.vuln_type}",
                "class": meta.cls.__name__ if meta.cls else meta.name,
            })
        return sorted(results, key=lambda x: x["name"])

    @staticmethod
    def get_kali_tool_skills() -> List[Dict[str, Any]]:
        """Retrieves all 62 Kali Tool Agent skills from KALI_TOOL_CATALOG."""
        from core.arsenal.kali_catalog import KALI_TOOL_CATALOG
        results = []
        for name, tool in KALI_TOOL_CATALOG.items():
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
        """Retrieves all 19 Agentic Bug Hunter specialized skills."""
        results = []
        base_dir = "skills_library/agentic-bug-hunter/skills"
        if not os.path.exists(base_dir):
            return results
        for item in sorted(os.listdir(base_dir)):
            md_path = os.path.join(base_dir, item, "SKILL.md")
            if os.path.isfile(md_path):
                desc = f"Agentic Bug Hunter specialized skill: {item}"
                try:
                    with open(md_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    for line in lines[:25]:
                        if line.startswith("description:"):
                            desc = line.replace("description:", "").strip().strip("'\"")
                            break
                except Exception:
                    pass
                results.append({
                    "name": f"abh-{item}",
                    "layer": "agentic_bug_hunter",
                    "category": "bug_hunter",
                    "description": desc,
                    "filepath": md_path,
                })
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

        if category:
            cat_lower = category.lower()
            all_skills = [
                s for s in all_skills
                if cat_lower in s.get("category", "").lower() or cat_lower in s.get("layer", "").lower()
            ]

        return all_skills

    @classmethod
    def get_skill_details(cls, skill_name: str) -> Optional[Dict[str, Any]]:
        """Finds detailed metadata for a skill by name."""
        name_lower = skill_name.strip().lower()
        for s in cls.list_all_skills():
            if s.get("name", "").lower() == name_lower or s.get("class", "").lower() == name_lower:
                return s
        return None

    @classmethod
    def get_summary_stats(cls) -> Dict[str, Any]:
        """Provides high-level breakdown statistics."""
        dir_skills = cls.get_directory_skills()
        hunter_skills = cls.get_hunter_skills()
        kali_skills = cls.get_kali_tool_skills()
        abh_skills = cls.get_agentic_bug_hunter_skills()

        dir_cats: Dict[str, int] = {}
        for s in dir_skills:
            cat = s.get("category", "other")
            dir_cats[cat] = dir_cats.get(cat, 0) + 1

        kali_cats: Dict[str, int] = {}
        for s in kali_skills:
            cat = s.get("category", "other")
            kali_cats[cat] = kali_cats.get(cat, 0) + 1

        return {
            "total_skills": len(dir_skills) + len(hunter_skills) + len(kali_skills) + len(abh_skills),
            "directory_skills_count": len(dir_skills),
            "directory_categories": dir_cats,
            "hunter_vuln_skills_count": len(hunter_skills),
            "kali_tool_skills_count": len(kali_skills),
            "kali_categories": kali_cats,
            "agentic_bug_hunter_skills_count": len(abh_skills),
        }
