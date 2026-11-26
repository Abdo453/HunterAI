#!/usr/bin/env python3
"""
Skill Context Injector (Internal Semantic RAG)
==============================================
يوجّه المهام عبر مهارة HunterAI المركزية ويحمّل المراجع المطابقة (multi-route top-K)
دون قصّ عشوائي بحد 24 سطراً أو 150 حرفاً للسطر.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = BASE_DIR / ".opencode" / "skills"
AGENTS_SKILLS_DIR = BASE_DIR / ".agents" / "skills"
MANIFEST_PATH = SKILLS_DIR / "MANIFEST.json"

ROLE_KEYWORDS = {
    "dialogue": ["browser", "recon", "osint", "mapping", "discovery"],
    "coder": ["code", "script", "automation", "fuzz", "build", "patch"],
    "redteam": ["red team", "pentest", "exploit", "bypass", "jailbreak", "injection"],
    "deep_thinker": ["analysis", "threat", "logic", "strategy", "attack path"],
    "cve_hunter": ["cve", "vulnerability", "variant", "exploit", "scan"],
    "adversary_chainer": ["chain", "pivot", "escalation", "identity", "cloud"],
    "network_analyst": ["network", "protocol", "packet", "service", "identity"],
}


class SkillContextInjector:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.skills: List[Dict[str, Any]] = []
        self._load_manifest()
        self._initialized = True

    def _load_manifest(self):
        if not MANIFEST_PATH.exists():
            self._load_from_disk()
            return
        try:
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                raw_skills = data.get("skills", [])
                if isinstance(raw_skills, dict):
                    self.skills = list(raw_skills.values())
                elif isinstance(raw_skills, list):
                    self.skills = raw_skills
                else:
                    self.skills = []
        except Exception:
            self._load_from_disk()

    def _load_from_disk(self):
        self.skills = []
        for base in [SKILLS_DIR, AGENTS_SKILLS_DIR]:
            if not base.exists():
                continue
            for d in base.iterdir():
                if d.is_dir() and (d / "SKILL.md").exists():
                    self.skills.append({
                        "name": d.name,
                        "description": f"Cybersecurity skill {d.name}",
                        "source": str(d / "SKILL.md"),
                    })

    def get_relevant_skills(self, role: str, query: str = "", limit: int = 5) -> List[Dict[str, Any]]:
        if not self.skills:
            return []

        role_keys = [k.lower() for k in ROLE_KEYWORDS.get(role, [])]
        query_words = [w.lower() for w in re.findall(r"\w+", query)] if query else []

        scored_skills = []
        for s in self.skills:
            score = 0
            name = s.get("name", "").lower()
            desc = s.get("description", "").lower()

            for q_term in query_words:
                if len(q_term) < 2:
                    continue
                if q_term in name:
                    score += 30
                if q_term in desc:
                    score += 12

            for r_term in role_keys:
                if len(r_term) < 3:
                    continue
                if r_term in name:
                    score += 3
                if r_term in desc:
                    score += 1

            if score > 0:
                scored_skills.append((score, s))

        scored_skills.sort(key=lambda x: x[0], reverse=True)
        selected = [item[1] for item in scored_skills[:limit]]
        if not selected:
            primary = next((item for item in self.skills if item.get("name") == "hunterai-redteam"), None)
            if primary:
                selected = [primary]
        return selected

    @staticmethod
    def _keyword_matches(keyword: str, query_lower: str) -> bool:
        kw = keyword.lower().strip()
        if not kw:
            return False
        if re.fullmatch(r"[a-z0-9_ -]+", kw):
            pattern = r"(?<![a-z0-9_])" + re.escape(kw) + r"(?![a-z0-9_])"
            return re.search(pattern, query_lower) is not None
        return kw in query_lower

    @classmethod
    def _routes_for_query(
        cls,
        skill: Dict[str, Any],
        query: str,
        *,
        top_k: int = 3,
        min_score: int = 2,
    ) -> List[str]:
        """Multi-route top-K selector: returns up to ``top_k`` distinct reference paths
        achieving ``score >= min_score`` (falling back to the single best match if max score == 1)."""
        if not query:
            return []
        query_lower = query.lower()
        ranked: List[tuple[int, str]] = []
        for route in skill.get("routes", []):
            path = str(route.get("path") or "").strip()
            if not path:
                continue
            score = sum(
                1 for keyword in route.get("keywords", []) if cls._keyword_matches(keyword, query_lower)
            )
            if score > 0:
                ranked.append((score, path))

        if not ranked:
            return []

        ranked.sort(key=lambda item: item[0], reverse=True)
        strong = [path for score, path in ranked if score >= min_score]
        if strong:
            # Deduplicate preserving rank order
            dedup: List[str] = []
            for p in strong:
                if p not in dedup:
                    dedup.append(p)
            return dedup[: max(1, top_k)]
        # Single-keyword query fallback: still route the single highest-scoring reference
        return [ranked[0][1]]

    @classmethod
    def _route_for_query(cls, skill: Dict[str, Any], query: str) -> Optional[str]:
        """Backwards-compatible single-route helper returning the top route."""
        routes = cls._routes_for_query(skill, query, top_k=1, min_score=1)
        return routes[0] if routes else None

    def extract_skill_summary(
        self,
        skill: Dict[str, Any],
        query: str = "",
        max_chars: int = 12000,
        *,
        top_k_routes: int = 3,
        min_route_score: int = 2,
    ) -> str:
        """Read full SKILL.md instructions (without 24-line / 150-char truncation)
        and append all multi-route top-K matched references."""
        skill_name = skill.get("name", "")
        skill_dir = SKILLS_DIR / skill_name
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            skill_dir = AGENTS_SKILLS_DIR / skill_name
            skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            return ""

        try:
            content = skill_file.read_text(encoding="utf-8", errors="ignore")
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    content = parts[2].strip()

            routes = self._routes_for_query(
                skill, query, top_k=top_k_routes, min_score=min_route_score
            )
            routed_set = {r.strip().replace("\\", "/") for r in routes}

            # Preserve complete structured instructions (no 24-line or 150-char line dropping),
            # while omitting unrouted `references/*.md` routing-table entries when a query
            # selected specific route(s) so unrouted reference paths never pollute context.
            ref_link_pat = re.compile(r"\((references/[^)\s]+\.md)\)")
            lines: List[str] = []
            for raw_line in content.splitlines():
                stripped = raw_line.rstrip()
                if not stripped.strip():
                    continue
                if routed_set:
                    linked_refs = [m.replace("\\", "/") for m in ref_link_pat.findall(stripped)]
                    if linked_refs and not any(ref in routed_set for ref in linked_refs):
                        continue
                lines.append(stripped)

            body = "\n".join(lines)
            if max_chars > 0 and len(body) > max_chars:
                body = body[:max_chars]

            routed_sections: List[str] = []
            skill_dir_resolved = skill_dir.resolve()
            for route in routes:
                reference = (skill_dir / route).resolve(strict=False)
                if reference.is_relative_to(skill_dir_resolved) and reference.is_file():
                    routed_text = reference.read_text(encoding="utf-8", errors="ignore").strip()
                    if max_chars > 0 and len(routed_text) > max_chars:
                        routed_text = routed_text[:max_chars]
                    routed_sections.append(f"[Routed reference: {route}]\n{routed_text}")

            if routed_sections:
                return f"{body}\n\n" + "\n\n".join(routed_sections)
            return body
        except Exception:
            return ""

    def build_injected_context(
        self,
        role: str,
        query: str = "",
        max_skills: int = 4,
        max_chars: int = 12000,
    ) -> str:
        relevant = self.get_relevant_skills(role, query, limit=max_skills)
        if not relevant:
            return ""

        context_blocks = [
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            f"🎯 الترسانة المعرفية التكتيكية المحقونة ({len(relevant)} مهارات تخصصية):",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ]

        for skill in relevant:
            name = skill.get("name", "")
            title = skill.get("title", name)
            summary = self.extract_skill_summary(skill, query=query, max_chars=max_chars)
            if not summary:
                summary = skill.get("description", "")

            block = f"■ [SKILL: {title}]\n{summary}"
            context_blocks.append(block)

        context_blocks.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return "\n".join(context_blocks)


skill_injector = SkillContextInjector()

if __name__ == "__main__":
    import sys
    role_arg = sys.argv[1] if len(sys.argv) > 1 else "redteam"
    query_arg = sys.argv[2] if len(sys.argv) > 2 else "bypass rate limit and test race condition"
    ctx = skill_injector.build_injected_context(role_arg, query_arg)
    print(ctx)
