"""
Mission Planner — مخطط المهام الذكي
مسؤول عن تحديد ترتيب تنفيذ الـ Skills، التحقق من الـ Dependencies، التخطيط التكيفي (Adaptive Replanning)، والتنفيذ المتوازي للمهام المستقلة.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set

from core.mission_state import MissionState
from core.skill_registry import SkillMeta, SkillRegistry

logger = logging.getLogger(__name__)

# Execution order priority by category
CATEGORY_PRIORITY = {
    "recon": 1,
    "browser": 2,
    "web": 3,
    "analysis": 4,
    "vulnerability": 5,
    "reporting": 6,
    "general": 7,
}

# Fallback skill mappings if primary skills fail
FALLBACK_SKILL_MAP: Dict[str, List[str]] = {
    "subdomain_enum": ["dns_enum"],
    "crawling": ["endpoint_discovery"],
    "port_scan": ["tech_detection"],
    "endpoint_discovery": ["api_surface_audit"],
}


class MissionPlanner:
    """
    مخطط المهام الذكي المستند إلى DAG والذكاء الاصطناعي مع دعم التنفيذ المتوازي والبدائل التكيفية:
    - يحدد الخطوات التالية الجاهزة للتنفيذ (Ready Skills)
    - يرتب المهام حسب الأولوية المنطقية (Recon -> Web -> Analysis -> Reporting)
    - يقسم المهام المستقلة إلى مجموعات متوازية (Parallel Batches)
    - يقترح مهارات بديلة (Fallback Skills) عند تعثر المهارات الأساسية
    """

    def __init__(self, registry: SkillRegistry):
        self.registry = registry

    def get_ready_skills(self, state: MissionState) -> List[SkillMeta]:
        """
        يسترجع المهارات الجاهزة للتنفيذ والتي تحققت جميع شروط اعتمادها مع ترتيبها حسب الأولوية
        """
        all_ready = self.registry.get_next_skills(
            completed=state.completed_skills,
            failed=state.failed_skills,
            skipped=state.skipped_skills,
        )

        # Filter by mission mode
        filtered: List[SkillMeta] = []
        for meta in all_ready:
            if self._is_skill_allowed_for_mode(meta, state.mode):
                filtered.append(meta)
            else:
                state.mark_skill_skipped(meta.name)

        # Sort by category priority
        filtered.sort(key=lambda m: CATEGORY_PRIORITY.get(m.category, 10))
        return filtered

    def group_independent_skills(
        self,
        ready_skills: List[SkillMeta],
        max_batch_size: int = 3
    ) -> List[List[SkillMeta]]:
        """
        تقسيم المهارات الجاهزة إلى حزم متوازية (Batches) يمكن تشغيلها في نفس الوقت عبر asyncio.gather()
        """
        if not ready_skills:
            return []

        batches: List[List[SkillMeta]] = []
        current_batch: List[SkillMeta] = []

        for skill in ready_skills:
            current_batch.append(skill)
            if len(current_batch) >= max_batch_size:
                batches.append(current_batch)
                current_batch = []

        if current_batch:
            batches.append(current_batch)

        return batches

    def get_fallback_skills(self, failed_skill: str, state: MissionState) -> List[SkillMeta]:
        """
        استرجاع المهارات البديلة لمهارة فاشلة لم تتم تجربتها بعد
        """
        candidates = FALLBACK_SKILL_MAP.get(failed_skill, [])
        fallbacks: List[SkillMeta] = []
        for name in candidates:
            if not state.is_skill_done(name) and not state.is_skill_failed(name):
                meta = self.registry.get_skill(name)
                if meta:
                    fallbacks.append(meta)
        return fallbacks

    def _is_skill_allowed_for_mode(self, meta: SkillMeta, mode: str) -> bool:
        """يتحقق مما إذا كانت المهارة مسموحة في النمط المحدد"""
        if mode in ("full", "auto"):
            return True
        if mode == "recon_only":
            return meta.category in ("recon", "browser", "reporting", "analysis")
        if mode == "web_only":
            return meta.category in ("web", "browser", "recon", "reporting", "analysis")
        if mode == "vuln_only":
            return meta.category in ("vulnerability", "browser", "reporting", "analysis")
        if mode == "quick":
            return meta.name in (
                "subdomain_enum", "live_host_detection", "port_scan",
                "tech_detection", "browser_recon", "crawling", "report_generator", "triage_gate"
            )
        return True

    def should_terminate(self, state: MissionState) -> bool:
        """يتحقق مما إذا كانت المهمة قد انتهت أو لا توجد خطوات متبقية"""
        if state.status in ("completed", "failed", "paused"):
            return True

        ready = self.get_ready_skills(state)
        return len(ready) == 0

    async def get_ai_strategic_guidance(
        self,
        state: MissionState,
        latest_findings: List[Dict[str, Any]]
    ) -> Optional[str]:
        """
        استشارة محرك الذكاء الاصطناعي لتوجيه الأولويات بناءً على المعطيات المكتشفة
        """
        if not latest_findings:
            return None

        try:
            from core.ai_reasoning_core import AIReasoningCore
            prompt = (
                f"Target: {state.target}\n"
                f"Completed Skills: {state.completed_skills}\n"
                f"Failed Skills: {state.failed_skills}\n"
                f"Findings Count: {state.findings_count}\n"
                f"Recent Findings: {str(latest_findings)[:1000]}\n\n"
                "Recommend the top priority security focus area for next phases."
            )
            guidance = await AIReasoningCore.ask_ai(
                prompt=prompt,
                system_prompt="You are an autonomous defensive security mission planner. Provide concise strategic guidance."
            )
            return guidance.strip() if guidance else None
        except Exception as exc:
            logger.debug(f"[MissionPlanner] AI guidance skipped: {exc}")
            return None
