"""
Adaptive Skill Router
Intelligently routes and schedules specialized skills based on discovered application surfaces, parameter types, and untested hypotheses.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from core.database.knowledge_db import KnowledgeDB
from core.mission_state import MissionState
from core.skill_registry import SkillMeta, SkillRegistry

logger = logging.getLogger(__name__)


class SkillRouter:
    """
    موجه المهارات التكيفي (Adaptive Skill Router):
    - يحلل قاعدة المعرفة (KnowledgeDB) وقائمة الفرضيات غير المختبرة.
    - يختار المهارة الأمنية الأكثر ملاءمة وفائدة للمرحلة التالية بدلاً من الفحص العشوائي.
    - يوفر تبريراً منطقياً واضحاً لاختيار كل مهارة.
    """

    def __init__(self, registry: SkillRegistry, db: KnowledgeDB):
        self.registry = registry
        self.db = db

    def route_next_skill(self, state: MissionState) -> Optional[Tuple[SkillMeta, str]]:
        """
        تحديد المهارة التالية ذات الأولوية القصوى مع بيان سبب الاختيار
        """
        # 1. Check if there are critical untested hypotheses
        draft_hypotheses = self.db.get_hypotheses(status="draft")
        for hyp in draft_hypotheses:
            rec_skill_name = hyp.get("recommended_skill")
            if rec_skill_name and not state.is_skill_done(rec_skill_name) and not state.is_skill_failed(rec_skill_name):
                meta = self.registry.get_skill(rec_skill_name)
                if meta and self._are_dependencies_met(meta, state):
                    reason = f"Testing hypothesis '{hyp.get('title')}' based on observation: {hyp.get('observation')}"
                    return meta, reason

        # 2. Check if specific parameters demand dedicated skills
        id_endpoints = self.db.get_endpoints_with_param("id")
        if id_endpoints and not state.is_skill_done("api_surface_audit") and not state.is_skill_failed("api_surface_audit"):
            meta = self.registry.get_skill("api_surface_audit")
            if meta and self._are_dependencies_met(meta, state):
                return meta, f"Discovered {len(id_endpoints)} endpoints with numeric object identifiers requiring authorization audit."

        # 3. Default to next ready skill in DAG
        all_ready = self.registry.get_next_skills(
            completed=state.completed_skills,
            failed=state.failed_skills,
            skipped=state.skipped_skills
        )
        if all_ready:
            first_ready = all_ready[0]
            return first_ready, f"Standard progression: Next ready skill in pipeline ({first_ready.name})"

        return None

    def _are_dependencies_met(self, meta: SkillMeta, state: MissionState) -> bool:
        """التحقق من اكتمال كافة المهارات التي تعتمد عليها المهارة المطلوبة"""
        for dep in meta.depends_on:
            if not state.is_skill_done(dep):
                return False
        return True
