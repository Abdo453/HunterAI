"""
Memory Manager (Unified Facade for Persistent Memories)
=======================================================
Coordinates ProjectMemory, TargetMemory, FalsePositiveMemory, LearningMemory,
FailureEpisodicMemory, and TaskClueCache.

 Backward-compatible: existing keyword arguments (project_storage, target_storage,
 fp_storage, learning_storage, persist) continue to work. New storages are
 opt-in via failure_storage / clue_storage.
"""
from typing import Optional

from agents.security_intelligence.project_memory import ProjectMemory
from agents.security_intelligence.target_memory import TargetMemory
from agents.security_intelligence.false_positive_memory import FalsePositiveMemory
from agents.security_intelligence.learning_memory import LearningMemory
from agents.security_intelligence.failure_episodic_memory import FailureEpisodicMemory
from agents.security_intelligence.task_clue_cache import TaskClueCache


class MemoryManager:
    """المحرك الجامع لجميع طبقات الذاكرة (MAM-PT facade)"""

    def __init__(
        self,
        project_storage: Optional[str] = None,
        target_storage: Optional[str] = None,
        fp_storage: Optional[str] = None,
        learning_storage: Optional[str] = None,
        failure_storage: Optional[str] = None,
        clue_storage: Optional[str] = None,
        persist: bool = False,
    ):
        # Default to session-only memory so each supplied target is treated as
        # new. Persistence requires an explicit opt-in by the caller.
        self.project = ProjectMemory(project_storage, persist=persist)
        self.target = TargetMemory(target_storage, persist=persist)
        self.false_positive = FalsePositiveMemory(fp_storage, persist=persist)
        self.learning = LearningMemory(learning_storage, persist=persist)

        # الطبقة الجديدة من الخطة: ذاكرة الفشل العرضية + كاش المهام والأدلة المشترك
        self.failure_episodic = FailureEpisodicMemory(failure_storage, persist=persist)
        self.task_clue = TaskClueCache(clue_storage, persist=persist)

    # ------------------------------------------------------------------ #
    # ملخص سريع لوحدات الذاكرة (للـ Dashboard / الاستقصاء)
    # ------------------------------------------------------------------ #
    def summary(self) -> dict:
        return {
            "project": {
                "technologies": len(self.project.technologies),
                "endpoints": len(self.project.api_endpoints),
                "roles": len(self.project.user_roles),
            },
            "target": {
                "targets_count": len(self.target.targets),
                "findings_count": sum(
                    len(t.get("confirmed_findings", []))
                    for t in self.target.targets.values()
                ),
            },
            "false_positive": len(self.false_positive.false_positive_records),
            "failure_episodic": len(self.failure_episodic.failures),
            "task_clue": {
                "tasks": len(self.task_clue.task_states),
                "clues": len(self.task_clue.clues),
            },
        }
