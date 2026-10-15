"""
Memory Manager (Unified Facade for Persistent Memories)
Coordinates ProjectMemory, TargetMemory, FalsePositiveMemory, and LearningMemory.
"""
from typing import Optional
from agents.security_intelligence.project_memory import ProjectMemory
from agents.security_intelligence.target_memory import TargetMemory
from agents.security_intelligence.false_positive_memory import FalsePositiveMemory
from agents.security_intelligence.learning_memory import LearningMemory


class MemoryManager:
    """المحرك الجامع لجميع طبقات الذاكرة"""

    def __init__(
        self,
        project_storage: Optional[str] = None,
        target_storage: Optional[str] = None,
        fp_storage: Optional[str] = None,
        learning_storage: Optional[str] = None,
        persist: bool = False,
    ):
        # Default to session-only memory so each supplied target is treated as
        # new.  Persistence requires an explicit opt-in by the caller.
        self.project = ProjectMemory(project_storage, persist=persist)
        self.target = TargetMemory(target_storage, persist=persist)
        self.false_positive = FalsePositiveMemory(fp_storage, persist=persist)
        self.learning = LearningMemory(learning_storage, persist=persist)
