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
        learning_storage: Optional[str] = None
    ):
        self.project = ProjectMemory(project_storage)
        self.target = TargetMemory(target_storage)
        self.false_positive = FalsePositiveMemory(fp_storage)
        self.learning = LearningMemory(learning_storage)
