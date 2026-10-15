"""
Backward-compatibility alias for MemoryManager 2.0
"""
from core.system.memory_manager_v2 import (
    MemoryManager,
    ExplorationMemory,
    ProjectMemory,
    BlackboardState,
    BrowserInteraction,
)

__all__ = [
    "MemoryManager",
    "ExplorationMemory",
    "ProjectMemory",
    "BlackboardState",
    "BrowserInteraction",
]
