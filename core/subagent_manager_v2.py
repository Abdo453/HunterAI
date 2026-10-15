"""
Backward-compatibility alias for SubagentManager 2.0
"""
from core.system.subagent_manager_v2 import (
    SubagentManager,
    SubagentInstance,
    SubagentStatus,
)

__all__ = ["SubagentManager", "SubagentInstance", "SubagentStatus"]
