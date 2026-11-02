"""Root controller package for the HunterAI agent hierarchy.

Public surface:

* :class:`AgentHierarchy` -- the tree (spawn, delegate, re-task, kill, replace)
* :class:`SharedMemory` -- append-only, hash-chained memory shared by all agents
* :class:`PermissionPolicy` -- capability model bound to a signed grant
* :class:`RootController` -- owner of the three, and the dispatch gate
"""

from .arsenal import Arsenal, ToolEntry
from .hierarchy import (
    AgentHierarchy,
    AgentNode,
    AgentStatus,
    HierarchyError,
)
from .playbooks import PlaybookRunner, PlaybookStep
from .permissions import (
    ACTION_CAPABILITIES,
    DEFAULT_CAPABILITIES,
    PROFILE_CAPABILITIES,
    PermissionPolicy,
    PermissionSet,
)
from .root_controller import RootController
from .shared_memory import Namespace, SharedMemory, redact_secrets

__all__ = [
    "ACTION_CAPABILITIES",
    "AgentHierarchy",
    "AgentNode",
    "AgentStatus",
    "Arsenal",
    "DEFAULT_CAPABILITIES",
    "HierarchyError",
    "Namespace",
    "PROFILE_CAPABILITIES",
    "PermissionPolicy",
    "PermissionSet",
    "PlaybookRunner",
    "PlaybookStep",
    "RootController",
    "SharedMemory",
    "ToolEntry",
    "redact_secrets",
]
