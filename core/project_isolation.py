"""
Backward-compatibility alias for ProjectIsolationManager
"""
from core.system.project_isolation import ProjectIsolationManager, ProjectSandbox, SecretReference

__all__ = ["ProjectIsolationManager", "ProjectSandbox", "SecretReference"]
