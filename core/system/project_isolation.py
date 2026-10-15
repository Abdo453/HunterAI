"""
HunterAI Project Isolation Manager (Phase 4)
============================================
Enforces strict multi-tenant sandboxing between assessment projects:
1. Isolated memory stores per project
2. Indirect secret references loaded from `secrets/` (never exposing raw values directly)
3. Hard boundaries preventing cross-project memory contamination without explicit A2A authorization
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.project_isolation")


@dataclass
class SecretReference:
    """
    Indirect handle to a secret stored in secrets/ directory.
    Agents only interact with the reference handle, not the raw secret value.
    """
    ref_id: str
    secret_type: str
    description: str
    allowed_projects: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    _raw_path: Optional[str] = None

    def can_access(self, project_id: str) -> bool:
        if not self.allowed_projects or "*" in self.allowed_projects:
            return True
        return project_id in self.allowed_projects

    def get_masked_representation(self) -> str:
        return f"[SECRET_REF:{self.ref_id}:TYPE={self.secret_type}]"


class ProjectSandbox:
    """
    Isolated environment for an individual project.
    """
    def __init__(self, project_id: str, name: str, scope: List[str], base_dir: Path):
        self.project_id = project_id
        self.name = name
        self.scope = list(scope)
        self.created_at = time.time()
        self.project_dir = base_dir / project_id
        self.project_dir.mkdir(parents=True, exist_ok=True)
        
        # Isolated storage paths
        self.memory_dir = self.project_dir / "memory"
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.artifacts_dir = self.project_dir / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory store
        self.memory_store: Dict[str, Any] = {
            "created_at": self.created_at,
            "observations": [],
            "hypotheses": [],
            "findings": [],
            "kv": {},
        }
        self.bound_secrets: Dict[str, SecretReference] = {}

    def set_memory(self, key: str, value: Any) -> None:
        self.memory_store["kv"][key] = value

    def get_memory(self, key: str, default: Any = None) -> Any:
        return self.memory_store["kv"].get(key, default)

    def persist_state(self) -> Path:
        state_file = self.memory_dir / "state.json"
        state_file.write_text(json.dumps(self.memory_store, indent=2, default=str), encoding="utf-8")
        return state_file


class ProjectIsolationManager:
    """
    Central authority managing all project sandboxes, secret references,
    and cross-project communication firewalls.
    """
    def __init__(self, workspace_root: str | Path = "data/projects", secrets_dir: str | Path = "secrets"):
        self.workspace_root = Path(workspace_root)
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.secrets_dir = Path(secrets_dir)
        self.secrets_dir.mkdir(parents=True, exist_ok=True)

        self._projects: Dict[str, ProjectSandbox] = {}
        self._secret_refs: Dict[str, SecretReference] = {}
        self._authorized_a2a_channels: Set[Tuple[str, str]] = set()  # (from_proj, to_proj)

        self._load_secrets()

    def _load_secrets(self) -> None:
        """Loads metadata references from secrets directory without logging values"""
        for f in self.secrets_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                ref_id = data.get("ref_id") or f.stem
                ref = SecretReference(
                    ref_id=ref_id,
                    secret_type=data.get("type", "api_key"),
                    description=data.get("description", ""),
                    allowed_projects=list(data.get("allowed_projects", [])),
                    _raw_path=str(f),
                )
                self._secret_refs[ref_id] = ref
            except Exception as e:
                logger.warning("Failed loading secret reference from %s: %s", f, e)

    def create_project(self, project_id: str, name: str = "", scope: Optional[List[str]] = None) -> ProjectSandbox:
        """Creates a strictly sandboxed project with isolated memory store"""
        if project_id in self._projects:
            return self._projects[project_id]
        
        sandbox = ProjectSandbox(
            project_id=project_id,
            name=name or project_id,
            scope=scope or [],
            base_dir=self.workspace_root,
        )
        self._projects[project_id] = sandbox
        logger.info("Project sandbox created: id=%s dir=%s", project_id, sandbox.project_dir)
        return sandbox

    def get_project(self, project_id: str) -> Optional[ProjectSandbox]:
        return self._projects.get(project_id)

    def list_projects(self) -> List[str]:
        return list(self._projects.keys())

    def bind_secret_reference(self, project_id: str, secret_ref_id: str) -> bool:
        """Binds a secret reference to a project after verifying project authorization"""
        sandbox = self._projects.get(project_id)
        if not sandbox:
            return False
            
        ref = self._secret_refs.get(secret_ref_id)
        if not ref or not ref.can_access(project_id):
            logger.warning("Access denied: Project '%s' cannot access secret '%s'", project_id, secret_ref_id)
            return False
            
        sandbox.bound_secrets[secret_ref_id] = ref
        return True

    def get_project_secret_reference(self, project_id: str, secret_ref_id: str) -> Optional[SecretReference]:
        sandbox = self._projects.get(project_id)
        if not sandbox:
            return None
        return sandbox.bound_secrets.get(secret_ref_id)

    def authorize_a2a_communication(self, from_project: str, to_project: str) -> None:
        """Explicitly permits cross-project messaging between two sandboxes"""
        self._authorized_a2a_channels.add((from_project, to_project))
        logger.info("A2A communication explicitly permitted: %s -> %s", from_project, to_project)

    def revoke_a2a_communication(self, from_project: str, to_project: str) -> None:
        self._authorized_a2a_channels.discard((from_project, to_project))

    def can_communicate(self, from_project: str, to_project: str) -> bool:
        """Blocks cross-project communication unless explicitly authorized via A2A"""
        if from_project == to_project:
            return True
        return (from_project, to_project) in self._authorized_a2a_channels

    def transfer_data_a2a(self, from_project: str, to_project: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
        """Safely transfers authorized payload across project boundaries"""
        if not self.can_communicate(from_project, to_project):
            return False, f"Cross-project transfer blocked: {from_project} is not authorized to communicate with {to_project}."
            
        dst_sandbox = self.get_project(to_project)
        if not dst_sandbox:
            return False, f"Destination project '{to_project}' does not exist."
            
        inbox = dst_sandbox.get_memory("a2a_inbox", [])
        inbox.append({
            "from_project": from_project,
            "timestamp": time.time(),
            "payload": payload,
        })
        dst_sandbox.set_memory("a2a_inbox", inbox)
        return True, "Data transferred successfully via A2A channel."
