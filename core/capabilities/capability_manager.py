"""
Capability Security & Sandbox Manager
Enforces fine-grained principle-of-least-privilege capability permissions on skills and agent actions.
Replaces blanket sudo/root execution with strict capability tokens and workspace sandboxing.
"""
from __future__ import annotations

import enum
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class Capability(str, enum.Enum):
    # Filesystem capabilities
    FILESYSTEM_READ = "filesystem.read"
    FILESYSTEM_WRITE = "filesystem.write"

    # Process capabilities
    PROCESS_RUN = "process.run"
    PROCESS_KILL = "process.kill"

    # Network capabilities
    NETWORK_HTTP = "network.http"
    NETWORK_SCAN = "network.scan"
    NETWORK_DNS = "network.dns"

    # Browser capabilities
    BROWSER_NAVIGATE = "browser.navigate"
    BROWSER_INTERACT = "browser.interact"
    BROWSER_NETWORK_INTERCEPT = "browser.network_intercept"
    BROWSER_SCREENSHOT = "browser.screenshot"

    # Knowledge & Database capabilities
    KNOWLEDGE_READ = "knowledge.read"
    KNOWLEDGE_WRITE = "knowledge.write"


@dataclass
class CapabilityToken:
    """رمز تصريح ممنوح لـ Skill أو Process محددة"""
    entity_name: str
    granted_capabilities: Set[Capability] = field(default_factory=set)
    allowed_workspace_root: Optional[Path] = None

    def has_capability(self, capability: Capability) -> bool:
        return capability in self.granted_capabilities

    def grant(self, capability: Capability) -> None:
        self.granted_capabilities.add(capability)

    def revoke(self, capability: Capability) -> None:
        self.granted_capabilities.discard(capability)


class CapabilityManager:
    """
    مدير الصلاحيات والقدرات (Capability Manager):
    - يمنح رموز التصاريح (Capability Tokens) لكل مهارة بناءً على ما تطلبه فقط.
    - يتحقق من قيود الـ Sandbox لضمان عدم وصول المهارات لمسارات خارج الـ Workspace.
    """

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = (workspace_root or Path("workspace")).resolve()
        self._tokens: Dict[str, CapabilityToken] = {}

    def create_skill_token(
        self,
        skill_name: str,
        declared_capabilities: List[str]
    ) -> CapabilityToken:
        """إنشاء وتوثيق تصريح خاص بمهارة محددة"""
        caps: Set[Capability] = set()
        for c in declared_capabilities:
            try:
                caps.add(Capability(c))
            except ValueError:
                logger.debug(f"[CapabilityManager] Unknown capability '{c}' declared for {skill_name}")

        token = CapabilityToken(
            entity_name=skill_name,
            granted_capabilities=caps,
            allowed_workspace_root=self.workspace_root
        )
        self._tokens[skill_name] = token
        return token

    def create_full_access_token(self, entity_name: str = "hunter_agent") -> CapabilityToken:
        """منح الـ Agent كامل الصلاحيات والقدرات (Full Capabilities Mode) لبيئات الاختبار المصرحة"""
        all_caps = set(Capability)
        token = CapabilityToken(
            entity_name=entity_name,
            granted_capabilities=all_caps,
            allowed_workspace_root=self.workspace_root
        )
        self._tokens[entity_name] = token
        logger.info(f"[CapabilityManager] Granted FULL CAPABILITIES ({len(all_caps)} permissions) to '{entity_name}'")
        return token

    def check_permission(self, token: CapabilityToken, required: Capability) -> bool:
        """التحقق من امتلاك الـ Token للـ Capability المطلوبة"""
        if not token.has_capability(required):
            logger.warning(
                f"[CapabilityManager] ACCESS DENIED: '{token.entity_name}' lacks required capability '{required.value}'"
            )
            return False
        return True

    def verify_sandbox_path(self, target_path: Path, token: CapabilityToken) -> bool:
        """
        التحقق من أن مسار الملف يقع تماماً داخل الـ Workspace المسموح (Sandbox Enclosure)
        """
        try:
            resolved = Path(target_path).resolve()
            allowed = (token.allowed_workspace_root or self.workspace_root).resolve()
            # Must be subpath of allowed root or current working dir if relative
            return allowed in resolved.parents or resolved == allowed
        except Exception:
            return False
