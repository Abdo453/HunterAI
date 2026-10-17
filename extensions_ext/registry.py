"""سجل الإضافات المثبّتة + تفعيل/تعطيل + فحص ثقة قبل التحميل."""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Optional

from extensions_ext.loader import (
    ExtensionError, activate_extension, deactivate_extension,
)
from extensions_ext.manifest import (
    ExtensionManifest, ManifestError, load_manifest,
)
from extensions_ext.trust import TrustLevel, TrustReport, assess_trust

logger = logging.getLogger(__name__)


@dataclass
class ExtensionRecord:
    """سجل إضافة مثبّتة."""

    manifest: ExtensionManifest
    path: str
    enabled: bool = False
    installed_at: float = field(default_factory=time.time)
    trust: Optional[TrustReport] = None
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.manifest.name,
            "version": self.manifest.version,
            "display_name": self.manifest.display_name,
            "description": self.manifest.description,
            "permissions": self.manifest.permissions,
            "enabled": self.enabled,
            "installed_at": self.installed_at,
            "trust_level": self.trust.level.value if self.trust else "unknown",
            "trust_reasons": self.trust.reasons if self.trust else [],
            "sha256": self.trust.sha256 if self.trust else "",
            "last_error": self.last_error,
            "path": self.path,
        }


class ExtensionRegistry:
    """مدير الإضافات المثبّتة — يفرض ثقة قبل التفعيل."""

    def __init__(
        self,
        *,
        extensions_root: str = "data/extensions",
        min_trust: TrustLevel = TrustLevel.LOW,
        tool_runner: Optional[Any] = None,
        llm_caller: Optional[Any] = None,
    ):
        self.root = Path(extensions_root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.min_trust = min_trust
        self.tool_runner = tool_runner
        self.llm_caller = llm_caller
        self._records: Dict[str, ExtensionRecord] = {}

    # ── التثبيت ────────────────────────────────────────────────────────────
    def install(self, ext_dir: str | Path,
                *, is_local: bool = True) -> ExtensionRecord:
        """فحص مانيفست + ثقة، ثم تسجيل الإضافة (بدون تفعيل)."""
        ext_dir = Path(ext_dir)
        manifest = load_manifest(ext_dir)   # يرمي ManifestError إذا فشل
        trust = assess_trust(
            manifest, ext_dir, is_local=is_local, min_level=self.min_trust)
        if not trust.allowed:
            raise ExtensionError(
                "الإضافة مرفوضة بسبب الثقة: " + "; ".join(trust.reasons))
        rec = ExtensionRecord(
            manifest=manifest, path=str(ext_dir), trust=trust)
        self._records[manifest.name] = rec
        return rec

    # ── التفعيل ───────────────────────────────────────────────────────────
    def enable(self, name: str) -> ModuleType:
        rec = self._records.get(name)
        if rec is None:
            raise ExtensionError(f"إضافة غير مثبّتة: {name}")
        if rec.trust is None or not rec.trust.allowed:
            raise ExtensionError(f"الإضافة {name} غير موثوقة")
        try:
            module = activate_extension(
                rec.manifest, rec.path,
                workspace=str(self.root / name / "workspace"),
                tool_runner=self.tool_runner,
                llm_caller=self.llm_caller)
        except ExtensionError as exc:
            rec.last_error = str(exc)
            rec.enabled = False
            raise
        rec.enabled = True
        rec.last_error = ""
        return module

    def disable(self, name: str) -> bool:
        rec = self._records.get(name)
        if rec is None or not rec.enabled:
            return False
        deactivate_extension(name)
        rec.enabled = False
        return True

    # ── الاستعلام ─────────────────────────────────────────────────────────
    def get(self, name: str) -> Optional[ExtensionRecord]:
        return self._records.get(name)

    def list_extensions(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._records.values()]

    def enabled_extensions(self) -> List[ExtensionRecord]:
        return [r for r in self._records.values() if r.enabled]

    # ── Persistence (اختياري) ─────────────────────────────────────────────
    def save_state(self, path: str | Path) -> None:
        state = [r.to_dict() for r in self._records.values()]
        Path(path).write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
