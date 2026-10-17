"""تحميل وتفعيل الإضافات في namespace معزول.

الإضافة تُحمَّل عبر importlib بمسارها، وتستقبل "host API" مقيّدة
حسب صلاحياتها. أي محاولة تجاوز الصلاحيات تُرفض (fail-closed).
"""
from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Dict, Optional

from extensions_ext.manifest import ExtensionManifest, Permission

logger = logging.getLogger(__name__)


class ExtensionError(RuntimeError):
    """فشل تحميل/تفعيل إضافة."""


class PermissionDenied(ExtensionError):
    """الإضافة حاولت استخدام صلاحية غير ممنوحة."""


class HostAPI:
    """واجهة مقيّدة تُسلَّم للإضافة — تتحقق من الصلاحيات في كل نداء."""

    def __init__(self, manifest: ExtensionManifest, workspace: Path,
                 tool_runner: Optional[Callable] = None,
                 llm_caller: Optional[Callable] = None):
        self._manifest = manifest
        self._workspace = workspace
        self._tool_runner = tool_runner
        self._llm_caller = llm_caller
        self._granted = set(manifest.permissions)

    def _check(self, perm: str) -> None:
        if perm not in self._granted:
            raise PermissionDenied(
                f"الإضافة {self._manifest.name} تحاول استخدام {perm!r} "
                f"بدون صلاحية (الممنوحة: {sorted(self._granted)})")

    def read_workspace(self, relpath: str) -> bytes:
        self._check(Permission.READ_WORKSPACE)
        target = (self._workspace / relpath).resolve()
        if not str(target).startswith(str(self._workspace.resolve())):
            raise PermissionDenied("خارج مجلد العمل (path traversal)")
        return target.read_bytes()

    def write_workspace(self, relpath: str, data: bytes) -> Path:
        self._check(Permission.WRITE_WORKSPACE)
        target = (self._workspace / relpath).resolve()
        if not str(target).startswith(str(self._workspace.resolve())):
            raise PermissionDenied("خارج مجلد العمل (path traversal)")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def call_llm(self, prompt: str, **kwargs) -> str:
        self._check(Permission.CALL_LLM)
        if self._llm_caller is None:
            raise ExtensionError("لا يوجد مزوّد LLM مُهيّأ")
        return self._llm_caller(prompt, **kwargs)

    def run_tool(self, tool_name: str, **kwargs) -> Any:
        self._check(Permission.RUN_TOOL)
        if self._tool_runner is None:
            raise ExtensionError("لا يوجد مشغّل أدوات مُهيّأ")
        return self._tool_runner(tool_name, **kwargs)


# ── إدارة التحميل ─────────────────────────────────────────────────────────
_LOADED: Dict[str, ModuleType] = {}


def activate_extension(
    manifest: ExtensionManifest,
    ext_dir: str | Path,
    *,
    workspace: str | Path = "data/extensions_workspace",
    tool_runner: Optional[Callable] = None,
    llm_caller: Optional[Callable] = None,
) -> ModuleType:
    """تحميل إضافة وإرجاع الوحدة المحلّية + حقن الـ HostAPI."""
    ext_dir = Path(ext_dir)
    entry_path = (ext_dir / manifest.entry).resolve()
    if not str(entry_path).startswith(str(ext_dir.resolve())):
        raise ExtensionError("entry خارج مجلد الإضافة")
    if not entry_path.exists():
        raise ExtensionError(f"entry غير موجود: {manifest.entry}")

    module_name = f"hunterai_ext_{manifest.name.replace('-', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, entry_path)
    if spec is None or spec.loader is None:
        raise ExtensionError(f"تعذّر إنشاء spec لـ {entry_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        sys.modules.pop(module_name, None)
        raise ExtensionError(f"فشل تنفيذ وحدة الإضافة: {exc}") from exc

    # حقن الـ HostAPI المقيّد
    host = HostAPI(
        manifest, Path(workspace),
        tool_runner=tool_runner, llm_caller=llm_caller)
    module.__dict__["HUNTER_HOST"] = host
    module.__dict__["HUNTER_MANIFEST"] = manifest

    # التحقق من وجود نقطة الدخول المعلنة
    if not hasattr(module, "register") and not hasattr(module, "run"):
        logger.warning(
            "الإضافة %s لا تعرّف register() أو run()", manifest.name)

    _LOADED[manifest.name] = module
    return module


def deactivate_extension(name: str) -> bool:
    """إلغاء تحميل إضافة من الذاكرة."""
    module_name = f"hunterai_ext_{name.replace('-', '_')}"
    if module_name in sys.modules:
        del sys.modules[module_name]
    return _LOADED.pop(name, None) is not None


def get_loaded(name: str) -> Optional[ModuleType]:
    return _LOADED.get(name)
