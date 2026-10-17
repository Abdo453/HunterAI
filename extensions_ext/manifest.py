"""مانيفست الإضافات (plugin.json) — قراءة وتحقق صارم (fail-closed)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List


class Permission:
    """صلاحيات مقيّدة — أي صلاحية غير معروفة تُرفض."""

    READ_WORKSPACE = "read_workspace"     # قراءة ملفات مجلد العمل
    WRITE_WORKSPACE = "write_workspace"   # كتابة نتائج في مجلد العمل
    CALL_LLM = "call_llm"                 # استدعاء نموذج عبر المزوّد
    RUN_TOOL = "run_tool"                 # تشغيل أداة مسجّلة في tool_registry
    NETWORK = "network"                   # اتصال شبكة مباشر (httpx)
    READ_ENV = "read_env"                 # قراءة متغيرات بيئة (حساس)

    ALL = (
        READ_WORKSPACE, WRITE_WORKSPACE, CALL_LLM,
        RUN_TOOL, NETWORK, READ_ENV,
    )
    # صلاحيات عالية الخطورة تتطلب ثقة عالية
    HIGH_RISK = (CALL_LLM, RUN_TOOL, NETWORK, READ_ENV)


@dataclass
class ExtensionManifest:
    """مانيفست مُتحقَّق منه."""

    name: str
    version: str
    display_name: str = ""
    description: str = ""
    entry: str = ""                        # ملف python نسبي داخل الإضافة
    permissions: List[str] = field(default_factory=list)
    engine_min: str = ""                   # أدنى إصدارHunterAI مدعوم (اختياري)
    author: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


class ManifestError(ValueError):
    """مانيفست غير صالح — تُرفض الإضافة."""


_REQUIRED = ("name", "version", "entry")
_NAME_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")
_VERSION_RE = __import__("re").compile(r"^\d+\.\d+\.\d+$")


def load_manifest(plugin_dir: str | Path) -> ExtensionManifest:
    """قراءة plugin.json من مجلد إضافة."""
    p = Path(plugin_dir) / "plugin.json"
    if not p.exists():
        raise ManifestError(f"plugin.json غير موجود في {plugin_dir}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ManifestError(f"plugin.json غير JSON صالح: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("plugin.json يجب أن يكون كائن JSON")
    return validate_manifest(data)


def validate_manifest(data: Dict[str, Any]) -> ExtensionManifest:
    """تحقق صارم من مانيفست — يرمي ManifestError عند أي مشكلة."""
    missing = [k for k in _REQUIRED if not data.get(k)]
    if missing:
        raise ManifestError(f"حقول مطلوبة ناقصة: {missing}")

    name = str(data["name"]).strip()
    if not _NAME_RE.match(name):
        raise ManifestError(
            f"اسم الإضافة غير صالح: {name!r} (أحرف صغيرة وأرقام و-/_ فقط)")

    version = str(data["version"]).strip()
    if not _VERSION_RE.match(version):
        raise ManifestError(f"إصدار غير صالح (يجب X.Y.Z): {version!r}")

    entry = str(data["entry"]).strip()
    if not entry.endswith(".py"):
        raise ManifestError(f"entry يجب أن يشير لملف .py: {entry!r}")
    # منع traversal
    if ".." in entry or entry.startswith(("/", "\\")):
        raise ManifestError(f"entry غير آمن: {entry!r}")

    perms_raw = data.get("permissions") or []
    if not isinstance(perms_raw, list):
        raise ManifestError("permissions يجب أن يكون قائمة")
    perms: List[str] = []
    for perm in perms_raw:
        perm = str(perm).strip()
        if perm not in Permission.ALL:
            raise ManifestError(
                f"صلاحية غير معروفة: {perm!r} (المتاح: {list(Permission.ALL)})")
        perms.append(perm)

    return ExtensionManifest(
        name=name,
        version=version,
        display_name=str(data.get("display_name") or name),
        description=str(data.get("description") or ""),
        entry=entry,
        permissions=perms,
        engine_min=str(data.get("engine_min") or ""),
        author=str(data.get("author") or ""),
        raw=data,
    )
