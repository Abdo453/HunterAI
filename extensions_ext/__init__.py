"""نظام إضافات HunterAI — Phase 6.

بنية:
- manifest.py    : قراءة/تحقق plugin.json (اسم، إصدار، صلاحيات، نقاط دخول)
- permissions.py : صلاحيات مقيّدة + فحص قبل التفعيل (fail-closed)
- trust.py       : تقييم ثقة (مصدر، hash، توقيع اختياري)
- loader.py      : تحميل وتفعيل إضافة في namespace معزول
- registry.py    : سجل الإضافات المثبّتة + تفعيل/تعطيل

كل إضافة مجلد فيه plugin.json + ملف python مُشار إليه.
"""
from extensions_ext.manifest import (
    ExtensionManifest, Permission, load_manifest, validate_manifest,
)
from extensions_ext.trust import TrustLevel, TrustReport, assess_trust
from extensions_ext.registry import (
    ExtensionRecord, ExtensionRegistry,
)
from extensions_ext.loader import (
    ExtensionError, activate_extension, deactivate_extension,
)

__all__ = [
    "ExtensionManifest", "Permission", "load_manifest", "validate_manifest",
    "TrustLevel", "TrustReport", "assess_trust",
    "ExtensionRecord", "ExtensionRegistry",
    "ExtensionError", "activate_extension", "deactivate_extension",
]
