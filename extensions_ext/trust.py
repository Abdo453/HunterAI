"""تقييم ثقة الإضافات — يُشطب قبل التفعيل (fail-closed).

يقيّم: مصدر الإضافة (محلية/مستوردة)، هل طلبت صلاحيات عالية الخطورة،
وهل المانيفست سليم. النتيجة مستوى ثقة يُقارن بحد أدنى قبل التفعيل.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List

from extensions_ext.manifest import ExtensionManifest, Permission


class TrustLevel(str, Enum):
    NONE = "none"          # لا تثق — لا تُفعَّل
    LOW = "low"            # مانيفست سليم بلا صلاحيات عالية
    MEDIUM = "medium"      # صلاحيات متوسطة مع مسارات آمنة
    HIGH = "high"          # مصدر محلي موثوق بلا صلاحيات خطرة

    def rank(self) -> int:
        return {"none": 0, "low": 1, "medium": 2, "high": 3}[self.value]


@dataclass
class TrustReport:
    level: TrustLevel
    reasons: List[str] = field(default_factory=list)
    sha256: str = ""
    high_risk_perms: List[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.level != TrustLevel.NONE


def _hash_dir(path: Path) -> str:
    """بصمة لكل محتوى المجلد (لرصد التلاعب بعد التثبيت)."""
    h = hashlib.sha256()
    for f in sorted(path.rglob("*")):
        if f.is_file():
            h.update(str(f.relative_to(path)).encode())
            h.update(f.read_bytes())
    return h.hexdigest()


def assess_trust(
    manifest: ExtensionManifest,
    ext_dir: str | Path,
    *,
    is_local: bool = True,
    min_level: TrustLevel = TrustLevel.LOW,
) -> TrustReport:
    """تقييم ثقة إضافة. يُستخدم قبل activate_extension."""
    ext_dir = Path(ext_dir)
    reasons: List[str] = []
    high_risk = [p for p in manifest.permissions if p in Permission.HIGH_RISK]

    digest = ""
    try:
        digest = _hash_dir(ext_dir)
    except OSError as exc:
        return TrustReport(
            level=TrustLevel.NONE,
            reasons=[f"تعذّرت قراءة مجلد الإضافة: {exc}"])

    if not (ext_dir / manifest.entry).exists():
        return TrustReport(
            level=TrustLevel.NONE,
            reasons=[f"ملف entry غير موجود: {manifest.entry}"],
            sha256=digest)

    level = TrustLevel.HIGH
    if high_risk:
        level = TrustLevel.MEDIUM
        reasons.append(f"صلاحيات عالية الخطورة: {high_risk}")
    if not is_local:
        # إضافة مستوردة تنزل درجة تلقائيًا
        if level == TrustLevel.HIGH:
            level = TrustLevel.MEDIUM
        reasons.append("مصدر غير محلي (مستورد)")
    if Permission.READ_ENV in manifest.permissions:
        level = TrustLevel.LOW
        reasons.append("تطلب قراءة متغيرات البيئة (حساس)")

    if level.rank() < min_level.rank():
        reasons.append(f"الثقة {level.value} أقل من الحد الأدنى {min_level.value}")
        level = TrustLevel.NONE   # fail-closed: أقل من الحد الأدنى ⇒ لا تُفعَّل

    return TrustReport(
        level=level, reasons=reasons, sha256=digest,
        high_risk_perms=high_risk)
