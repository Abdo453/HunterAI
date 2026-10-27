"""
Deterministic Verification Filter — طبقة التحقق والسلامة (Layer 5)
===================================================================
قبل أي أمر "هجومي" (استغلال، رفع صلاحيات، تعديل)، يجب أن يجتاز فلتر التحقق الحتمي
الذي يؤكد:
1. الهدف داخل النطاق المسموح (in-scope).
2. الأمر لن يسبب تدميرًا أو حجب خدمة (DoS).
3. الأمر متوافق مع حالة البيئة الحالية (لن يفشل حتمًا).
"""

from core.verification.deterministic_filter import (
    DeterministicFilter,
    VerificationResult,
    VerificationVerdict,
)

__all__ = [
    "DeterministicFilter",
    "VerificationResult",
    "VerificationVerdict",
]
