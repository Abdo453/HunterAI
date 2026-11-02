"""
Verifier — مدقق النتائج
========================

يراجع مخرجات الأدوات قبل تسليمها للمستخدم، للتأكد من:
- عدم تسريب بيانات حساسة.
- أن النتيجة تتوافق مع ما تم طلبه.
- أن العملية لم تتجاوز النطاق المصرح به.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class VerificationResult:
    """نتيجة التحقق من مخرجات أداة."""
    verified: bool
    data: Any
    warnings: List[str] = field(default_factory=list)
    blocked_sections: List[str] = field(default_factory=list)
    reason: str = ""


class Verifier:
    """
    يتحقق من نتائج الأدوات قبل تسليمها.
    """

    def __init__(
        self,
        blocked_patterns: Optional[List[str]] = None,
        max_output_size: int = 512 * 1024,  # 512 كيلو بايت
    ):
        self.blocked_patterns = blocked_patterns or [
            r"(?i)api[_-]?key\s*[:=]\s*[^\s]+",
            r"(?i)secret[_-]?key\s*[:=]\s*[^\s]+",
            r"(?i)password\s*[:=]\s*[^\s]+",
            r"(?i)token\s*[:=]\s*[^\s]+",
            r"(?i)private[_-]?key\s*[:=]\s*[^\s]+",
            r"(?i)stripe[_-]?sk[_]?",
            r"(?i)aws[_-]?secret[_-]?access[_-]?key",
        ]
        self.max_output_size = max_output_size

    def verify(
        self,
        data: Any,
        context: Optional[dict] = None,
    ) -> VerificationResult:
        """
        يتحقق من البيانات ويعيد نتيجة التحقق.
        """
        warnings: List[str] = []
        blocked: List[str] = []

        # 1. تحويل البيانات إلى نص للفحص
        text_data = ""
        if isinstance(data, str):
            text_data = data
        elif isinstance(data, (dict, list)):
            import json
            text_data = json.dumps(data, ensure_ascii=False)
        elif data is not None:
            text_data = str(data)

        # 2. فحص حجم المخرجات
        if len(text_data) > self.max_output_size:
            blocked.append(f"حجم المخرجات يتجاوز الحد المسموح ({self.max_output_size} بايت)")
            text_data = text_data[: self.max_output_size] + "\n... (تم裁اق المخرجات)"

        # 3. فحص الأنماط المحظورة (التسريبات)
        for pattern in self.blocked_patterns:
            matches = re.findall(pattern, text_data)
            if matches:
                blocked.append(
                    f"تم اكتشاف نمط محتمل لتسريب بيانات حساسة: {pattern}"
                )
                # إخفاء التطابقات
                text_data = re.sub(pattern, "[REDACTED]", text_data)

        # 4. التحقق من السياق إذا fournish
        if context:
            target = context.get("target", "")
            if target and "localhost" not in target and "127.0.0.1" not in target:
                warnings.append(
                    f"الهدف '{target}' ليس محلياً — تأكد من أن لديك إذن كتابي للاختبار عليه"
                )

        verified = len(blocked) == 0

        # إعادة البيانات النظيفة
        clean_data = text_data if isinstance(data, str) else data
        if isinstance(data, str):
            clean_data = text_data

        return VerificationResult(
            verified=verified,
            data=clean_data,
            warnings=warnings,
            blocked_sections=blocked,
            reason="تم التحقق بنجاح" if verified else "تم حظر أجزاء من المخرجات لأسباب أمنية",
        )

    def verify_tool_result(
        self,
        tool_name: str,
        result: Any,
        target: Optional[str] = None,
    ) -> VerificationResult:
        """
        يتحقق من نتيجة أداة معينة مع سياق الهدف.
        """
        context = {"target": target} if target else None
        return self.verify(result, context=context)


__all__ = ["Verifier", "VerificationResult"]
