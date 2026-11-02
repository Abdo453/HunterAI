"""
UX Messages — رسائل تجربة المستخدم الواضحة
============================================

بدلاً من رسائل "غير مصرح" المبهمة، توفر هذه الوحدة رسائل واضحة تشرح:
- ماذا تم رفضه ولماذا.
- ما المطلوب لتجاوز الرفض (موافقة، توكن، تغيير النطاق).
- بدائل آمنة إن وجدت.
"""
from __future__ import annotations

from .permission_matrix import EnvScope, ToolOp, UserRole


class UXMessages:
    """
    يولّد رسائل واضحة ومفيدة للمستخدم بناءً على قرار السياسة.
    """

    @staticmethod
    def denial_message(tool: str, operation: ToolOp, env: EnvScope, user: UserRole, reason: str) -> str:
        """رسالة رفض قياسية مع توضيح السبب."""
        return (
            f"❌ **تم رفض الطلب**\n"
            f"   الأداة: `{tool}`\n"
            f"   العملية: `{operation.value}`\n"
            f"   البيئة: `{env.value}`\n"
            f"   الدور: `{user.value}`\n"
            f"   السبب: {reason}\n"
        )

    @staticmethod
    def needs_approval_message(tool: str, operation: ToolOp, env: EnvScope) -> str:
        """رسالة توضح أن العملية تحتاج موافقة بشرية."""
        return (
            f"⚠️ **الم processo يحتاج موافقة**\n"
            f"   الأداة: `{tool}`\n"
            f"   العملية: `{operation.value}`\n"
            f"   البيئة: `{env.value}`\n"
            f"   يمكنك طلب موافقة مسبقة باستخدام `grant_pre_approval` "
            f"للعمل ضمن نطاق محدود دون الحاجة للموافقة في كل مرة.\n"
        )

    @staticmethod
    def rate_limit_message(tool: str, limit: int, window: str = "دقيقة") -> str:
        """رسالة जब تم تجاوز الحد المسموح من المكالمات."""
        return (
            f"⏱️ **تم تجاوز الحد المسموح**\n"
            f"   الأداة: `{tool}`\n"
            f"   الحد: {limit} عملية في {window}\n"
            f"   يرجى الانتظار حتى انتهاء المدة والمحاولة مرة أخرى.\n"
        )

    @staticmethod
    def unknown_tool_message(tool: str) -> str:
        """رسالة عندما تكون الأداة غير معرفة."""
        return (
            f"⚠️ **أداة غير معروفة**\n"
            f"   الأداة: `{tool}`\n"
            f"   هذه الأداة غير معرفة في مصفوفة الصلاحيات. "
            f"أضفها إلى المصفوفة أولاً أو راجع مسؤول النظام.\n"
        )

    @staticmethod
    def pre_approval_granted_message(approval_id: str, tool: str, operation: ToolOp, env: EnvScope) -> str:
        """رسالة تأكيد عند منح موافقة مسبقة."""
        return (
            f"✅ **تم منح موافقة مسبقة**\n"
            f"   معرف الموافقة: `{approval_id}`\n"
            f"   الأداة: `{tool}`\n"
            f"   العملية: `{operation.value}`\n"
            f"   البيئة: `{env.value}`\n"
            f"   يمكنك الآن تنفيذ العملية ضمن هذا النطاق دون طلب موافقة في كل مرة.\n"
        )

    @staticmethod
    def sandbox_blocked_message(command: str, reason: str) -> str:
        """رسالة عندما يتم حظر أمر في البيئة المعزولة."""
        return (
            f"🚫 **تم حظر الأمر في البيئة المعزولة**\n"
            f"   الأمر: `{command}`\n"
            f"   السبب: {reason}\n"
            f"   البيئة المعزولة لا تسمح بهذا الأمر لأسباب أمنية.\n"
        )

    @staticmethod
    def verification_warning_message(warnings: list) -> str:
        """رسالة تحذير عند وجود تحذيرات في التحقق من النتيجة."""
        lines = ["⚠️ **تحذيرات في التحقق من النتيجة:**"]
        for w in warnings:
            lines.append(f"   - {w}")
        return "\n".join(lines)

    @staticmethod
    def success_message(tool: str, operation: ToolOp, env: EnvScope) -> str:
        """رسالة نجاح واضحة."""
        return (
            f"✅ **تم التنفيذ بنجاح**\n"
            f"   الأداة: `{tool}`\n"
            f"   العملية: `{operation.value}`\n"
            f"   البيئة: `{env.value}`\n"
        )


__all__ = ["UXMessages"]
