"""
Policy Engine — محرك السياسات
===============================

يجمع بين Permission Matrix و Pre-Approval Manager لاتخاذ قرار نهائي
لكل طلب تشغيل أداة.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .permission_matrix import (
    EnvScope,
    PermissionDecision,
    PermissionMatrix,
    ToolOp,
    UserRole,
)
from .pre_approval import PreApprovalManager


@dataclass
class PolicyResult:
    """نتيجة تقييم السياسة لطلب واحد."""
    allowed: bool
    tool: str
    operation: ToolOp
    env: EnvScope
    user: UserRole
    decision: PermissionDecision
    pre_approval_used: Optional[str] = None
    message: str = ""
    requires_human_approval: bool = False


class PolicyEngine:
    """
    motore السياسات المركزي.
    يتم استدعاؤه قبل أي عملية أداة لتحديد ما إذا كانت مسموحة أم لا.
    """

    def __init__(
        self,
        matrix: Optional[PermissionMatrix] = None,
        pre_approval: Optional[PreApprovalManager] = None,
        default_user: UserRole = UserRole.AUTHORIZED_RESEARCHER,
        default_env: EnvScope = EnvScope.LOCAL,
    ):
        self.matrix = matrix or PermissionMatrix()
        self.pre_approval = pre_approval or PreApprovalManager()
        self.default_user = default_user
        self.default_env = default_env
        self._evaluation_log: List[PolicyResult] = []

    # ------------------------------------------------------------------ #
    # التقييم الرئيسي
    # ------------------------------------------------------------------ #
    def evaluate(
        self,
        tool: str,
        operation: ToolOp,
        env: Optional[EnvScope] = None,
        user: Optional[UserRole] = None,
        pre_approval_id: Optional[str] = None,
        context: Optional[dict] = None,
    ) -> PolicyResult:
        """
        يقيّم طلب تشغيل أداة ويقرر ما إذا كان مسموحاً أم لا.

        المعلمات:
            tool: اسم الأداة.
            operation: العملية المطلوبة.
            env: البيئة (يفتراضي LOCAL).
            user: المستخدم (يفتراضي AUTHORIZED_RESEARCHER).
            pre_approval_id: معرف الموافقة المسبقة إن وجد.
            context: سياق إضافي للتسجيل (الهدف، الباراميترات، إلخ).

        يرجع: PolicyResult تحتوي على القرار والرسالة الواضحة.
        """
        env = env or self.default_env
        user = user or self.default_user

        # إذا كان هناك pre_approval_id، نتأكد من أنه ساري ويعطي صلاحية لهذه العملية
        effective_pre_approval = pre_approval_id
        if pre_approval_id and not self.pre_approval.is_valid(
            pre_approval_id, tool, operation, env, user
        ):
            effective_pre_approval = None
            # لا نرفض تلقائياً، لكننا نلغي الموافقة لأنها غير سارية

        # تقييم المصفوفة
        decision = self.matrix.evaluate(
            tool=tool,
            operation=operation,
            env=env,
            user=user,
            pre_approval_id=effective_pre_approval,
        )

        # بناء النتيجة
        result = PolicyResult(
            allowed=decision.allowed,
            tool=tool,
            operation=operation,
            env=env,
            user=user,
            decision=decision,
            pre_approval_used=effective_pre_approval,
            message=decision.message,
            requires_human_approval=decision.requires_approval,
        )

        # تسجيل التقييم للمراجعة اللاحقة
        self._evaluation_log.append(result)

        return result

    # ------------------------------------------------------------------ #
    # مساعدات سريعة
    # ------------------------------------------------------------------ #
    def is_allowed(
        self,
        tool: str,
        operation: ToolOp,
        env: Optional[EnvScope] = None,
        user: Optional[UserRole] = None,
        pre_approval_id: Optional[str] = None,
    ) -> bool:
        """يعيد True إذا كان الطلب مسموحاً، False خلاف ذلك."""
        return self.evaluate(
            tool, operation, env, user, pre_approval_id
        ).allowed

    def get_log(self) -> List[PolicyResult]:
        """يعيد سجل جميع التقييمات التي تم إجراؤها."""
        return list(self._evaluation_log)

    def clear_log(self) -> None:
        self._evaluation_log.clear()

    def summary(self) -> dict:
        total = len(self._evaluation_log)
        allowed = sum(1 for r in self._evaluation_log if r.allowed)
        denied = total - allowed
        needs_approval = sum(1 for r in self._evaluation_log if r.requires_human_approval)
        return {
            "total_evaluations": total,
            "allowed": allowed,
            "denied": denied,
            "needs_approval": needs_approval,
        }


__all__ = ["PolicyEngine", "PolicyResult"]
