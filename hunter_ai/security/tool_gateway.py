"""
Tool Gateway — بوابة الأدوات
=============================

جميع استدعاءات الأدوات تمر عبر هذه البوابة الواحدة، حيث:
- يتم التحقق من الصلاحية عبر Policy Engine.
- يتم تسجيل كل عملية (logs).
- يتم تطبيق rate limits.
- يتم طلب موافقة للحساسة.
- تُرجع نتيجة واضحة تشمل قرار السياسة ومبرراته.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .permission_matrix import EnvScope, PermissionDecision, ToolOp, UserRole
from .policy_engine import PolicyEngine, PolicyResult
from .pre_approval import PreApprovalManager


@dataclass
class GatewayResult:
    """نتيجة مرور استدعاء عبر البوابة."""
    allowed: bool
    tool: str
    operation: ToolOp
    env: EnvScope
    user: UserRole
    policy_result: PolicyResult
    execution_result: Optional[Any] = None
    error: Optional[str] = None
    duration_ms: float = 0.0
    rate_limited: bool = False
    message: str = ""


class ToolGateway:
    """
    بوابة مركزية لكل استدعاءات الأدوات.
    لا يمكن استدعاء أي أداة مباشرة بدون المرور من هنا (في الإنتاج).
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        rate_limit_per_minute: int = 60,
        max_concurrent: int = 10,
    ):
        self.policy = policy_engine or PolicyEngine()
        self.rate_limit_per_minute = rate_limit_per_minute
        self.max_concurrent = max_concurrent

        # تتبع المعدل: tool -> list of timestamps
        self._call_timestamps: Dict[str, List[float]] = {}
        self._active_calls: Dict[str, int] = {}
        self._lock = asyncio.Lock()

        # سجل العمليات
        self._execution_log: List[GatewayResult] = []

    # ------------------------------------------------------------------ #
    # معدل المكالمات
    # ------------------------------------------------------------------ #
    def _is_rate_limited(self, tool: str) -> bool:
        now = time.time()
        window_start = now - 60.0  # نافذة دقيقة واحدة
        timestamps = self._call_timestamps.get(tool, [])
        # إزالة التايمستامب القديمة
        recent = [t for t in timestamps if t > window_start]
        self._call_timestamps[tool] = recent
        return len(recent) >= self.rate_limit_per_minute

    def _record_call(self, tool: str) -> None:
        now = time.time()
        self._call_timestamps.setdefault(tool, []).append(now)

    # ------------------------------------------------------------------ #
    # التنفيذ عبر البوابة
    # ------------------------------------------------------------------ #
    async def execute(
        self,
        tool: str,
        operation: ToolOp,
        func: Callable,
        env: EnvScope = EnvScope.LOCAL,
        user: UserRole = UserRole.AUTHORIZED_RESEARCHER,
        pre_approval_id: Optional[str] = None,
        *args,
        **kwargs,
    ) -> GatewayResult:
        """
        ينفذ استدعاء أداة عبر البوابة.

        التدفق:
        1. فحص rate limit.
        2. تقييم السياسة (Policy Engine).
        3. إذا المرفوض → إرجاع رسالة واضحة.
        4. إذا يحتاج موافقة ولم تُقدَّم → إرجاع طلب موافقة.
        5. إذا مسموح → تنفيذ الدالة الفعلية وتسجيل النتيجة.
        """
        start = time.time()

        # 1. Rate limit
        if self._is_rate_limited(tool):
            return GatewayResult(
                allowed=False,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                policy_result=PolicyResult(
                    allowed=False,
                    tool=tool,
                    operation=operation,
                    env=env,
                    user=user,
                    decision=self.policy.matrix.evaluate(tool, operation, env, user),
                    message=(
                        f"⏱️ تم تجاوز الحد المسموح من المكالمات ({self.rate_limit_per_minute} في الدقيقة) "
                        f"لأداة '{tool}'. يرجى المحاولة لاحقاً."
                    ),
                    requires_human_approval=False,
                ),
                rate_limited=True,
                message="تم تجاوز الحد المسموح من المكالمات",
            )

        # 2. تقييم السياسة
        policy_result = self.policy.evaluate(
            tool=tool,
            operation=operation,
            env=env,
            user=user,
            pre_approval_id=pre_approval_id,
        )

        # 3. إذا المرفوض ولا يحتاج موافقة
        if not policy_result.allowed and not policy_result.requires_human_approval:
            duration = (time.time() - start) * 1000
            result = GatewayResult(
                allowed=False,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                policy_result=policy_result,
                duration_ms=duration,
                message=policy_result.message,
            )
            self._execution_log.append(result)
            return result

        # 4. إذا يحتاج موافقة ولم تُقدَّم موافقة سارية
        if policy_result.requires_human_approval and not policy_result.pre_approval_used:
            duration = (time.time() - start) * 1000
            result = GatewayResult(
                allowed=False,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                policy_result=policy_result,
                duration_ms=duration,
                message=(
                    f"{policy_result.message}\n"
                    f"💡 يمكنك طلب موافقة مسبقة عبر 'grant_pre_approval' "
                    f"أو استخدام أي أداة ضمن نطاق مصرح به بالفعل."
                ),
            )
            self._execution_log.append(result)
            return result

        # 5. تنفيذ الدالة الفعلية
        self._record_call(tool)
        self._active_calls[tool] = self._active_calls.get(tool, 0) + 1
        try:
            # إذا كانت الدالة كوروتيين (async)، ننتظرها
            if asyncio.iscoroutinefunction(func):
                exec_result = await func(*args, **kwargs)
            else:
                exec_result = func(*args, **kwargs)

            duration = (time.time() - start) * 1000
            result = GatewayResult(
                allowed=True,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                policy_result=policy_result,
                execution_result=exec_result,
                duration_ms=duration,
                message=f"✅ تم تنفيذ '{tool}.{operation.value}' بنجاح",
            )
        except Exception as exc:
            duration = (time.time() - start) * 1000
            result = GatewayResult(
                allowed=True,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                policy_result=policy_result,
                execution_result=None,
                error=str(exc),
                duration_ms=duration,
                message=f"⚠️ فشل تنفيذ '{tool}.{operation.value}': {exc}",
            )
        finally:
            self._active_calls[tool] = max(0, self._active_calls.get(tool, 0) - 1)

        self._execution_log.append(result)
        return result

    # ------------------------------------------------------------------ #
    # استعلامات وسجلات
    # ------------------------------------------------------------------ #
    def get_log(self) -> List[GatewayResult]:
        return list(self._execution_log)

    def clear_log(self) -> None:
        self._execution_log.clear()

    def summary(self) -> dict:
        total = len(self._execution_log)
        allowed = sum(1 for r in self._execution_log if r.allowed)
        denied = total - allowed
        rate_limited = sum(1 for r in self._execution_log if r.rate_limited)
        return {
            "total_calls": total,
            "allowed": allowed,
            "denied": denied,
            "rate_limited": rate_limited,
            "policy_summary": self.policy.summary(),
            "pre_approval_summary": self.policy.pre_approval.summary(),
        }


__all__ = ["ToolGateway", "GatewayResult"]
