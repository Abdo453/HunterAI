"""
Pre-Approval Manager — إدارة الموافقة المسبقة
=============================================

يتيح给某些 النطاقات موافقة مسبقة لفترة محددة، بحيث لا يحتاج الإيجنت
لطلب موافقة في كل مرة ينفذ فيها عملية متكررة ضمن هذا النطاق.

مثال:
- "مسموح تعديل ملفات مجلد X لمدة الجلسة الحالية"
- "مسموح إرسال طلبات HTTP للهدف Y لمدة ساعة"
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .permission_matrix import EnvScope, ToolOp, UserRole


@dataclass
class PreApproval:
    """موافقة مسبقة على نطاق معين."""
    id: str
    tool: str
    operation: ToolOp
    env: EnvScope
    user: UserRole
    target: Optional[str] = None  # الهدف المحدد (مثال: http://localhost:8080)
    granted_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None  # None = لا تنتهي
    max_uses: Optional[int] = None  # عدد الاستخدامات القصوى
    used_count: int = 0
    description: str = ""

    def is_valid(
        self,
        tool: str,
        operation: ToolOp,
        env: EnvScope,
        user: UserRole,
    ) -> bool:
        """يتحقق من أن الموافقة لا تزال سارية لهذا الطلب."""
        # تحقق من الصلاحية الأساسية
        if self.tool != tool:
            return False
        if self.operation != operation:
            return False
        if self.env != env:
            return False
        if self.user != user:
            return False

        # تحقق من انتهاء الصلاحية الزمنية
        if self.expires_at is not None and time.time() > self.expires_at:
            return False

        # تحقق من عدد الاستخدامات
        if self.max_uses is not None and self.used_count >= self.max_uses:
            return False

        return True

    def use(self) -> None:
        """يُحسب استخدام واحد للموافقة."""
        self.used_count += 1

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "tool": self.tool,
            "operation": self.operation.value,
            "env": self.env.value,
            "user": self.user.value,
            "target": self.target,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "max_uses": self.max_uses,
            "used_count": self.used_count,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PreApproval":
        return cls(
            id=data["id"],
            tool=data["tool"],
            operation=ToolOp(data["operation"]),
            env=EnvScope(data["env"]),
            user=UserRole(data["user"]),
            target=data.get("target"),
            granted_at=data.get("granted_at", time.time()),
            expires_at=data.get("expires_at"),
            max_uses=data.get("max_uses"),
            used_count=data.get("used_count", 0),
            description=data.get("description", ""),
        )


class PreApprovalManager:
    """
    يدير所有 الموافقات المسبقة.
    يمكن حفظها وتحميلها من ملف JSON للاستمرار بين الجلسات.
    """

    def __init__(self, storage_file: Optional[str] = None):
        self.storage_file = Path(storage_file) if storage_file else None
        self._approvals: Dict[str, PreApproval] = {}
        self._counter = 0
        self._load()

    # ------------------------------------------------------------------ #
    # الإدارة الداخلية
    # ------------------------------------------------------------------ #
    def _load(self) -> None:
        if self.storage_file and self.storage_file.is_file():
            try:
                data = json.loads(self.storage_file.read_text(encoding="utf-8"))
                for item in data:
                    approval = PreApproval.from_dict(item)
                    self._approvals[approval.id] = approval
                    self._counter = max(self._counter, int(approval.id.split("_")[-1]) if "_" in approval.id else 0)
            except Exception:
                pass

    def _save(self) -> None:
        if self.storage_file:
            self.storage_file.parent.mkdir(parents=True, exist_ok=True)
            self.storage_file.write_text(
                json.dumps([a.to_dict() for a in self._approvals.values()], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

    def _next_id(self) -> str:
        self._counter += 1
        return f"pre_approval_{self._counter}"

    # ------------------------------------------------------------------ #
    # واجهة عامة
    # ------------------------------------------------------------------ #
    def grant(
        self,
        tool: str,
        operation: ToolOp,
        env: EnvScope,
        user: UserRole,
        target: Optional[str] = None,
        duration_seconds: Optional[int] = None,
        max_uses: Optional[int] = None,
        description: str = "",
    ) -> str:
        """
        يمنح موافقة مسبقة على نطاق معين ويعيد معرف الموافقة.
        """
        expires_at = None
        if duration_seconds is not None:
            expires_at = time.time() + duration_seconds

        approval = PreApproval(
            id=self._next_id(),
            tool=tool,
            operation=operation,
            env=env,
            user=user,
            target=target,
            expires_at=expires_at,
            max_uses=max_uses,
            description=description,
        )
        self._approvals[approval.id] = approval
        self._save()
        return approval.id

    def revoke(self, approval_id: str) -> bool:
        """يلغي موافقة مسبقة."""
        if approval_id in self._approvals:
            del self._approvals[approval_id]
            self._save()
            return True
        return False

    def is_valid(
        self,
        approval_id: str,
        tool: str,
        operation: ToolOp,
        env: EnvScope,
        user: UserRole,
    ) -> bool:
        """يتحقق من أن الموافقة سارية لهذا الطلب."""
        approval = self._approvals.get(approval_id)
        if approval is None:
            return False
        if not approval.is_valid(tool, operation, env, user):
            return False
        # يتم حساب الاستخدام عند التحقق من الصحة
        approval.use()
        self._save()
        return True

    def get_active(self, tool: Optional[str] = None) -> List[PreApproval]:
        """يعيد جميع الموافقات النشطة (ولawy منتهية أو منتهية الاستخدام)."""
        now = time.time()
        active = []
        for approval in self._approvals.values():
            if tool is not None and approval.tool != tool:
                continue
            if approval.expires_at is not None and now > approval.expires_at:
                continue
            if approval.max_uses is not None and approval.used_count >= approval.max_uses:
                continue
            active.append(approval)
        return active

    def summary(self) -> dict:
        active = len(self.get_active())
        total = len(self._approvals)
        return {
            "total_approvals": total,
            "active_approvals": active,
            "expired_or_used": total - active,
        }


__all__ = ["PreApproval", "PreApprovalManager"]
