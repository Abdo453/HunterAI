"""
Permission Matrix — مصفوفة الصلاحيات
=====================================

تحدد कौन يستطيع استخدام أي أداة، لأي عملية، في أي بيئة، وهل تحتاج موافقة مسبقة أم لا.

المبادئ:
- القراءة: مسموحة دائماً في نطاق المشروع.
- التعديل: مسموح في sandbox فقط.
- الحذف/النشر/تغيير الصلاحيات: تحتاج موافقة بشرية صريحة.
- أي عملية خارج النطاق: تُرفض برسالة واضحة تشرح السبب وما المطلوب لتجاوزها.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ToolOp(str, Enum):
    """العمليات المدعومة لكل أداة."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    MODIFY = "modify"
    NETWORK = "network"
    INSTALL = "install"
    CONFIGURE = "configure"


class EnvScope(str, Enum):
    """نطاق البيئة المسموح العمل فيها."""
    LOCAL = "local"          # localhost فقط
    SANDBOX = "sandbox"      # بيئة معزولة
    AUTHORIZED_TARGET = "authorized_target"  # هدف مصرح به كتابياً
    ANY = "any"              # أي بيئة (خطرة، تتطلب موافقة)


class UserRole(str, Enum):
    """أدوار المستخدمين."""
    GUEST = "guest"
    AUTHORIZED_RESEARCHER = "authorized_researcher"
    ADMIN = "admin"


@dataclass
class PermissionDecision:
    """قرار الصلاحية لطلب واحد."""
    allowed: bool
    tool: str
    operation: ToolOp
    env: EnvScope
    user: UserRole
    requires_approval: bool = False
    reason: str = ""
    pre_approval_id: Optional[str] = None
    message: str = ""  # رسالة واضحة للمستخدم


@dataclass
class ToolRule:
    """قاعدة أداة واحدة في المصفوفة."""
    tool: str
    allowed_ops: Set[ToolOp]
    allowed_envs: Set[EnvScope]
    allowed_users: Set[UserRole]
    requires_approval_for: Set[ToolOp] = field(default_factory=set)
    description: str = ""

    def allows(self, op: ToolOp, env: EnvScope, user: UserRole) -> bool:
        return (
            op in self.allowed_ops
            and env in self.allowed_envs
            and user in self.allowed_users
        )


class PermissionMatrix:
    """
    مصفوفة الصلاحيات الرئيسية.
    تُمكّن من تعريف ما هو مسموح وما هو ممنوع، وما يحتاج موافقة.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, ToolRule] = {}
        self._denied_tools: Set[str] = set()
        self._global_denied_ops: Set[ToolOp] = set()
        self._setup_default_rules()

    # ------------------------------------------------------------------ #
    # الإعداد الافتراضي للقواعد (لوكيل تجاوز WAF)
    # ------------------------------------------------------------------ #
    def _setup_default_rules(self) -> None:
        # أدوات reconnaissance ووصف WAF — مسموحة للقراءة والبصمة في الأهداف المصرح بها
        self.add_rule(ToolRule(
            tool="wafw00f",
            allowed_ops={ToolOp.READ, ToolOp.EXECUTE, ToolOp.NETWORK},
            allowed_envs={EnvScope.LOCAL, EnvScope.AUTHORIZED_TARGET},
            allowed_users={UserRole.AUTHORIZED_RESEARCHER, UserRole.ADMIN},
            requires_approval_for=set(),
            description="بصمة WAF على الهدف",
        ))

        # أداة wafryt — تحتاج موافقة للتنفيذ على أهداف حقيقية
        self.add_rule(ToolRule(
            tool="wafryt",
            allowed_ops={ToolOp.READ, ToolOp.EXECUTE, ToolOp.NETWORK},
            allowed_envs={EnvScope.LOCAL, EnvScope.SANDBOX, EnvScope.AUTHORIZED_TARGET},
            allowed_users={UserRole.AUTHORIZED_RESEARCHER, UserRole.ADMIN},
            requires_approval_for={ToolOp.EXECUTE, ToolOp.NETWORK},
            description="محرك طفرة WAF (تجاوز)",
        ))

        # السلم البرمجي للتجاوز — يحتاج موافقة للتنفيذ على الشبكة
        self.add_rule(ToolRule(
            tool="waf_bypass_ladder",
            allowed_ops={ToolOp.READ, ToolOp.EXECUTE, ToolOp.NETWORK},
            allowed_envs={EnvScope.LOCAL, EnvScope.SANDBOX, EnvScope.AUTHORIZED_TARGET},
            allowed_users={UserRole.AUTHORIZED_RESEARCHER, UserRole.ADMIN},
            requires_approval_for={ToolOp.EXECUTE, ToolOp.NETWORK},
            description="سلم تجاوز WAF التدريجي",
        ))

        # طلبات HTTP عبر httpx — تحتاج موافقة للهدف الحقيقي
        self.add_rule(ToolRule(
            tool="httpx",
            allowed_ops={ToolOp.READ, ToolOp.NETWORK},
            allowed_envs={EnvScope.LOCAL, EnvScope.SANDBOX, EnvScope.AUTHORIZED_TARGET},
            allowed_users={UserRole.AUTHORIZED_RESEARCHER, UserRole.ADMIN},
            requires_approval_for={ToolOp.NETWORK},
            description="طلبات HTTP للاختبار",
        ))

        # بنك الجينات — قراءة وكتابة محلية فقط
        self.add_rule(ToolRule(
            tool="waf_gene_bank",
            allowed_ops={ToolOp.READ, ToolOp.WRITE},
            allowed_envs={EnvScope.LOCAL},
            allowed_users={UserRole.AUTHORIZED_RESEARCHER, UserRole.ADMIN},
            requires_approval_for=set(),
            description="تخزين نجاح/فشل محاولات التجاوز",
        ))

        # محسن RL — قراءة وكتابة محلية فقط
        self.add_rule(ToolRule(
            tool="rl_policy_optimizer",
            allowed_ops={ToolOp.READ, ToolOp.WRITE, ToolOp.EXECUTE},
            allowed_envs={EnvScope.LOCAL},
            allowed_users={UserRole.AUTHORIZED_RESEARCHER, UserRole.ADMIN},
            requires_approval_for=set(),
            description="تحسين سياسة التعلم المعزز",
        ))

        # نظام الملفات — قراءة فقط للمجلدات المسموحة،禁止 التعديل المباشر
        self.add_rule(ToolRule(
            tool="file_system",
            allowed_ops={ToolOp.READ},
            allowed_envs={EnvScope.LOCAL, EnvScope.SANDBOX},
            allowed_users={UserRole.AUTHORIZED_RESEARCHER, UserRole.ADMIN},
            requires_approval_for=set(),
            description="قراءة ملفات المشروع والبيانات",
        ))

        #禁止pletely: الحذف، التثبيت، تغيير الصلاحيات، النشر
        self._denied_tools.update({
            "rm", "del", "format", "fdisk", "mkfs",
        })
        self._global_denied_ops.update({
            ToolOp.DELETE,
            ToolOp.INSTALL,
        })

    # ------------------------------------------------------------------ #
    # واجهة عامة
    # ------------------------------------------------------------------ #
    def add_rule(self, rule: ToolRule) -> None:
        self._rules[rule.tool] = rule

    def remove_rule(self, tool: str) -> None:
        self._rules.pop(tool, None)

    def deny_tool(self, tool: str) -> None:
        self._denied_tools.add(tool)

    def allow_tool(self, tool: str) -> None:
        self._denied_tools.discard(tool)

    def evaluate(
        self,
        tool: str,
        operation: ToolOp,
        env: EnvScope,
        user: UserRole,
        pre_approval_id: Optional[str] = None,
    ) -> PermissionDecision:
        """
        يقرر ما إذا كان الطلب مسموحاً أم لا، وهل يحتاج موافقة.
        """
        # 1. إذا كانت الأداة محظورة تماماً
        if tool in self._denied_tools:
            return PermissionDecision(
                allowed=False,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                requires_approval=False,
                reason=f"الأداة '{tool}' محظورة تماماً في النظام",
                message=(
                    f"❌ الأداة '{tool}' غير مسموحة في أي حالة. "
                    f"إذا كنت بحاجة إليها، راجع responsable الأمن لتفعيلها."
                ),
            )

        # 2. إذا كانت العملية محظورة عالمياً
        if operation in self._global_denied_ops:
            return PermissionDecision(
                allowed=False,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                requires_approval=False,
                reason=f"العملية '{operation.value}' محظورة عالمياً",
                message=(
                    f"❌ العملية '{operation.value}' محظورة على جميع الأدوات. "
                    f"هذه العملية تشكل خطراً أمنياً ولا يمكن تجاوزها."
                ),
            )

        # 3. إذا لم تكن هناك قاعدة للأداة
        rule = self._rules.get(tool)
        if rule is None:
            return PermissionDecision(
                allowed=False,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                requires_approval=False,
                reason=f"الأداة '{tool}' غير معرفة في مصفوفة الصلاحيات",
                message=(
                    f"⚠️ الأداة '{tool}' غير معروفة للنظام. "
                    f"أضفها إلى مصفوفة الصلاحيات أولاً أو راجع responsible الأمن."
                ),
            )

        # 4. إذا كانت العملية/البيئة/المستخدم غير مسموحين لهذه الأداة
        if not rule.allows(operation, env, user):
            return PermissionDecision(
                allowed=False,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                requires_approval=False,
                reason=(
                    f"الأداة '{tool}' لا تدعم العملية '{operation.value}' "
                    f"في البيئة '{env.value}' للمستخدم '{user.value}'"
                ),
                message=(
                    f"❌ العملية '{operation.value}' على '{tool}' غير مسموحة "
                    f"في البيئة '{env.value}' لدورك '{user.value}'. "
                    f"المسموح: {', '.join(o.value for o in rule.allowed_ops)} "
                    f"في البيئات: {', '.join(e.value for e in rule.allowed_envs)}"
                ),
            )

        # 5. إذا كانت العملية تحتاج موافقة ولم تكن هناك موافقة مسبقة سارية
        if operation in rule.requires_approval_for and not pre_approval_id:
            return PermissionDecision(
                allowed=False,
                tool=tool,
                operation=operation,
                env=env,
                user=user,
                requires_approval=True,
                reason=(
                    f"العملية '{operation.value}' على '{tool}' تحتاج موافقة مسبقة"
                ),
                message=(
                    f"⚠️ العملية '{operation.value}' على '{tool}' في البيئة '{env.value}' "
                    f"تحتاج موافقة بشرية قبل التنفيذ. "
                    f"يمكنك طلب الموافقة أو استخدام 'pre_approval' لنطاق محدود."
                ),
                pre_approval_id=None,
            )

        # 6. كل شيء جيد — مسموح
        return PermissionDecision(
            allowed=True,
            tool=tool,
            operation=operation,
            env=env,
            user=user,
            requires_approval=False,
            reason="العملية داخل نطاق الصلاحيات المصرح بها",
            message=(
                f"✅ العملية '{operation.value}' على '{tool}' مسموحة في البيئة '{env.value}'."
            ),
            pre_approval_id=pre_approval_id,
        )


__all__ = ["PermissionMatrix", "PermissionDecision", "ToolOp", "EnvScope", "UserRole", "ToolRule"]
