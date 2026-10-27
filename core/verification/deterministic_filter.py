"""
فلتر التحقق الحتمي (Deterministic Verification Filter)
========================================================
قبل أي أمر "هجومي" (استغلال، رفع صلاحيات، تعديل)، يجب أن يجتاز هذا الفلتر
الذي يؤكد ثلاث شرائط حتمية:

1. الهدف داخل النطاق المسموح (in-scope) — باستخدام StrictScopeEngine إذا كان متاحاً.
2. الأمر不会 يسبب تدمير أو حجب خدمة (DoS) — استناداً إلى مستوى أمان الأمر.
3. الأمر متوافق مع حالة البيئة الحالية — باستخدام EnvironmentCompatibilityChecker.

إذا فشل أي شرط، يُرفض الأمر وتُعاد رسالة رفض واضحة مع السبب.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Any, Dict

from core.command_kb.models import CommandEntry, CommandSafetyLevel
from core.command_kb.compatibility import EnvironmentCompatibilityChecker, CompatibilityResult

log = logging.getLogger("core.verification.deterministic_filter")


class VerificationVerdict(str, Enum):
    """حكم التحقق."""
    APPROVED = "approved"         # الأمر مسموح به للتنفيذ
    REJECTED_OUT_OF_SCOPE = "rejected_out_of_scope"  # الهدف خارج النطاق
    REJECTED_DESTRUCTIVE = "rejected_destructive"    # الأمر مدمر/DoS محتمل
    REJECTED_INCOMPATIBLE = "rejected_incompatible"  # غير متوافق مع البيئة
    REJECTED_POLICY = "rejected_policy"              # انتهاك سياسة أخرى


@dataclass
class VerificationResult:
    """نتيجة التحقق من أمر."""
    verdict: VerificationVerdict
    command_id: str
    tool: str
    target: str
    reason: str
    safety_level: CommandSafetyLevel
    compatible: bool = False
    missing_requirements: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "command_id": self.command_id,
            "tool": self.tool,
            "target": self.target,
            "reason": self.reason,
            "safety_level": self.safety_level.value,
            "compatible": self.compatible,
            "missing_requirements": self.missing_requirements,
        }

    def is_approved(self) -> bool:
        return self.verdict == VerificationVerdict.APPROVED


class DeterministicFilter:
    """
    فلتر التحقق الحتمي قبل التنفيذ.
    يُستدعى من قبل Executor قبل تمرير أي أمر للتنفيذ الفعلي.
    """

    def __init__(
        self,
        scope_engine: Optional[Any] = None,
        compatibility_checker: Optional[EnvironmentCompatibilityChecker] = None,
        allowed_targets: Optional[List[str]] = None,
        allowed_networks: Optional[List[str]] = None,
        block_destructive_by_default: bool = True,
    ):
        """
        scope_engine: مثيل StrictScopeEngine إذا كان موجوداً في النظام.
        compatibility_checker: محقِّق توافق البيئة من EKG-CG.
        allowed_targets: قائمة الأهداف المسموح بها (نطاق يدوي).
        allowed_networks: الشبكات المسموحة (CIDR).
        block_destructive_by_default: حظر الأوامر المدمرة افتراضياً.
        """
        self.scope_engine = scope_engine
        self.compatibility_checker = compatibility_checker or EnvironmentCompatibilityChecker()
        self.allowed_targets = allowed_targets or []
        self.allowed_networks = allowed_networks or []
        self.block_destructive_by_default = block_destructive_by_default

        # أنماط الأوامر الخطيرة التي تُحظر تلقائياً (DoS, 파괴)
        self.destructive_patterns = [
            r"rm\s+-rf",
            r"dd\s+if=",
            r">\s*/dev/",
            r"mkfs",
            r"fdisk",
            r"shutdown",
            r"reboot",
            r"--dos",
            r"flood",
            r"slowloris",
            r"goldeneye",
            r"hulk",
            r"slowhttptest",
            r"xerxes",
            r"pyloris",
        ]

    # ------------------------------------------------------------------ #
    # الفحص الرئيسي
    # ------------------------------------------------------------------ #
    def verify(
        self,
        command: CommandEntry,
        target: str = "",
        rendered_command: Optional[str] = None,
    ) -> VerificationResult:
        """
        التحقق الحتمي من أمر قبل تنفيذه.
        ترجع VerificationResult مع الحكم والسبب.
        """
        rendered_command = rendered_command or command.command_template

        # ── الشرط 1: النطاق المسموح (In-Scope) ──
        scope_ok, scope_reason = self._check_scope(target)
        if not scope_ok:
            return VerificationResult(
                verdict=VerificationVerdict.REJECTED_OUT_OF_SCOPE,
                command_id=command.id,
                tool=command.tool,
                target=target,
                reason=scope_reason,
                safety_level=command.safety_level,
                compatible=False,
            )

        # ── الشرط 2: عدم التدمير / DoS ──
        destructive, destructive_reason = self._check_destructive(command, rendered_command)
        if destructive:
            return VerificationResult(
                verdict=VerificationVerdict.REJECTED_DESTRUCTIVE,
                command_id=command.id,
                tool=command.tool,
                target=target,
                reason=destructive_reason,
                safety_level=command.safety_level,
                compatible=False,
            )

        # ── الشرط 3: توافق البيئة ──
        if self.compatibility_checker:
            compat = self.compatibility_checker.check(command, target=target)
            if not compat.compatible:
                return VerificationResult(
                    verdict=VerificationVerdict.REJECTED_INCOMPATIBLE,
                    command_id=command.id,
                    tool=command.tool,
                    target=target,
                    reason=compat.reason,
                    safety_level=command.safety_level,
                    compatible=False,
                    missing_requirements=compat.missing_tools + compat.missing_ports + compat.missing_endpoints + compat.missing_privileges,
                )

        # ── جميع الشروط نجحت ──
        log.info(
            f"[FILTER] APPROVED: {command.tool} on {target} "
            f"(safety={command.safety_level.value})"
        )
        return VerificationResult(
            verdict=VerificationVerdict.APPROVED,
            command_id=command.id,
            tool=command.tool,
            target=target,
            reason="All deterministic checks passed",
            safety_level=command.safety_level,
            compatible=True,
        )

    # ------------------------------------------------------------------ #
    # الفحوص الفرعية
    # ------------------------------------------------------------------ #
    def _check_scope(self, target: str) -> tuple[bool, str]:
        """
        التحقق من أن الهدف داخل النطاق المسموح.
        أولوية: StrictScopeEngine إذا توفّر، ثم القائمة اليدوية allowed_targets.
        """
        if not target:
            return True, "No target specified — scope check skipped"

        # استخدام StrictScopeEngine إذا توفّر
        if self.scope_engine is not None:
            try:
                result = self.scope_engine.is_in_scope(target)
                if hasattr(result, "in_scope"):
                    if result.in_scope:
                        return True, "In scope (StrictScopeEngine)"
                    return False, f"Out of scope (StrictScopeEngine): {getattr(result, 'reason', '')}"
                if isinstance(result, bool):
                    return (True, "In scope (StrictScopeEngine)") if result else (False, "Out of scope (StrictScopeEngine)")
            except Exception as exc:
                log.warning(f"Scope engine error: {exc}")

        # القائمة اليدوية
        if self.allowed_targets:
            if target in self.allowed_targets:
                return True, "In scope (allowed_targets list)"
            return False, f"Target '{target}' not in allowed_targets list"

        # الشبكات المسموحة (CIDR بسيطة)
        if self.allowed_networks:
            # فحص بسيط للبادئ (prefix) دون الحاجة لـ ipaddress للتركيز على المنطق
            for net in self.allowed_networks:
                if target.startswith(net.split("/")[0]):
                    return True, f"In scope (network {net})"
            return False, f"Target '{target}' not in allowed networks"

        # إذا لم يُحدد نطاق، نسمح افتراضياً (لكن يُنصح بتحديد allowed_targets في الإنتاج)
        return True, "No scope restrictions configured — allowed by default"

    def _check_destructive(
        self,
        command: CommandEntry,
        rendered_command: str,
    ) -> tuple[bool, str]:
        """
        التحقق من أن الأمر ليس مدمرًا أو يسبب DoS.
        """
        # إذا كان مستوى الأمان DESTRUCTIVE والمحظور افتراضيًا
        if command.safety_level == CommandSafetyLevel.DESTRUCTIVE and self.block_destructive_by_default:
            return True, (
                f"Command marked as DESTRUCTIVE and destructive commands are blocked by default "
                f"({command.tool})"
            )

        # فحص أنماط الأوامر الخطيرة في الأمر المرسوم
        cmd_lower = rendered_command.lower()
        for pattern in self.destructive_patterns:
            if re.search(pattern, cmd_lower):
                return True, (
                    f"Command matches destructive pattern '{pattern}' "
                    f"({command.tool}): {rendered_command[:100]}"
                )

        return False, "Not destructive"

    # ------------------------------------------------------------------ #
    # تحديث التكوين
    # ------------------------------------------------------------------ #
    def set_scope(self, allowed_targets: List[str], allowed_networks: Optional[List[str]] = None) -> None:
        self.allowed_targets = allowed_targets
        self.allowed_networks = allowed_networks or []

    def set_compatibility_checker(self, checker: EnvironmentCompatibilityChecker) -> None:
        self.compatibility_checker = checker

    def allow_destructive(self, allow: bool = True) -> None:
        self.block_destructive_by_default = not allow
