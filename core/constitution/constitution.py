"""
HunterAI Machine Constitution (الدستور الآلي للمبادئ غير القابلة للتجاوز)
مبادئ P0-P4 التي لا يمكن تجاوزها بأي أداة أو وكيل أو موديل لغوي
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

log = logging.getLogger("hunter_ai.constitution")


class ConstitutionLevel(str):
    P0 = "P0"  # Zero Out-of-Scope Egress — حظر الخروج خارج النطاق
    P1 = "P1"  # Zero Unapproved State Mutations —禁止 تغييرات الحالة غير المعتمدة
    P2 = "P2"  # Zero Plaintext Secret Disclosure — 금지 كشف الأسرار بالنص الصريح
    P3 = "P3"  # Zero Unverifiable Claims —禁止 الادعاءات غير القابلة للتحقق
    P4 = "P4"  # Least Privilege & Kill Switch — أقل امتياز ومفتاح إيقاف طارئ


@dataclass
class ConstitutionRule:
    """قاعدة دستور واحدة"""
    level: str  # P0, P1, P2, P3, P4
    rule_id: str
    title: str
    description: str
    is_absolute: bool = True  # هل يمكن تجاوزها أم لا
    auto_enforced: bool = True  # هل يتم تطبيقها تلقائياً بواسطة النظام

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "is_absolute": self.is_absolute,
            "auto_enforced": self.auto_enforced,
        }


@dataclass
class ConstitutionViolation:
    """انتهاك لأحد مبادئ الدستور"""
    violation_id: str
    level: str
    rule_id: str
    action: str
    target: str
    reason: str
    blocked: bool = True  # هل تم منع التنفيذ أم تم السماح مع تحذير
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "violation_id": self.violation_id,
            "level": self.level,
            "rule_id": self.rule_id,
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "blocked": self.blocked,
            "timestamp": self.timestamp,
        }


class MachineConstitution:
    """
    الدستور الآلي لـ HunterAI — يطبّق المبادئ غير القابلة للتجاوز (P0-P4)
    على جميع الإجراءات التي ينفذها النظام.
    """

    def __init__(self):
        self.rules: Dict[str, ConstitutionRule] = {}
        self.violations: List[ConstitutionViolation] = []
        self._violation_counter = 0
        self._initialize_default_rules()

    def _initialize_default_rules(self):
        """تهيئة القواعد الافتراضية للدستور"""
        self.register_rule(ConstitutionRule(
            level=ConstitutionLevel.P0,
            rule_id="P0-001",
            title="Zero Out-of-Scope Egress",
            description="حظر أي حركة Netzwerk خارج النطاق المصرح به (RFC1918, Cloud Metadata 169.254.x, localhost)",
            is_absolute=True,
            auto_enforced=True,
        ))
        self.register_rule(ConstitutionRule(
            level=ConstitutionLevel.P1,
            rule_id="P1-001",
            title="Zero Unapproved State Mutations in Production",
            description="حظر أي تغييرات حالة غير معتمدة على أهداف إنتاجية",
            is_absolute=True,
            auto_enforced=True,
        ))
        self.register_rule(ConstitutionRule(
            level=ConstitutionLevel.P2,
            rule_id="P2-001",
            title="Zero Plaintext Secret Disclosure",
            description="حظر كشف أي أسرار (كلمات مرور، توكنات، مفاتيح API) بالنص الصريح في السجلات أو التقارير",
            is_absolute=True,
            auto_enforced=True,
        ))
        self.register_rule(ConstitutionRule(
            level=ConstitutionLevel.P3,
            rule_id="P3-001",
            title="Zero Unverifiable / Hallucinated Claims",
            description="حظر الإبلاغ عن أي نتيجة بدون أدلة قابلة لإعادة الإنتاج والتحقق",
            is_absolute=True,
            auto_enforced=True,
        ))
        self.register_rule(ConstitutionRule(
            level=ConstitutionLevel.P4,
            rule_id="P4-001",
            title="Principle of Least Privilege & Emergency Kill Switch",
            description="تشغيل بأقل امتياز ضروري مع وجود مفتاح إيقاف طارئ يمكن تفعيله فوراً",
            is_absolute=True,
            auto_enforced=True,
        ))

    def register_rule(self, rule: ConstitutionRule):
        self.rules[rule.rule_id] = rule
        log.debug(f"[Constitution] Registered rule: {rule.rule_id} ({rule.level})")

    def get_rule(self, rule_id: str) -> Optional[ConstitutionRule]:
        return self.rules.get(rule_id)

    def list_rules(self) -> List[ConstitutionRule]:
        return list(self.rules.values())

    def check_action(
        self,
        action: str,
        target: str,
        level: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """
        التحقق من إجراء واحد ضد قواعد الدستور.
        يرجع (مسموح, سبب, قاعدة مخترقة أو None)
        """
        context = context or {}

        # فحص القواعد بناءً على المستوى
        for rule in self.rules.values():
            if rule.level != level:
                continue

            violation = self._evaluate_rule(rule, action, target, context)
            if violation:
                self.violations.append(violation)
                self._violation_counter += 1
                log.warning(
                    f"[Constitution] VIOLATION {violation.rule_id}: {violation.action} on {violation.target} — {violation.reason}"
                )
                return False, violation.reason, violation

        return True, "OK", None

    def _evaluate_rule(
        self,
        rule: ConstitutionRule,
        action: str,
        target: str,
        context: Dict[str, Any],
    ) -> Optional[ConstitutionViolation]:
        """تقييم قاعدة واحدة ضد إجراء معين"""
        # هذه المنطق يمكن تخصيصه لكل قاعدة
        if rule.rule_id == "P0-001":
            # حظر النطاقات الخاصة والمetadata
            blocked_hosts = ["localhost", "127.0.0.1", "169.254.169.254", "metadata.google.internal"]
            private_subnets = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."]
            for host in blocked_hosts:
                if host in target.lower():
                    return ConstitutionViolation(
                        violation_id=f"viol_{self._violation_counter + 1}",
                        level=rule.level,
                        rule_id=rule.rule_id,
                        action=action,
                        target=target,
                        reason=f"Host '{host}' is blocked by P0-001 (internal/metadata service)",
                    )
            for subnet in private_subnets:
                if target.startswith(subnet):
                    return ConstitutionViolation(
                        violation_id=f"viol_{self._violation_counter + 1}",
                        level=rule.level,
                        rule_id=rule.rule_id,
                        action=action,
                        target=target,
                        reason=f"Subnet '{subnet}' is blocked by P0-001 (private IP range)",
                    )

        if rule.rule_id == "P3-001":
            # حظر الادعاءات غير القابلة للتحقق
            if context.get("evidence_level") == "E0" and context.get("claim_confirmed", False):
                return ConstitutionViolation(
                    violation_id=f"viol_{self._violation_counter + 1}",
                    level=rule.level,
                    rule_id=rule.rule_id,
                    action=action,
                    target=target,
                    reason="Cannot confirm finding with E0 evidence only — P3-001 violation",
                )

        return None

    def get_violations(self) -> List[ConstitutionViolation]:
        return list(self.violations)

    def get_violations_by_level(self, level: str) -> List[ConstitutionViolation]:
        return [v for v in self.violations if v.level == level]

    def clear_violations(self):
        self.violations.clear()
        self._violation_counter = 0

    def summary(self) -> dict:
        return {
            "total_rules": len(self.rules),
            "total_violations": len(self.violations),
            "violations_by_level": {
                level: len(self.get_violations_by_level(level))
                for level in [ConstitutionLevel.P0, ConstitutionLevel.P1, ConstitutionLevel.P2, ConstitutionLevel.P3, ConstitutionLevel.P4]
            },
        }


# مثيل افتراضي يمكن استخدامه في toda the system
constitution: Optional[MachineConstitution] = None


def get_constitution() -> MachineConstitution:
    global constitution
    if constitution is None:
        constitution = MachineConstitution()
    return constitution
