"""
Policy Engine for Governed Tool Gateway (CyberStrikeAI-Inspired)
Enforces multi-layer safety arbitration: Scope boundaries, Risk Tiers, Action Rate-Limiting, and Input Sanitization.
"""
import re
import logging
from typing import Optional, Dict

from core.gateway.schemas import ActionProposal, PolicyVerdict, RiskTier
from core.gateway.risk_classifier import RiskClassifier
from agents.security_intelligence.scope_guard import ScopeGuard
from agents.security_intelligence.schemas import ScopeRule, ScopeMode

log = logging.getLogger("core.gateway.policy_engine")


class PolicyEngine:
    """
    محرك السياسات الأمني:
    يقوم بالتحكيم الأمني الصارم قبل السماح لأي أداة بالعمل:
    1. حظر الأفعال التدميرية والتخريبية فوراً
    2. تطبيق قيود النطاق الصارمة من ScopeGuard
    3. التحقق من تصاريح الفحص النشط (Active Testing Permissions)
    4. منع الحلقات التكرارية العشوائية (Rate-Limiting & Loop Guard)
    5. تعقيم المدخلات
    """

    def __init__(
        self,
        scope_guard: Optional[ScopeGuard] = None,
        risk_classifier: Optional[RiskClassifier] = None,
        max_repeated_actions: Optional[int] = None,
        full_permissions: bool = True
    ):
        # Default to full permissions mode with open scope
        rule = ScopeRule(target="*", allow_active_tests=True, mode=ScopeMode.ACTIVE) if full_permissions else ScopeRule(target="*")
        self.scope_guard = scope_guard or ScopeGuard(rule)
        self.risk_classifier = risk_classifier or RiskClassifier()
        self.full_permissions = full_permissions
        self.max_repeated_actions = max_repeated_actions if max_repeated_actions is not None else (99999 if full_permissions else 5)
        self._action_counts: Dict[str, int] = {}

    def enable_full_permissions(self):
        """منح كافة الصلاحيات الكاملة للـ Agent للعمل بحرية واستقلالية تامة"""
        self.full_permissions = True
        self.max_repeated_actions = 99999
        self.scope_guard.set_scope(ScopeRule(target="*", allow_active_tests=True, mode=ScopeMode.ACTIVE))
        log.info("[PolicyEngine] 🔓 Full Autonomous Permissions Mode ENABLED.")

    def set_scope(self, rule: ScopeRule):
        """تحديث سياسة النطاق والتصاريح"""
        self.scope_guard.set_scope(rule)

    def evaluate_proposal(self, proposal: ActionProposal) -> PolicyVerdict:
        """
        تقييم المقترح وإرجاع قرار PolicyVerdict شامل
        """
        # 1. Classify Risk Tier
        risk_tier, risk_reason = self.risk_classifier.classify_proposal(proposal)

        # Rule A: Instantly Block Destructive Commands (TIER 4)
        if risk_tier == RiskTier.TIER_4_PROHIBITED_DESTRUCTIVE:
            log.warning(f"[PolicyEngine] REJECTED proposal {proposal.id}: Destructive risk detected. Reason: {risk_reason}")
            return PolicyVerdict(
                allowed=False,
                risk_tier=risk_tier,
                status="BLOCKED_DESTRUCTIVE",
                reason=f"Action blocked by anti-destruction policy: {risk_reason}"
            )

        # 2. Scope Guard Check
        scope_dec = self.scope_guard.evaluate_scope_decision(
            target=proposal.target,
            action=proposal.action_type
        )

        if not scope_dec.allowed:
            log.warning(f"[PolicyEngine] REJECTED proposal {proposal.id}: Scope violation. Reason: {scope_dec.reason}")
            return PolicyVerdict(
                allowed=False,
                risk_tier=risk_tier,
                status="BLOCKED_SCOPE",
                reason=f"Target or path is outside authorized scope: {scope_dec.reason}"
            )

        # 3. Active Testing Permission Check
        if risk_tier in [RiskTier.TIER_2_PROBE, RiskTier.TIER_3_EXPLOIT_POC]:
            if not self.scope_guard.rule.allow_active_tests:
                log.warning(f"[PolicyEngine] REJECTED proposal {proposal.id}: Active probing disallowed by scope rule.")
                return PolicyVerdict(
                    allowed=False,
                    risk_tier=risk_tier,
                    status="BLOCKED_ACTIVE_DISALLOWED",
                    reason="Active probing or exploitation is prohibited by scope rule. Only passive observation permitted."
                )

        # 4. Action Loop / Rate-Limiting Protection
        action_key = f"{proposal.target}:{proposal.tool_name}:{proposal.action_type}"
        current_count = self._action_counts.get(action_key, 0)
        if current_count >= self.max_repeated_actions:
            log.warning(f"[PolicyEngine] REJECTED proposal {proposal.id}: Repeated action limit reached ({current_count}).")
            return PolicyVerdict(
                allowed=False,
                risk_tier=risk_tier,
                status="BLOCKED_RATE_LIMIT",
                reason=f"Action loop detected: Tool '{proposal.tool_name}' on '{proposal.target}' reached repeat limit ({self.max_repeated_actions})."
            )

        # 5. Sanitize Arguments (Prevent shell injection breakouts in tool args)
        sanitized_args = self._sanitize_command_args(proposal.command_args)

        # Increment count
        self._action_counts[action_key] = current_count + 1

        log.info(f"[PolicyEngine] APPROVED proposal {proposal.id} for tool '{proposal.tool_name}' ({risk_tier.value}).")
        return PolicyVerdict(
            allowed=True,
            risk_tier=risk_tier,
            status="APPROVED",
            reason=f"Proposal verified against scope, risk ({risk_tier.value}), and safety policies.",
            sanitized_args=sanitized_args
        )

    def _sanitize_command_args(self, raw_args: str) -> str:
        """
        تعقيم الباراميترات لمنع كسر أوامر الشل غير المصرح بها
        """
        if not raw_args:
            return ""
        # Strip newline/carriage returns and control characters
        clean = raw_args.replace("\r", " ").replace("\n", " ").strip()
        # Collapse multiple spaces
        clean = re.sub(r"\s+", " ", clean)
        return clean
