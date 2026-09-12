"""
Strict Scope & Authorization Guard for Security Intelligence (Defense in Depth)
Enforces granular scope decisions across PASSIVE, ACTIVE, THEORETICAL, and BLOCKED modes.
"""
import re
import posixpath
import urllib.parse
from typing import Dict, List, Optional, Tuple
from agents.security_intelligence.schemas import (
    ScopeRule,
    ScopeCheckResult,
    ScopeDecision,
    ScopeMode
)


class ScopeGuard:
    """الحارس الأمني الصارم لضمان عدم تجاوز النطاق وتصنيف الأوضاع الأمنية"""

    def __init__(self, rule: Optional[ScopeRule] = None):
        self.rule = rule or ScopeRule(target="*")
        self._custom_rules: Dict[str, ScopeRule] = {}

    def set_scope(self, rule: ScopeRule):
        self.rule = rule
        if rule.target:
            self._custom_rules[rule.target] = rule

    @staticmethod
    def normalize_target(target: str) -> Tuple[str, str, Optional[int]]:
        """
        Normalizes target string into (normalized_host, normalized_path, port).
        Handles:
        - Missing schemes (e.g. 'api.target.local:8443/test')
        - Case insensitivity (e.g. 'API.TARGET.LOCAL')
        - URL percent-encoding (e.g. '%2Fadmin%2Fdelete')
        - Path traversal sequences (e.g. '/api/v1/../../admin/delete')
        - Explicit ports
        """
        raw = target.strip()
        if not raw:
            return "", "/", None

        raw_with_scheme = "http://" + raw if "://" not in raw else raw

        try:
            parsed = urllib.parse.urlparse(raw_with_scheme)
            host = (parsed.hostname or "").strip().lower()
            port = parsed.port

            # Decode percent-encoding first
            unquoted_path = urllib.parse.unquote(parsed.path or "/")
            # Normalize path traversal ('..', '.', repeated slashes)
            clean_path = posixpath.normpath(unquoted_path)
            if not clean_path.startswith("/"):
                clean_path = "/" + clean_path
            if unquoted_path.endswith("/") and not clean_path.endswith("/"):
                clean_path += "/"

            return host, clean_path, port
        except Exception:
            return raw.lower(), "/", None

    def evaluate_scope_decision(self, target: str, action: str = "passive_analysis") -> ScopeDecision:
        """
        تقييم أمني دقيق يرجع ScopeDecision مع وضع التشغيل Mode:
        PASSIVE, ACTIVE, THEORETICAL, BLOCKED
        """
        action_clean = action.lower().strip()

        # 1. Theoretical & Educational reasoning is always allowed
        if any(kw in action_clean for kw in ["education", "theory", "explain", "lesson", "quiz", "research"]):
            return ScopeDecision(
                allowed=True,
                mode=ScopeMode.THEORETICAL,
                target=target or "General Topic",
                action=action,
                reason="Theoretical, research, and educational analysis is always authorized."
            )

        if not target or not target.strip():
            return ScopeDecision(
                allowed=False,
                mode=ScopeMode.BLOCKED,
                target=target,
                action=action,
                reason="Target identifier is empty or invalid.",
                safe_alternative="Provide a valid in-scope target hostname."
            )

        # Normalize host, path, and port
        host, clean_path, port = self.normalize_target(target)

        # Check Excluded safety paths (e.g. /logout, /reset, /delete) with path normalization
        for exc in self.rule.excluded_paths:
            exc_clean = posixpath.normpath(urllib.parse.unquote(exc.strip())).lower()
            if exc_clean in clean_path.lower() or exc.lower() in target.lower():
                return ScopeDecision(
                    allowed=False,
                    mode=ScopeMode.BLOCKED,
                    target=target,
                    action=action,
                    reason=f"Path '{clean_path}' contains excluded safety boundary '{exc}'.",
                    safe_alternative="Simulate logic theoretically without triggering state destruction."
                )

        # Check Wildcard scope
        if self.rule.target == "*" and not self.rule.allowed_domains:
            is_active = "active" in action_clean or "probe" in action_clean or "poc" in action_clean
            if is_active and not self.rule.allow_active_tests:
                return ScopeDecision(
                    allowed=False,
                    mode=ScopeMode.BLOCKED,
                    target=target,
                    action=action,
                    reason="Active testing is disabled in wildcard scope policy.",
                    safe_alternative="Use passive traffic observation only."
                )
            return ScopeDecision(
                allowed=True,
                mode=ScopeMode.ACTIVE if is_active else ScopeMode.PASSIVE,
                target=target,
                action=action,
                reason="Wildcard scope permitted."
            )

        # Check Domain match (case-insensitive and subdomain-aware)
        domain_match = False
        target_rule_clean = self.rule.target.strip().lower()
        if target_rule_clean != "*" and (target_rule_clean == host or host.endswith("." + target_rule_clean.lstrip("*."))):
            domain_match = True

        for allowed in self.rule.allowed_domains:
            clean_allowed = allowed.strip().lower().lstrip("*.")
            if host == clean_allowed or host.endswith("." + clean_allowed):
                domain_match = True
                break

        if not domain_match:
            return ScopeDecision(
                allowed=False,
                mode=ScopeMode.BLOCKED,
                target=target,
                action=action,
                reason=f"Target '{host}' is outside authorized domain scope.",
                safe_alternative="I can explain this vulnerability theoretically or analyze offline logs."
            )

        # Domain matches -> Check active testing permission
        is_active = "active" in action_clean or "probe" in action_clean or "poc" in action_clean
        if is_active and not self.rule.allow_active_tests:
            return ScopeDecision(
                allowed=False,
                mode=ScopeMode.BLOCKED,
                target=target,
                action=action,
                reason="Active testing is disallowed by scope rule. Only passive analysis is permitted.",
                safe_alternative="Perform passive analysis and heuristic inference only."
            )

        return ScopeDecision(
            allowed=True,
            mode=ScopeMode.ACTIVE if is_active else ScopeMode.PASSIVE,
            target=target,
            action=action,
            reason="Target and action are fully authorized."
        )

    def check_target(self, url_or_host: str, action: str = "passive_analysis") -> ScopeCheckResult:
        """Legacy compatibility wrapper around evaluate_scope_decision"""
        dec = self.evaluate_scope_decision(url_or_host, action)
        return ScopeCheckResult(
            is_in_scope=dec.allowed,
            is_action_permitted=dec.allowed,
            reason=dec.reason,
            safe_alternative_suggested=dec.safe_alternative
        )
