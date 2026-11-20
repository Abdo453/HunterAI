"""
HunterAI / ARTEX Guard & Tool Interceptor Gate
==============================================
Provides safety boundary enforcement and command interception:
- Pre-tool execution hooks that evaluate command lines and parameters.
- Destructive command blocking (filesystem formatting, database wiping, fork bombs).
- Scope enforcement (blocks requests to non-authorized IP ranges / domains).
- Detailed audit logging of every tool execution attempt.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.guard")

DESTRUCTIVE_COMMAND_PATTERNS = [
    re.compile(r"\brm\s+-(?:r[fF]|f[rR])\s+/(?:\s|$)", re.IGNORECASE),
    re.compile(r"\bmkfs(?:\.\w+)?\s+", re.IGNORECASE),
    re.compile(r"\bdd\s+if=/dev/(?:zero|random|urandom)\s+of=/dev/[snhv]d", re.IGNORECASE),
    re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:", re.IGNORECASE),
    re.compile(r"\bdrop\s+database\b", re.IGNORECASE),
    re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
    re.compile(r"\bshutdown\s+-(?:h|r)\b", re.IGNORECASE),
]


class InterceptAction(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"


@dataclass
class AuditEntry:
    timestamp: float
    tool_name: str
    action: InterceptAction
    command_or_target: str
    reason: str = ""


class ToolInterceptorGate:
    """
    Evaluates tool invocation parameters against safety rules and target scope boundaries.
    """

    def __init__(self, allowed_scope: Optional[List[str]] = None):
        self.allowed_scope = [s.lower().strip() for s in (allowed_scope or [])]
        self.audit_log: List[AuditEntry] = []
        self._custom_rules: List[Callable[[str, Dict[str, Any]], Tuple[bool, str]]] = []
        try:
            from core.guard.supply_chain_defense import SupplyChainDefenseGuard
            self.supply_chain = SupplyChainDefenseGuard()
        except Exception:
            self.supply_chain = None

    def add_custom_rule(self, rule_fn: Callable[[str, Dict[str, Any]], Tuple[bool, str]]) -> None:
        """Rule function returns (is_blocked, reason)"""
        self._custom_rules.append(rule_fn)

    def evaluate_pre_tool_use(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Evaluates tool execution before it runs.
        Returns (is_allowed, reason).
        """
        cmd = str(arguments.get("command") or arguments.get("cmd") or "")
        target = str(arguments.get("target") or arguments.get("url") or arguments.get("host") or "")

        # 0. Supply chain threat intelligence & malicious image / repo check
        if self.supply_chain and cmd:
            is_blocked, reason = self.supply_chain.inspect_command(cmd)
            if is_blocked:
                self._record_audit(tool_name, InterceptAction.BLOCK, cmd, reason)
                return False, reason

        # 1. Shell command safety check
        for pattern in DESTRUCTIVE_COMMAND_PATTERNS:
            if pattern.search(cmd):
                reason = f"Blocked dangerous destructive pattern: {pattern.pattern}"
                self._record_audit(tool_name, InterceptAction.BLOCK, cmd, reason)
                return False, reason

        # 2. Strict Scope verification check for network/HTTP tools
        if target and self.allowed_scope:
            if self.supply_chain:
                is_in_scope, reason = self.supply_chain.enforce_mandatory_scope(target, self.allowed_scope)
                if not is_in_scope:
                    self._record_audit(tool_name, InterceptAction.BLOCK, target, reason)
                    return False, reason
            else:
                in_scope = any(scope_item in target.lower() for scope_item in self.allowed_scope)
                if not in_scope:
                    reason = f"Target '{target}' is outside the authorized scope: {self.allowed_scope}"
                    self._record_audit(tool_name, InterceptAction.BLOCK, target, reason)
                    return False, reason

        # 3. Custom user-defined rules
        for rule in self._custom_rules:
            is_blocked, custom_reason = rule(tool_name, arguments)
            if is_blocked:
                self._record_audit(tool_name, InterceptAction.BLOCK, str(arguments), custom_reason)
                return False, custom_reason

        # Allowed
        self._record_audit(tool_name, InterceptAction.ALLOW, cmd or target or tool_name, "Verified safe & in-scope")
        return True, "Authorized"

    def _record_audit(self, tool_name: str, action: InterceptAction, cmd: str, reason: str):
        entry = AuditEntry(
            timestamp=time.time(),
            tool_name=tool_name,
            action=action,
            command_or_target=cmd[:200],
            reason=reason,
        )
        self.audit_log.append(entry)
        if action == InterceptAction.BLOCK:
            logger.warning("[Guard Gate] BLOCKED: %s on tool '%s' - %s", cmd[:60], tool_name, reason)
        else:
            logger.debug("[Guard Gate] ALLOWED: tool '%s'", tool_name)
