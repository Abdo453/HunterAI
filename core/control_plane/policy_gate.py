"""
HunterAI Immutable Policy Gate
==============================
Strict Python-enforced, frozen security governance gate.
Architectural Principle:
    LLM -> REQUEST ACTION -> POLICY GATE -> ALLOW / DENY -> EXECUTOR

The LLM / AI Model Council can NEVER modify, mutate, or loosen the policy rules.
Even if an LLM returns a JSON payload asking to override scope, disable safety,
or scan internal cloud metadata, the Policy Gate rejects it deterministically.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from core.scope_engine import (
    HARD_BLOCKED_HOSTS,
    INVIOLABLE_IPV4_SUBNETS,
    INVIOLABLE_IPV6_SUBNETS,
    RFC1918_IPV4_SUBNETS,
    DEFAULT_EXCLUDED_PATHS,
    DEFAULT_EXCLUDED_PORTS,
    ScopePolicy,
    StrictScopeEngine,
)

logger = logging.getLogger("hunter_ai.policy_gate")


class ActionCategory(str, Enum):
    TERMINAL_COMMAND = "terminal_command"
    BROWSER_NAVIGATE = "browser_navigate"
    BROWSER_INTERACTION = "browser_interaction"
    HTTP_REQUEST = "http_request"
    ACTIVE_FUZZING = "active_fuzzing"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    PROCESS_SPAWN = "process_spawn"


@dataclass(frozen=True)
class ActionRequest:
    """An immutable request from an AI agent or planner to execute an action"""
    category: ActionCategory
    target: str
    command: Optional[str] = None
    url: Optional[str] = None
    path: Optional[str] = None
    method: str = "GET"
    port: Optional[int] = None
    reason: str = ""
    requested_by_model: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    """Immutable policy decision returned to the executor"""
    allowed: bool
    reason: str
    action_request: ActionRequest
    sanitized_target: Optional[str] = None


class PolicyGate:
    """
    Inviolable Gatekeeper.
    All execution channels (Terminal, Browser, Network, Filesystem) MUST pass
    through this gate before invoking OS or network resources.
    """

    def __init__(
        self,
        scope_policy: ScopePolicy,
        authorized: bool = False,
        allow_destructive: bool = False,
    ):
        # Store frozen policy instance
        self._policy = scope_policy
        self._scope_engine = StrictScopeEngine(self._policy)
        self._authorized = authorized
        self._allow_destructive = allow_destructive
        self._blocked_commands = {
            "rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero",
            ":(){ :|:& };:", "shutdown", "reboot", "init 0"
        }

    @property
    def is_authorized(self) -> bool:
        return self._authorized

    @property
    def allows_lab_private_ips(self) -> bool:
        return self._policy.allow_private_ips_override

    def evaluate(self, req: ActionRequest) -> PolicyDecision:
        """
        Deterministically evaluates an action request.
        The LLM has NO access to modify this method or bypass its checks.
        """
        # 1. Inspect Terminal Commands for destructive shell bombs
        if req.category in (ActionCategory.TERMINAL_COMMAND, ActionCategory.PROCESS_SPAWN):
            if req.command:
                low_cmd = req.command.strip().lower()
                for bc in self._blocked_commands:
                    if bc in low_cmd:
                        logger.critical(f"POLICY VIOLATION: Blocked catastrophic command: {req.command}")
                        return PolicyDecision(
                            allowed=False,
                            reason=f"POLICY INVARIANT: Destructive command pattern '{bc}' is strictly prohibited.",
                            action_request=req
                        )

        # 2. Check Active Fuzzing Authorization
        if req.category == ActionCategory.ACTIVE_FUZZING and not self._authorized:
            return PolicyDecision(
                allowed=False,
                reason="POLICY RESTRICTION: Active fuzzing/injection requires explicit authorization (--authorized).",
                action_request=req
            )

        # 3. Scope Engine Validation on Target / URL
        target_to_check = req.url or req.target
        if not target_to_check and req.category in (ActionCategory.BROWSER_NAVIGATE, ActionCategory.HTTP_REQUEST):
            return PolicyDecision(
                allowed=False,
                reason="POLICY REJECTION: Missing target URL for network action.",
                action_request=req
            )

        # For purely local OS command execution without a network target, bypass domain whitelist check
        is_local_exec = req.category in (ActionCategory.TERMINAL_COMMAND, ActionCategory.PROCESS_SPAWN, ActionCategory.FILE_READ, ActionCategory.FILE_WRITE) and (
            not req.target or req.target in ("local_terminal", "background_process", "localhost_shell", "local")
        )

        if target_to_check and not is_local_exec:
            # Clean target
            clean = target_to_check.strip()
            if clean.startswith("data:") or clean.startswith("about:"):
                return PolicyDecision(
                    allowed=True,
                    reason="In-memory browser document permitted.",
                    action_request=req,
                    sanitized_target="in_memory_doc"
                )
            parsed = urlparse(clean if "://" in clean else f"http://{clean}")
            host = parsed.hostname or clean

            # Run through StrictScopeEngine
            allowed, scope_reason = self._scope_engine.is_allowed(
                target=host,
                path=req.path or parsed.path or "",
                port=req.port or parsed.port,
                method=req.method
            )

            if not allowed:
                logger.warning(f"POLICY GATE DENIED: target='{host}' reason='{scope_reason}'")
                return PolicyDecision(
                    allowed=False,
                    reason=f"SCOPE VIOLATION: {scope_reason}",
                    action_request=req,
                    sanitized_target=host
                )

        # Passed all gate checks
        return PolicyDecision(
            allowed=True,
            reason="Authorized within verified engagement scope and safety policy.",
            action_request=req,
            sanitized_target=target_to_check
        )
