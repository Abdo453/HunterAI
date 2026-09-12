"""
HunterAI Operational Execution Modes & Human Approval Gate
==========================================================
Enforces operational safety:
- ExecutionMode.PASSIVE (DEFAULT):
    Passive crawling, endpoint mapping, JavaScript parsing, traffic analysis.
    Dispatches ZERO offensive payloads.
- ExecutionMode.ACTIVE:
    Allows targeted verification probes only after explicit authorization.
- HumanApprovalGate:
    Requires explicit human approval before high-risk actions:
    - Active SQL Injection
    - SSRF canary/internal probes
    - File upload attempts
    - Brute force or credential stuffing
    - Mutating state-changing requests (POST/PUT/DELETE)
"""
from __future__ import annotations

import logging
import time
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("hunter_ai.execution_modes")


class ExecutionMode(str, Enum):
    PASSIVE = "PASSIVE"  # Default: Zero offensive packets sent
    ACTIVE = "ACTIVE"    # Requires explicit authorization


class HighRiskActionType(str, Enum):
    ACTIVE_SQLI = "ACTIVE_SQLI"
    SSRF_PROBE = "SSRF_PROBE"
    FILE_UPLOAD = "FILE_UPLOAD"
    BRUTE_FORCE = "BRUTE_FORCE"
    STATE_CHANGING_REQUEST = "STATE_CHANGING_REQUEST"
    RCE_PAYLOAD = "RCE_PAYLOAD"


class ModeViolationError(PermissionError):
    """Raised when an active payload is dispatched while system is in PASSIVE mode"""
    pass


class HumanApprovalDeniedError(PermissionError):
    """Raised when a high-risk security action is rejected by Human Approval Gate"""
    pass


class ModeManager:
    """Manages system-wide execution mode with PASSIVE as immutable default"""

    def __init__(self, initial_mode: ExecutionMode = ExecutionMode.PASSIVE):
        self._current_mode = initial_mode
        self._mode_change_log: List[Dict[str, Any]] = [{
            "mode": initial_mode.value,
            "timestamp": time.time(),
            "reason": "System initialization (Default PASSIVE)."
        }]

    @property
    def current_mode(self) -> ExecutionMode:
        return self._current_mode

    @property
    def is_passive(self) -> bool:
        return self._current_mode == ExecutionMode.PASSIVE

    @property
    def is_active(self) -> bool:
        return self._current_mode == ExecutionMode.ACTIVE

    def switch_mode(self, new_mode: ExecutionMode, reason: str = "", authorized_by: str = "user") -> None:
        if new_mode == self._current_mode:
            return
        old_mode = self._current_mode
        self._current_mode = new_mode
        self._mode_change_log.append({
            "from_mode": old_mode.value,
            "to_mode": new_mode.value,
            "timestamp": time.time(),
            "reason": reason,
            "authorized_by": authorized_by
        })
        logger.warning(f"[OPERATIONAL MODE SWITCH] {old_mode.value} -> {new_mode.value} by '{authorized_by}': {reason}")

    def assert_active_allowed(self, action_description: str) -> None:
        """Enforces that active payloads cannot be dispatched in PASSIVE mode"""
        if self.is_passive:
            err = (
                f"SAFETY SHIELD: Cannot execute '{action_description}' in PASSIVE mode. "
                f"System is configured to Passive Discovery by default. "
                f"Switch to ACTIVE mode with explicit authorization before dispatching payloads."
            )
            logger.error(err)
            raise ModeViolationError(err)


class HumanApprovalGate:
    """
    Human Approval Gate for high-consequence pentesting actions.
    Pauses execution and requests confirmation before dangerous probes.
    """

    def __init__(
        self,
        interactive: bool = False,
        auto_approved_categories: Optional[List[HighRiskActionType]] = None,
        approval_callback: Optional[Callable[[Dict[str, Any]], bool]] = None
    ):
        self.interactive = interactive
        self.auto_approved = set(auto_approved_categories or [])
        self.approval_callback = approval_callback
        self.audit_log: List[Dict[str, Any]] = []

    def request_approval(
        self,
        action_type: HighRiskActionType,
        target: str,
        details: Dict[str, Any]
    ) -> bool:
        """
        Evaluates approval for a high-risk action.
        Returns True if approved, raises HumanApprovalDeniedError if rejected.
        """
        request_record = {
            "action_type": action_type.value,
            "target": target,
            "details": details,
            "timestamp": time.time()
        }

        # Check whitelist
        if action_type in self.auto_approved:
            request_record["status"] = "APPROVED_BY_WHITELIST"
            self.audit_log.append(request_record)
            return True

        # Custom callback check
        if self.approval_callback:
            approved = self.approval_callback(request_record)
            request_record["status"] = "APPROVED_BY_CALLBACK" if approved else "DENIED_BY_CALLBACK"
            self.audit_log.append(request_record)
            if not approved:
                raise HumanApprovalDeniedError(f"High-risk action '{action_type.value}' on '{target}' was rejected by callback.")
            return True

        # Non-interactive fallback: If not whitelisted and no callback, reject high risk for safety
        if not self.interactive:
            request_record["status"] = "DENIED_NO_INTERACTIVE_USER"
            self.audit_log.append(request_record)
            raise HumanApprovalDeniedError(
                f"HUMAN APPROVAL GATE: High-risk action '{action_type.value}' on '{target}' "
                f"requires explicit human approval. (Auto-approval disabled in safe headless mode)."
            )

        # Interactive user prompt
        print(f"\n⚠️  [HUMAN APPROVAL REQUIRED] High-risk action: {action_type.value}")
        print(f"   Target:  {target}")
        print(f"   Details: {details}")
        ans = input("   Authorize this high-risk action? [y/N]: ").strip().lower()
        if ans == "y":
            request_record["status"] = "APPROVED_BY_USER"
            self.audit_log.append(request_record)
            return True
        else:
            request_record["status"] = "DENIED_BY_USER"
            self.audit_log.append(request_record)
            raise HumanApprovalDeniedError(f"User declined authorization for '{action_type.value}' on '{target}'.")
