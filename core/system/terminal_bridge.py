"""
HunterAI Safe Terminal Execution Bridge (Phase 7)
=================================================
Safely executes terminal commands with:
1. Scope verification & catastrophic command prevention
2. Output capture with automated credential & secret redaction
3. Active process supervision and rogue process termination
"""
from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.terminal_bridge")

# Catastrophic command patterns that must NEVER be executed
BLOCKED_PATTERNS = [
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+/(?:\s|$)", re.I),
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.I),  # fork bomb
    re.compile(r"\bmkfs\b", re.I),
    re.compile(r"\bdd\s+if=/dev/zero", re.I),
    re.compile(r">\s*/dev/sd[a-z]", re.I),
    re.compile(r"\b(shutdown|reboot|init\s+0|poweroff)\b", re.I),
]

# Sensitive information to redact from captured terminal output
REDACT_PATTERNS = [
    (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_\.]+", re.I), r"\1[REDACTED]"),
    (re.compile(r"(api[_\-]?key[=:\s]+)[A-Za-z0-9\-_]{16,}", re.I), r"\1[REDACTED]"),
    (re.compile(r"(password[=:\s]+)\S+", re.I), r"\1[REDACTED]"),
    (re.compile(r"(token[=:\s]+)[A-Za-z0-9\-_\.]{16,}", re.I), r"\1[REDACTED]"),
]

# ── GOVERNANCE INTEGRATION ────────────────────────────────────────────────────
# Terminal execution is a security-sensitive operation and must NEVER bypass the
# security policy layer. When a PolicyGate is wired in, it becomes the
# authoritative decision point (fail-closed). These imports are defensive so the
# module can still be imported in isolation (e.g. for pure signature checks).
try:
    from core.control_plane.policy_gate import (
        ActionCategory,
        ActionRequest,
        PolicyDecision,
        extract_candidate_destinations,
    )
except Exception:  # pragma: no cover - defensive: keep module importable standalone
    ActionCategory = None
    ActionRequest = None
    PolicyDecision = None
    extract_candidate_destinations = None


@dataclass
class TrackedProcess:
    pid: int
    command: str
    project_id: str
    started_at: float = field(default_factory=time.time)
    process_handle: Optional[subprocess.Popen] = None
    is_active: bool = True


class TerminalBridge:
    """
    Secure terminal execution layer with safety invariants and process supervisor.
    """
    def __init__(self, scope_engine: Optional[Any] = None, policy_gate: Optional[Any] = None):
        self.scope_engine = scope_engine
        self.policy_gate = policy_gate
        self.active_processes: Dict[int, TrackedProcess] = {}
        self.execution_history: List[Dict[str, Any]] = []

    def capture_output(self, raw_text: str) -> str:
        """Sanitizes terminal output by redacting credentials and tokens"""
        if not raw_text:
            return ""
        text = raw_text
        for pattern, repl in REDACT_PATTERNS:
            text = pattern.sub(repl, text)
        return text

    def _is_command_safe(self, command: str) -> Tuple[bool, Optional[str]]:
        for pat in BLOCKED_PATTERNS:
            if pat.search(command):
                return False, f"Catastrophic command signature blocked: {pat.pattern}"
        return True, None

    def execute_command(
        self,
        command: str,
        project_id: str = "default",
        timeout_seconds: float = 30.0,
        shell: bool = False,
        tool_id: Optional[str] = None,
        agent_id: str = "terminal_bridge",
    ) -> Dict[str, Any]:
        """
        Executes a terminal command with safety invariants, scope checks, and output redaction.

        Governed execution order (security-sensitive operations must never bypass the gate):
            1. Inviolable PolicyGate evaluation (authoritative when wired in, fail-closed)
            2. Local catastrophic-command signature check (defense in depth)
            3. Scope-engine check on an embedded network destination (fallback mode)
            4. Execution + output redaction
            5. Auditable execution record (project_id, tool_id, action, timestamp, decision, result)
        """
        start_time = time.time()
        resolved_tool_id = tool_id or "terminal"
        base_record: Dict[str, Any] = {
            "command": command,
            "project_id": project_id,
            "tool_id": resolved_tool_id,
            "action": "terminal_command",
            "agent_id": agent_id,
            "timestamp": start_time,
            "authorization": "NOT_EVALUATED",
            "authorization_decision": "",
        }

        # 1. Inviolable Policy Gate (authoritative, fail-closed)
        if self.policy_gate is not None and ActionRequest is not None:
            try:
                destinations = (
                    extract_candidate_destinations(command)
                    if extract_candidate_destinations is not None
                    else []
                )
                request = ActionRequest(
                    category=ActionCategory.TERMINAL_COMMAND,
                    # When a network destination is embedded in the command, surface it
                    # as the target so the scope-whitelist check applies to it as well.
                    target=destinations[0] if destinations else "local_terminal",
                    command=command,
                    reason="TerminalBridge.execute_command",
                    requested_by_model=agent_id,
                    metadata={
                        "project_id": project_id,
                        "tool_id": resolved_tool_id,
                        "destinations": destinations,
                    },
                )
                decision: "PolicyDecision" = self.policy_gate.evaluate(request)
            except Exception as exc:  # fail-closed on any evaluation error
                reason = f"POLICY GATE ERROR (fail-closed): {exc}"
                entry = {
                    **base_record,
                    "status": "DENIED_POLICY_ERROR",
                    "authorization": "DENIED",
                    "authorization_decision": reason,
                    "returncode": -1,
                    "stdout": "",
                    "stderr": reason,
                    "duration_ms": 0.0,
                }
                self.execution_history.append(entry)
                logger.error("Terminal command denied (policy gate error): %s", command)
                return entry

            if not decision.allowed:
                entry = {
                    **base_record,
                    "status": "DENIED_POLICY",
                    "authorization": "DENIED",
                    "authorization_decision": decision.reason,
                    "returncode": -1,
                    "stdout": "",
                    "stderr": decision.reason,
                    "duration_ms": 0.0,
                }
                self.execution_history.append(entry)
                logger.warning("Terminal command denied by PolicyGate: %s (reason: %s)", command, decision.reason)
                return entry

            base_record["authorization"] = "ALLOWED"
            base_record["authorization_decision"] = decision.reason

        # 2. Defense-in-depth: local catastrophic command signatures
        safe, reason = self._is_command_safe(command)
        if not safe:
            entry = {
                **base_record,
                "status": "DENIED",
                "authorization": base_record["authorization"] if base_record["authorization"] != "NOT_EVALUATED" else "DENIED",
                "authorization_decision": base_record["authorization_decision"] or (reason or ""),
                "returncode": -1,
                "stdout": "",
                "stderr": reason,
                "duration_ms": 0.0,
            }
            self.execution_history.append(entry)
            logger.warning("Terminal command denied: %s (reason: %s)", command, reason)
            return entry

        # 3. Scope check (fallback when no PolicyGate is wired in)
        if self.policy_gate is None and self.scope_engine is not None and hasattr(self.scope_engine, "is_allowed"):
            # Simple heuristic extraction of domain/IP
            parts = command.split()
            for part in parts:
                if "." in part and not part.startswith("-"):
                    cleaned = part.strip("\"'").split("/")[0].split(":")[0]
                    allowed, scope_reason = self.scope_engine.is_allowed(cleaned)
                    if not allowed:
                        entry = {
                            **base_record,
                            "status": "DENIED_SCOPE",
                            "authorization": "DENIED",
                            "authorization_decision": str(scope_reason),
                            "returncode": -1,
                            "stdout": "",
                            "stderr": f"Scope violation: {scope_reason}",
                            "duration_ms": 0.0,
                        }
                        self.execution_history.append(entry)
                        return entry

        # 4. Execution
        try:
            # Run command with timeout
            proc = subprocess.Popen(
                command if shell else (shlex.split(command) if sys.platform != "win32" else command),
                shell=shell or (sys.platform == "win32" and not isinstance(command, list)),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            
            # Register in supervisor
            self.active_processes[proc.pid] = TrackedProcess(
                pid=proc.pid,
                command=command,
                project_id=project_id,
                process_handle=proc,
            )

            stdout_raw, stderr_raw = proc.communicate(timeout=timeout_seconds)
            returncode = proc.returncode
            status = "SUCCESS" if returncode == 0 else "ERROR"
            
            # Clean from active processes
            if proc.pid in self.active_processes:
                self.active_processes[proc.pid].is_active = False

        except subprocess.TimeoutExpired:
            proc.kill()
            stdout_raw, stderr_raw = proc.communicate()
            returncode = -9
            status = "TIMEOUT"
            if proc.pid in self.active_processes:
                self.active_processes[proc.pid].is_active = False

        except Exception as e:
            stdout_raw, stderr_raw = "", str(e)
            returncode = -1
            status = "EXCEPTION"

        duration = (time.time() - start_time) * 1000.0
        
        # Redact output
        stdout_safe = self.capture_output(stdout_raw)
        stderr_safe = self.capture_output(stderr_raw)

        record = {
            **base_record,
            "status": status,
            "returncode": returncode,
            "stdout": stdout_safe,
            "stderr": stderr_safe,
            "duration_ms": round(duration, 2),
        }
        self.execution_history.append(record)
        return record

    def process_supervisor(self, max_duration_seconds: float = 60.0) -> List[Dict[str, Any]]:
        """
        Monitors active background processes and terminates rogue / runaway executions.
        """
        now = time.time()
        terminated: List[Dict[str, Any]] = []

        for pid, tracked in list(self.active_processes.items()):
            if tracked.is_active and tracked.process_handle:
                # Check if still running
                poll_result = tracked.process_handle.poll()
                if poll_result is None:
                    # Still running, check timeout
                    if now - tracked.started_at > max_duration_seconds:
                        tracked.process_handle.kill()
                        tracked.is_active = False
                        info = {
                            "pid": pid,
                            "command": tracked.command,
                            "project_id": tracked.project_id,
                            "action": "KILLED_ROGUE",
                            "running_seconds": round(now - tracked.started_at, 2),
                        }
                        terminated.append(info)
                        logger.warning("Process supervisor killed rogue process: %s", info)
                else:
                    tracked.is_active = False

        return terminated
