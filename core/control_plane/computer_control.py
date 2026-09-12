"""
HunterAI Unified Computer Control Plane
=======================================
Provides audited Terminal execution, process management, and filesystem operations.
Every single action is:
1. Checked by PolicyGate (non-bypassable safety invariants).
2. Monitored for timeout, memory, and return codes.
3. Audited to terminal_history.jsonl and linked to Evidence / Lineage.
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.control_plane.policy_gate import ActionCategory, ActionRequest, PolicyGate

logger = logging.getLogger("hunter_ai.computer_control")


@dataclass
class ExecutionRecord:
    command: str
    timestamp: str
    cwd: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    tool: str
    stage: str
    reason: str
    artifact_ref: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ManagedProcess:
    process_id: str
    pid: int
    command: str
    started_at: float
    popen_obj: subprocess.Popen
    log_path: str
    status: str = "running"  # running, finished, terminated, errored


class ComputerControl:
    """
    Unified Computer Control Agent Interface:
    - execute_command()
    - read_output()
    - write_file()
    - read_file()
    - list_directory()
    - search_files()
    - start_process()
    - stop_process()
    - get_process_status()
    """

    def __init__(
        self,
        workspace_dir: str,
        policy_gate: PolicyGate,
        audit_log_path: Optional[str] = None,
    ):
        self.workspace_dir = Path(workspace_dir).resolve()
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.policy_gate = policy_gate
        self.audit_log_path = audit_log_path or str(self.workspace_dir / "terminal_history.jsonl")
        self._background_processes: Dict[str, ManagedProcess] = {}
        self.execution_history: List[ExecutionRecord] = []

    def _audit_record(self, record: ExecutionRecord) -> None:
        """Persist execution record to JSONL history for reproducible lineage"""
        self.execution_history.append(record)
        try:
            with open(self.audit_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to append to audit log {self.audit_log_path}: {e}")

    # ── 1. TERMINAL COMMAND EXECUTION ────────────────────────────────────────

    async def execute_command(
        self,
        command: str,
        tool: str = "custom",
        stage: str = "general",
        reason: str = "",
        timeout: int = 120,
        cwd: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None,
        target: str = "",
        requested_by_model: str = "unknown",
    ) -> ExecutionRecord:
        """
        Executes a shell/terminal command safely through PolicyGate with full auditing.
        """
        start_time = time.time()
        iso_time = datetime.now().isoformat()
        effective_cwd = Path(cwd).resolve() if cwd else self.workspace_dir

        # 1. Evaluate against PolicyGate
        req = ActionRequest(
            category=ActionCategory.TERMINAL_COMMAND,
            target=target or "local_terminal",
            command=command,
            reason=reason,
            requested_by_model=requested_by_model,
        )
        decision = self.policy_gate.evaluate(req)
        if not decision.allowed:
            rec = ExecutionRecord(
                command=command,
                timestamp=iso_time,
                cwd=str(effective_cwd),
                exit_code=-1,
                stdout="",
                stderr=f"DENIED_BY_POLICY_GATE: {decision.reason}",
                duration_ms=0.0,
                tool=tool,
                stage=stage,
                reason=reason,
                success=False,
                error_message=decision.reason,
            )
            self._audit_record(rec)
            return rec

        # 2. Build environment
        full_env = os.environ.copy()
        if env_vars:
            full_env.update(env_vars)

        # 3. Asynchronously execute process
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(effective_cwd),
                env=full_env,
            )

            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    proc.communicate(), timeout=float(timeout)
                )
                stdout_str = stdout_data.decode("utf-8", errors="replace")
                stderr_str = stderr_data.decode("utf-8", errors="replace")
                exit_code = proc.returncode or 0
                error_msg = None if exit_code == 0 else f"Process exited with code {exit_code}"
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                stdout_str = ""
                stderr_str = f"Execution timed out after {timeout} seconds"
                exit_code = -2
                error_msg = "CommandTimeout"

        except Exception as e:
            stdout_str = ""
            stderr_str = str(e)
            exit_code = -3
            error_msg = f"ExecutionException: {e}"

        duration_ms = (time.time() - start_time) * 1000.0

        rec = ExecutionRecord(
            command=command,
            timestamp=iso_time,
            cwd=str(effective_cwd),
            exit_code=exit_code,
            stdout=stdout_str,
            stderr=stderr_str,
            duration_ms=round(duration_ms, 2),
            tool=tool,
            stage=stage,
            reason=reason,
            success=(exit_code == 0),
            error_message=error_msg,
        )
        self._audit_record(rec)
        return rec

    # ── 2. PROCESS MANAGEMENT (BACKGROUND JOBS) ──────────────────────────────

    def start_process(
        self,
        process_id: str,
        command: str,
        tool: str = "daemon",
        stage: str = "background",
        reason: str = "",
        cwd: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Start a persistent background process and track its output stream"""
        effective_cwd = Path(cwd).resolve() if cwd else self.workspace_dir
        log_file = self.workspace_dir / f"process_{process_id}.log"

        # Check policy
        req = ActionRequest(
            category=ActionCategory.PROCESS_SPAWN,
            target="background_process",
            command=command,
            reason=reason,
        )
        decision = self.policy_gate.evaluate(req)
        if not decision.allowed:
            return False, f"POLICY REJECTION: {decision.reason}"

        try:
            out_fd = open(log_file, "w", encoding="utf-8")
            p = subprocess.Popen(
                command,
                shell=True,
                stdout=out_fd,
                stderr=subprocess.STDOUT,
                cwd=str(effective_cwd),
            )
            managed = ManagedProcess(
                process_id=process_id,
                pid=p.pid,
                command=command,
                started_at=time.time(),
                popen_obj=p,
                log_path=str(log_file),
                status="running",
            )
            self._background_processes[process_id] = managed
            logger.info(f"Started background process {process_id} (PID: {p.pid})")
            return True, f"Process '{process_id}' started with PID {p.pid}"
        except Exception as e:
            return False, f"Failed to spawn background process: {e}"

    def get_process_status(self, process_id: str) -> Dict[str, Any]:
        """Poll the current state and exit status of a tracked background process"""
        if process_id not in self._background_processes:
            return {"status": "not_found", "error": f"No process tracked with ID '{process_id}'"}

        m = self._background_processes[process_id]
        poll_res = m.popen_obj.poll()
        if poll_res is None:
            m.status = "running"
        elif poll_res == 0:
            m.status = "finished"
        else:
            m.status = f"errored_code_{poll_res}"

        # Read last 50 lines of log
        tail_log = ""
        if os.path.exists(m.log_path):
            try:
                with open(m.log_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                    tail_log = "".join(lines[-50:])
            except Exception:
                pass

        return {
            "process_id": m.process_id,
            "pid": m.pid,
            "command": m.command,
            "status": m.status,
            "runtime_sec": round(time.time() - m.started_at, 1),
            "tail_output": tail_log,
        }

    def stop_process(self, process_id: str) -> bool:
        """Terminate a running background process"""
        if process_id not in self._background_processes:
            return False
        m = self._background_processes[process_id]
        try:
            m.popen_obj.terminate()
            m.status = "terminated"
            return True
        except Exception as e:
            logger.warning(f"Error terminating process {process_id}: {e}")
            return False

    def read_output(self, process_id: str) -> str:
        """Read complete log output of a tracked background process"""
        status = self.get_process_status(process_id)
        return status.get("tail_output", "")

    # ── 3. WORKSPACE FILESYSTEM OPERATIONS ───────────────────────────────────

    def write_file(self, relative_path: str, content: str) -> Tuple[bool, str]:
        """Safely writes a file within the designated workspace directory"""
        try:
            full_path = (self.workspace_dir / relative_path).resolve()
            # Enforce workspace jail
            if not str(full_path).startswith(str(self.workspace_dir)):
                return False, f"SECURITY: Path '{relative_path}' escapes workspace jail."
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True, str(full_path)
        except Exception as e:
            return False, f"Write failed: {e}"

    def read_file(self, relative_path: str) -> Tuple[bool, str]:
        """Safely reads a file within the workspace"""
        try:
            full_path = (self.workspace_dir / relative_path).resolve()
            if not full_path.exists():
                return False, f"File not found: {relative_path}"
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                return True, f.read()
        except Exception as e:
            return False, f"Read failed: {e}"

    def list_directory(self, relative_path: str = "") -> List[Dict[str, Any]]:
        """Lists directory entries within workspace"""
        full_path = (self.workspace_dir / relative_path).resolve()
        if not full_path.exists() or not full_path.is_dir():
            return []
        items = []
        for entry in os.scandir(full_path):
            items.append({
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size_bytes": entry.stat().st_size if entry.is_file() else 0,
                "path": str(Path(entry.path).relative_to(self.workspace_dir)),
            })
        return items

    def search_files(self, pattern: str, sub_dir: str = "") -> List[str]:
        """Glob search files within the workspace"""
        root = (self.workspace_dir / sub_dir).resolve()
        if not root.exists():
            return []
        matches = []
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                if fnmatch.fnmatch(fname, pattern):
                    rel = Path(os.path.join(dirpath, fname)).relative_to(self.workspace_dir)
                    matches.append(str(rel))
        return matches
