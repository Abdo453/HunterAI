"""
Command Executor Bridge — جسر 명령 الأوامر الآمن
================================================
يربط CommandKB (الأوامر الموثقة) مع DeterministicFilter (التحقق الحتمي)
وينفذ الأوامر عبر subprocess مع مهلة وقتية وقوائم سماح (allowlist).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from core.command_kb.models import CommandEntry
from core.command_kb.registry import CommandRegistry
from core.verification import DeterministicFilter, VerificationResult

log = logging.getLogger("core.command_executor")


@dataclass
class CommandExecutionResult:
    """نتيجة تنفيذ أمر"""
    command_id: str
    tool: str
    target: str
    rendered_command: str
    success: bool
    return_code: int
    stdout: str
    stderr: str
    execution_time: float
    verification_result: Optional[VerificationResult] = None
    error: Optional[str] = None
    evidence_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command_id": self.command_id,
            "tool": self.tool,
            "target": self.target,
            "rendered_command": self.rendered_command,
            "success": self.success,
            "return_code": self.return_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "execution_time": round(self.execution_time, 3),
            "verification": self.verification_result.to_dict() if self.verification_result else None,
            "error": self.error,
            "evidence_files": self.evidence_files,
        }


class CommandExecutor:
    """
    ينفذ أوامر CommandKB بعد التحقق الحتمي عبر DeterministicFilter.
    يدعم:
    - Allowlist للأوامر المسموح بها (فقط من CommandKB)
    - مهلة وقتية لكل أمر (timeout)
    - captura 출력 (stdout/stderr)
    - تسجيل الأدلة في TaskClueCache
    """

    def __init__(
        self,
        command_registry: CommandRegistry,
        verification_filter: DeterministicFilter,
        default_timeout: float = 60.0,
        max_output_size: int = 10 * 1024 * 1024,  # 10 MB
    ):
        self.registry = command_registry
        self.filter = verification_filter
        self.default_timeout = default_timeout
        self.max_output_size = max_output_size
        self.execution_history: List[CommandExecutionResult] = []

    # ------------------------------------------------------------------ #
    # التنفيذ الرئيسي
    # ------------------------------------------------------------------ #
    async def execute_command(
        self,
        command_id: str,
        target: str = "",
        placeholders: Optional[Dict[str, str]] = None,
    ) -> CommandExecutionResult:
        """
        تنفيذ أمر بمعرّفه من CommandKB.
        1. يجلب الأمر من السجل.
        2. يستبدل placeholders (target, port, url, ...).
        3. يمرر الأمر عبر DeterministicFilter.
        4. إذا تمت الموافقة → ينفذ عبر subprocess.
        5. يرجع نتيجة التنفيذ.
        """
        command = self.registry.get(command_id)
        if not command:
            return CommandExecutionResult(
                command_id=command_id,
                tool="unknown",
                target=target,
                rendered_command="",
                success=False,
                return_code=-1,
                stdout="",
                stderr=f"Command {command_id} not found in CommandKB",
                execution_time=0.0,
                error="COMMAND_NOT_FOUND",
            )

        placeholders = placeholders or {}
        placeholders.setdefault("target", target)

        # توليد الأمر النهائي
        try:
            rendered = command.render(**placeholders)
        except ValueError as exc:
            return CommandExecutionResult(
                command_id=command.id,
                tool=command.tool,
                target=target,
                rendered_command=command.command_template,
                success=False,
                return_code=-1,
                stdout="",
                stderr=str(exc),
                execution_time=0.0,
                error="RENDER_ERROR",
            )

        # التحقق الحتمي قبل التنفيذ
        verification = self.filter.verify(command, target=target, rendered_command=rendered)
        if not verification.is_approved():
            return CommandExecutionResult(
                command_id=command.id,
                tool=command.tool,
                target=target,
                rendered_command=rendered,
                success=False,
                return_code=-1,
                stdout="",
                stderr=verification.reason,
                execution_time=0.0,
                verification_result=verification,
                error=f"REJECTED:{verification.verdict.value}",
            )

        # التنفيذ الفعلي
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_shell(
                rendered,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=self.default_timeout
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                stdout_bytes, stderr_bytes = await proc.communicate()
                execution_time = time.time() - start
                return CommandExecutionResult(
                    command_id=command.id,
                    tool=command.tool,
                    target=target,
                    rendered_command=rendered,
                    success=False,
                    return_code=-1,
                    stdout=stdout_bytes.decode("utf-8", errors="replace")[: self.max_output_size],
                    stderr=stderr_bytes.decode("utf-8", errors="replace")[: self.max_output_size],
                    execution_time=execution_time,
                    verification_result=verification,
                    error="TIMEOUT",
                )

            execution_time = time.time() - start
            stdout = stdout_bytes.decode("utf-8", errors="replace")[: self.max_output_size]
            stderr = stderr_bytes.decode("utf-8", errors="replace")[: self.max_output_size]
            success = proc.returncode == 0

            result = CommandExecutionResult(
                command_id=command.id,
                tool=command.tool,
                target=target,
                rendered_command=rendered,
                success=success,
                return_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                verification_result=verification,
            )

            self.execution_history.append(result)
            log.info(
                f"[CMD-EXEC] {command.tool} on {target} -> "
                f"{'OK' if success else 'FAIL'} (rc={proc.returncode}, {execution_time:.2f}s)"
            )
            return result

        except Exception as exc:
            execution_time = time.time() - start
            log.exception(f"[CMD-EXEC] Exception executing {command.tool}")
            return CommandExecutionResult(
                command_id=command.id,
                tool=command.tool,
                target=target,
                rendered_command=rendered,
                success=False,
                return_code=-1,
                stdout="",
                stderr=str(exc),
                execution_time=execution_time,
                verification_result=verification,
                error="EXCEPTION",
            )

    # ------------------------------------------------------------------ #
    # مساعدات
    # ------------------------------------------------------------------ #
    def get_history(self) -> List[CommandExecutionResult]:
        return list(self.execution_history)

    def get_successful_executions(self) -> List[CommandExecutionResult]:
        return [r for r in self.execution_history if r.success]

    def get_failed_executions(self) -> List[CommandExecutionResult]:
        return [r for r in self.execution_history if not r.success]
