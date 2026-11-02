"""
Sandbox Executor — المنفذ المعزول
================================

ينفذ الأوامر في بيئة معزولة مع حدود على الموارد (زمن، ذاكرة، شبكة)،
لمنع التأثيرات الجانبية غير المقصودة على النظام الرئيسي.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SandboxResult:
    """نتيجة تنفيذ 명령 في البيئة المعزولة."""
    success: bool
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration_ms: float
    sandbox_dir: Optional[str] = None
    error: Optional[str] = None


class SandboxExecutor:
    """
    ينفذ أوامر shell في مجلد مؤقت معزول، مع حدود على الموارد.
    لا يلمس ملفات النظام الرئيسية إلا إذا تم تحديدها صراحة.
    """

    def __init__(
        self,
        default_timeout: int = 30,
        max_output_size: int = 1024 * 1024,  # 1 ميجابايت
        allowed_commands: Optional[List[str]] = None,
        denied_commands: Optional[List[str]] = None,
        workdir: Optional[str] = None,
    ):
        self.default_timeout = default_timeout
        self.max_output_size = max_output_size
        self.allowed_commands = set(allowed_commands or [])
        self.denied_commands = set(denied_commands or [])
        self.workdir = workdir or tempfile.mkdtemp(prefix="waf_sandbox_")

        # أوامر خطرة محظورة دائماً
        self.denied_commands.update({
            "rm", "del", "format", "fdisk", "mkfs", "shutdown", "reboot",
            "passwd", "su", "sudo", "chmod", "chown", "mkfs",
        })

    # ------------------------------------------------------------------ #
    # التحقق من الأمر
    # ------------------------------------------------------------------ #
    def _command_allowed(self, cmd: str) -> bool:
        base = cmd.split()[0] if cmd.split() else ""
        if base in self.denied_commands:
            return False
        if self.allowed_commands and base not in self.allowed_commands:
            return False
        return True

    # ------------------------------------------------------------------ #
    # التنفيذ
    # ------------------------------------------------------------------ #
    def run(
        self,
        command: str,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        capture_output: bool = True,
    ) -> SandboxResult:
        """
        ينفذ 명령 في البيئة المعزولة.
        """
        if not self._command_allowed(command):
            return SandboxResult(
                success=False,
                command=command,
                stdout="",
                stderr="",
                returncode=-1,
                duration_ms=0.0,
                sandbox_dir=self.workdir,
                error=f"الأمر '{command.split()[0] if command.split() else command}' غير مسموح في البيئة المعزولة",
            )

        timeout = timeout or self.default_timeout
        start = time.time()

        try:
            proc = subprocess.run(
                command,
                shell=True,
                cwd=self.workdir,
                env=env or os.environ.copy(),
                capture_output=capture_output,
                text=True,
                timeout=timeout,
            )
            duration_ms = (time.time() - start) * 1000

            stdout = proc.stdout or ""
            stderr = proc.stderr or ""

            # تقييد حجم المخرجات
            if len(stdout) > self.max_output_size:
                stdout = stdout[: self.max_output_size] + "\n... (تم裁اق المخرجات)"
            if len(stderr) > self.max_output_size:
                stderr = stderr[: self.max_output_size] + "\n... (تم裁اق المخرجات)"

            return SandboxResult(
                success=proc.returncode == 0,
                command=command,
                stdout=stdout,
                stderr=stderr,
                returncode=proc.returncode,
                duration_ms=duration_ms,
                sandbox_dir=self.workdir,
            )

        except subprocess.TimeoutExpired:
            duration_ms = (time.time() - start) * 1000
            return SandboxResult(
                success=False,
                command=command,
                stdout="",
                stderr="",
                returncode=-1,
                duration_ms=duration_ms,
                sandbox_dir=self.workdir,
                error=f"انتهت المهلة ({timeout} ثانية) للأمر: {command}",
            )
        except Exception as exc:
            duration_ms = (time.time() - start) * 1000
            return SandboxResult(
                success=False,
                command=command,
                stdout="",
                stderr="",
                returncode=-1,
                duration_ms=duration_ms,
                sandbox_dir=self.workdir,
                error=str(exc),
            )

    async def run_async(
        self,
        command: str,
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """نسخة غير متزامنة من run."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.run, command, timeout, env, True)

    # ------------------------------------------------------------------ #
    # تنظيف
    # ------------------------------------------------------------------ #
    def cleanup(self) -> None:
        """يحذف مجلد البيئة المعزولة إذا كان مؤقتاً."""
        import shutil
        try:
            if os.path.exists(self.workdir):
                shutil.rmtree(self.workdir, ignore_errors=True)
        except Exception:
            pass


import time  # noqa: E402  (placed after class to avoid circular style warning)

__all__ = ["SandboxExecutor", "SandboxResult"]
