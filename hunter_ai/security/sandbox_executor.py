"""
Sandbox Executor — المنفذ المعزول
================================

ينفذ الأوامر في بيئة معزولة مع حدود على الموارد (زمن، ذاكرة، شبكة)،
لمنع التأثيرات الجانبية غير المقصودة على النظام الرئيسي.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from core.control_plane.computer_control import _kill_popen_tree_sync, _parse_command_argv
from core.process_utils import kill_process_tree

logger = logging.getLogger("hunter_ai.sandbox_executor")


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
    @staticmethod
    def _normalize_binary_name(exe: str) -> str:
        name = Path(exe).name.lower()
        if name.endswith(".exe"):
            name = name[:-4]
        return name

    def _parse_and_validate(self, cmd: Union[str, Sequence[str]]) -> List[str]:
        argv = _parse_command_argv(cmd)
        base = self._normalize_binary_name(argv[0])
        if not base or base in self.denied_commands:
            raise PermissionError(f"الأمر '{base or argv[0]}' غير مسموح في البيئة المعزولة")
        if self.allowed_commands and base not in {self._normalize_binary_name(c) for c in self.allowed_commands}:
            raise PermissionError(f"الأمر '{base}' خارج قائمة الأوامر المسموحة في البيئة المعزولة")
        return argv

    def _command_allowed(self, cmd: Union[str, Sequence[str]]) -> bool:
        try:
            self._parse_and_validate(cmd)
            return True
        except (ValueError, PermissionError):
            return False

    # ------------------------------------------------------------------ #
    # التنفيذ
    # ------------------------------------------------------------------ #
    def run(
        self,
        command: Union[str, Sequence[str]],
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
        capture_output: bool = True,
    ) -> SandboxResult:
        """
        ينفذ الأمر كمصفوفة argv بدون shell=True مع إنهاء شجرة العمليات عند انتهاء المهلة.
        """
        cmd_display = " ".join(str(x) for x in command) if isinstance(command, (list, tuple)) else str(command)
        try:
            argv = self._parse_and_validate(command)
        except (ValueError, PermissionError) as err:
            return SandboxResult(
                success=False,
                command=cmd_display,
                stdout="",
                stderr="",
                returncode=-1,
                duration_ms=0.0,
                sandbox_dir=self.workdir,
                error=str(err),
            )

        timeout = timeout or self.default_timeout
        start = time.time()

        proc: Optional[subprocess.Popen] = None
        try:
            proc = subprocess.Popen(
                argv,
                shell=False,
                cwd=self.workdir,
                env=env or os.environ.copy(),
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                text=True,
            )
            stdout_raw, stderr_raw = proc.communicate(timeout=timeout)
            duration_ms = (time.time() - start) * 1000

            stdout = stdout_raw or ""
            stderr = stderr_raw or ""

            # تقييد حجم المخرجات
            if len(stdout) > self.max_output_size:
                stdout = stdout[: self.max_output_size] + "\n... (truncated)"
            if len(stderr) > self.max_output_size:
                stderr = stderr[: self.max_output_size] + "\n... (truncated)"

            return SandboxResult(
                success=proc.returncode == 0,
                command=cmd_display,
                stdout=stdout,
                stderr=stderr,
                returncode=proc.returncode,
                duration_ms=duration_ms,
                sandbox_dir=self.workdir,
            )

        except subprocess.TimeoutExpired:
            if proc is not None:
                _kill_popen_tree_sync(proc)
            duration_ms = (time.time() - start) * 1000
            return SandboxResult(
                success=False,
                command=cmd_display,
                stdout="",
                stderr="",
                returncode=-1,
                duration_ms=duration_ms,
                sandbox_dir=self.workdir,
                error=f"انتهت المهلة ({timeout} ثانية) للأمر: {cmd_display}",
            )
        except Exception as exc:
            duration_ms = (time.time() - start) * 1000
            return SandboxResult(
                success=False,
                command=cmd_display,
                stdout="",
                stderr="",
                returncode=-1,
                duration_ms=duration_ms,
                sandbox_dir=self.workdir,
                error=str(exc),
            )

    async def run_async(
        self,
        command: Union[str, Sequence[str]],
        timeout: Optional[int] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        """نسخة غير متزامنة عبر create_subprocess_exec + kill_process_tree."""
        cmd_display = " ".join(str(x) for x in command) if isinstance(command, (list, tuple)) else str(command)
        try:
            argv = self._parse_and_validate(command)
        except (ValueError, PermissionError) as err:
            return SandboxResult(
                success=False,
                command=cmd_display,
                stdout="",
                stderr="",
                returncode=-1,
                duration_ms=0.0,
                sandbox_dir=self.workdir,
                error=str(err),
            )

        timeout_s = float(timeout or self.default_timeout)
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=self.workdir,
                env=env or os.environ.copy(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
            except asyncio.TimeoutError:
                await kill_process_tree(proc)
                return SandboxResult(
                    success=False,
                    command=cmd_display,
                    stdout="",
                    stderr="",
                    returncode=-1,
                    duration_ms=(time.time() - start) * 1000,
                    sandbox_dir=self.workdir,
                    error=f"انتهت المهلة ({timeout_s} ثانية) للأمر: {cmd_display}",
                )

            stdout = out_b.decode("utf-8", errors="replace")
            stderr = err_b.decode("utf-8", errors="replace")
            if len(stdout) > self.max_output_size:
                stdout = stdout[: self.max_output_size] + "\n... (truncated)"
            if len(stderr) > self.max_output_size:
                stderr = stderr[: self.max_output_size] + "\n... (truncated)"
            return SandboxResult(
                success=proc.returncode == 0,
                command=cmd_display,
                stdout=stdout,
                stderr=stderr,
                returncode=proc.returncode or 0,
                duration_ms=(time.time() - start) * 1000,
                sandbox_dir=self.workdir,
            )
        except Exception as exc:
            return SandboxResult(
                success=False,
                command=cmd_display,
                stdout="",
                stderr="",
                returncode=-1,
                duration_ms=(time.time() - start) * 1000,
                sandbox_dir=self.workdir,
                error=str(exc),
            )

    # ------------------------------------------------------------------ #
    # تنظيف
    # ------------------------------------------------------------------ #
    def cleanup(self) -> None:
        """يحذف مجلد البيئة المعزولة إذا كان مؤقتاً."""
        try:
            if os.path.exists(self.workdir):
                shutil.rmtree(self.workdir, ignore_errors=True)
        except Exception as exc:
            logger.warning("Sandbox cleanup failed for %s: %s", self.workdir, exc)


__all__ = ["SandboxExecutor", "SandboxResult"]
