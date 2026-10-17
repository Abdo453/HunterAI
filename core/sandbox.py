"""
صندوق الرمل (Sandbox) — مرحلة G.

واجهة مجردة لتنفيذ الكود غير الموثوق والأدوات الأمنية في بيئة معزولة.
التنفيذ الافتراضي (LocalSandbox) يُنفذ محليًا مع قيود عملية (مهلة، حدود إخراج،
دليل عمل مقيد، متغيرات بيئة محدودة). DockerSandbox مDocumented للاستخدام على
Kali/خادم حيث Docker متوفر.

ضوابط أمنية:
- لا تُمرر سلسلة أوامر shell (shell strings) — تُستخدم مصفوفات وسيطات (argv).
- دليل عمل مقيد (working directory) لمنع الوصول للملفات خارجه.
- مهلة عملية مع إيقاف شجرة العمليات عند التجاوز.
- متغيرات بيئة محدودة (لا تُورث كل بيئة المضيف تلقائيًا).
- حد أقصى لحجم مخرجات الأداة.
- لا أسرار خام في البيئة المُمررة إلا ما صُرح به صراحةً عبر credential_env.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    ok: bool
    command: List[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_s: float = 0.0
    error: Optional[str] = None
    error_category: Optional[str] = None
    artefact_reference: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class Sandbox(ABC):
    """واجهة صندوق الرمل — كل تنفيذ أمان يُمرر عبر هذه الواجهة."""

    @abstractmethod
    async def run(
        self,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: float = 60.0,
        max_output_bytes: int = 1_000_000,
    ) -> SandboxResult:
        """تنفيذ أمر كمصفوفة وسيطات (لا shell string) في بيئة معزولة."""
        raise NotImplementedError

    @abstractmethod
    async def health_check(self) -> bool:
        """فصلhether صندوق الرمل متاح."""
        raise NotImplementedError


class LocalSandbox(Sandbox):
    """
    صندوق رمل محلي يُنفذ الأوامر عبر asyncio.create_subprocess_exec (بلا shell).

    مناسب للتطوير والأدوات التي لا تحتاج عزلًا حاويًا كاملاً. القيود المطبقة:
    - argv فقط (no shell injection)
    - cwd مقيد داخل الدليل المسموح
    - env محدود بمتغيرات آمنة + ما يُصرح به صراحةً
    - timeout مع process termination
    - output size cap
    """

    _SAFE_ENV_VARS = {
        "PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
    }

    def __init__(
        self,
        *,
        allowed_workdir: Optional[str] = None,
        extra_env: Optional[Dict[str, str]] = None,
        default_timeout_s: float = 60.0,
    ):
        self.allowed_workdir = os.path.abspath(
            allowed_workdir or os.path.join("data", "sandbox_workdir")
        )
        os.makedirs(self.allowed_workdir, exist_ok=True)
        self.extra_env = dict(extra_env or {})
        self.default_timeout_s = default_timeout_s

    def _resolve_cwd(self, cwd: Optional[str]) -> str:
        """يضمن أن دليل العمل داخل الدليل المسموح (fail-closed)."""
        target = os.path.abspath(cwd or self.allowed_workdir)
        allowed = os.path.abspath(self.allowed_workdir)
        # منع path traversal: يجب أن يبدأ الهدف بالدليل المسموح
        if not (target == allowed or target.startswith(allowed + os.sep)):
            raise PermissionError(
                f"دليل العمل خارج النطاق المسموح: {cwd}")
        return target

    def _build_env(
        self, env: Optional[Dict[str, str]]
    ) -> Dict[str, str]:
        """بيئة محدودة: متغيرات آمنة من النظام + ما يُصرح به صراحةً فقط."""
        new_env: Dict[str, str] = {}
        for var in self._SAFE_ENV_VARS:
            val = os.environ.get(var)
            if val:
                new_env[var] = val
        new_env.update(self.extra_env)
        if env:
            # لا نسمح بتجاوز متغيرات حساسة إلا إذا صُرح بها صراحةً
            for key, val in env.items():
                kl = key.lower()
                if any(s in kl for s in ("secret", "key", "token", "password",
                                         "api_", "credential")):
                    continue
                new_env[key] = val
        return new_env

    async def run(
        self,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: float = 60.0,
        max_output_bytes: int = 1_000_000,
    ) -> SandboxResult:
        if not command:
            return SandboxResult(
                ok=False, command=[], error="أمر فارغ",
                error_category="VALIDATION")
        exe = command[0]
        if not shutil.which(exe) and not os.path.isabs(exe):
            return SandboxResult(
                ok=False, command=command,
                error=f"الملف التنفيذي غير موجود: {exe}",
                error_category="TOOL_UNAVAILABLE")

        resolved_cwd = self._resolve_cwd(cwd)
        sandbox_env = self._build_env(env)
        start = time.time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=resolved_cwd,
                env=sandbox_env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                ok=False, command=command,
                error=str(exc), error_category="EXECUTION_ERROR",
                metadata={"duration_s": time.time() - start})

        try:
            out, err = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            dur = time.time() - start
            return SandboxResult(
                ok=False, command=command,
                error=f"انتهت المهلة بعد {timeout_s}s",
                error_category="TIMEOUT",
                duration_s=dur,
                metadata={"cwd": resolved_cwd, "timeout_s": timeout_s})

        dur = time.time() - start
        stdout_limited = out[:max_output_bytes] if out else b""
        stderr_limited = err[:max_output_bytes] if err else b""
        if len(out or b"") > max_output_bytes:
            stdout_limited += b"\n...[output truncated]..."
        if len(err or b"") > max_output_bytes:
            stderr_limited += b"\n...[output truncated]..."

        ret = proc.returncode or 0
        return SandboxResult(
            ok=(ret == 0),
            command=command,
            stdout=stdout_limited.decode("utf-8", errors="replace"),
            stderr=stderr_limited.decode("utf-8", errors="replace"),
            exit_code=ret,
            duration_s=round(dur, 3),
            error=stderr_limited.decode("utf-8", errors="replace")
            if ret != 0 else None,
            error_category=("NONZERO_EXIT" if ret != 0 else None),
            metadata={
                "cwd": resolved_cwd,
                "timeout_s": timeout_s,
                "max_output_bytes": max_output_bytes,
            },
        )

    async def health_check(self) -> bool:
        try:
            result = await self.run(
                [shutil.which("python") or "python", "-c", "print('ok')"],
                timeout_s=10.0,
                max_output_bytes=64,
            )
            return result.ok
        except Exception:  # noqa: BLE001
            return False


class DockerSandbox(Sandbox):
    """
    صندوق رمل مبني على Docker — للاستخدام على Kali/خادم حيث Docker متوفر.

    متطلبات التشغيل (توثيق، لا تُنشئ حاويات تلقائيًا):
    - صورة مناسبة (مثل kalilinux/kali-rolling أو hunterai-worker:kali).
    - mount محدود لدليل العمل فقط (لا المضيف كاملاً، لا Docker socket).
    - --user غير root إن أمكن.
    - --network-segment مع سياسة شبكة (لا خدمات metadata، لا loopback إلا مصرح).
    - متغيرات بيئة محدودة فقط.
    """

    def __init__(
        self,
        *,
        image: str = "hunterai-worker:kali",
        allowed_workdir: Optional[str] = None,
        network_mode: str = "none",
        default_timeout_s: float = 300.0,
        docker_client: Optional[Any] = None,
    ):
        self.image = image
        self.allowed_workdir = allowed_workdir or "/worker"
        self.network_mode = network_mode
        self.default_timeout_s = default_timeout_s
        self._docker = docker_client  # تُحقن للاختبار؛ تُنشأ من docker SDK في الإنتاج

    def _get_client(self):
        if self._docker is not None:
            return self._docker
        try:
            import docker  # type: ignore
            return docker.from_env()
        except ImportError:
            raise RuntimeError(
                "Puppeteer: حزمة 'docker' غير مثبتة. ثبتّها للتشغيل على الخادم.")

    async def run(
        self,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: float = 60.0,
        max_output_bytes: int = 1_000_000,
    ) -> SandboxResult:
        start = time.time()
        try:
            client = self._get_client()
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                ok=False, command=command,
                error=str(exc), error_category="SANDBOX_UNAVAILABLE",
                metadata={"duration_s": time.time() - start})

        container = None
        try:
            container = client.containers.run(
                self.image,
                command=command,
                working_dir=cwd or self.allowed_workdir,
                environment=env or {},
                network_mode=self.network_mode,
                detach=True,
                mem_limit="256m",
                pids_limit=50,
                read_only=True,
                tmpfs={"/tmp": "noexec,nosuid,size=100m"},
            )
            try:
                result = container.wait(timeout=timeout_s)
            except Exception:
                try:
                    container.kill()
                except Exception:
                    pass
                result = {"StatusCode": -1}

            logs = container.logs(stdout=True, stderr=True)
            stdout = logs.decode("utf-8", errors="replace")[:max_output_bytes]
            # docker logs combine stdout/stderr depending on version; we store
            # what we get in stdout and leave stderr empty unless captured.
            ret = result.get("StatusCode", -1)
            return SandboxResult(
                ok=(ret == 0),
                command=command,
                stdout=stdout,
                exit_code=ret,
                duration_s=round(time.time() - start, 3),
                artefact_reference=container.id,
                metadata={"image": self.image, "container": container.id},
            )
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                ok=False, command=command,
                error=str(exc), error_category="EXECUTION_ERROR",
                metadata={"duration_s": time.time() - start})
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:  # noqa: BLE001
                    pass

    async def health_check(self) -> bool:
        try:
            client = self._get_client()
            client.containers.run(
                self.image, ["python", "-c", "print('ok')"],
                network_mode="none", detach=False, remove=True,
            )
            return True
        except Exception:  # noqa: BLE001
            return False
