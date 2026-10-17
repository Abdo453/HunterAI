"""الكلاس الأساسي لكل محرك CLI (EngineDriver).

كل محرك = Adapter رقيق يترجم مهمة واحدة إلى argv محدّد، ويعيد تطبيع المخرجات.
الفكرة: الـ scheduler لا يعرف تفاصيل أي CLI بعينه، فقط هذا العقد.
"""
from __future__ import annotations

import abc
import os
import platform
import shutil
import subprocess
import time
from typing import Dict, List, Optional, Tuple

from engines.types import (
    CAP_RESUME,
    CAP_SECURE_PROMPT,
    CAP_STREAMING,
    CAP_WEB_ISOLATION,
    EngineResult,
    LaunchContext,
    StreamStep,
)

_IS_WINDOWS = platform.system() == "Windows"


class SecurePromptUnsupported(RuntimeError):
    """المحرك لا يدعم نقل prompt سريًا عبر stdin."""


class EngineDriver(abc.ABC):
    """محرك CLI: مسؤول عن argv + التطبيع + فحص الصحة فقط.

    سمات يعلنها كل محرك للـ scheduler:
    - secure_prompt_transport: prompt سريًا عبر stdin (لا يظهر في جدول العمليات)
    - persistent_stdin_prompt: يقبل stdin دون إتلاف جلسة محفوظة
    - offline_web_isolation: يستطيع تعطيل أدوات الويب الأصلية للـ CLI
    """

    name: str = ""
    display_name: str = ""
    # متغير البيئة الذي يُجاوز به المعرّف الافتراضي (MUTEKI-style: ENGINE_BIN)
    env_bin_override: str = ""

    secure_prompt_transport: bool = False
    persistent_stdin_prompt: bool = False
    offline_web_isolation: bool = False

    _bin: Optional[str] = None
    _HELLO_PROMPT = "Reply with exactly: OK"
    _HELLO_TIMEOUT = 120
    _HELLO_RETRIES = 2

    @property
    def capabilities(self) -> List[str]:
        caps: List[str] = [CAP_RESUME] if self.supports_resume else []
        if self.secure_prompt_transport:
            caps.append(CAP_SECURE_PROMPT)
        if self.supports_streaming:
            caps.append(CAP_STREAMING)
        if self.offline_web_isolation:
            caps.append(CAP_WEB_ISOLATION)
        return caps

    supports_resume: bool = False
    supports_streaming: bool = False

    # ── محلّل الثنائي ─────────────────────────────────────────────────────
    @property
    def bin(self) -> str:
        override = os.environ.get(self.env_bin_override, "").strip() if self.env_bin_override else ""
        if override:
            return override
        if self._bin is None:
            self._bin = self._resolve_bin()
        return self._bin

    def _resolve_bin(self) -> str:
        found = shutil.which(self.name)
        return found or self.name  # يُترك للـ FileNotFoundError ليظهر رسالة واضحة

    def version_argv(self) -> List[str]:
        return [self.bin, "--version"]

    # ── بناء argv ─────────────────────────────────────────────────────────
    @abc.abstractmethod
    def build_execute(
        self,
        prompt: str,
        session: Optional[str] = None,
        *,
        web_access: bool = True,
        stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        """argv لتشغيل جديد بمهام واحدة."""

    def build_execute_stdin(
        self,
        prompt: str,
        session: Optional[str] = None,
        *,
        web_access: bool = True,
        stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        """argv يستقبل الـ prompt عبر stdin (الأسرع أمانًا للأسرار)."""
        raise SecurePromptUnsupported(
            f"{self.name} لا يدعم نقل prompt عبر stdin بشكل غير محفوظ")

    def build_resume(
        self,
        prompt: str,
        session: str,
        *,
        web_access: bool = True,
        stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        """argv لاستئناف جلسة سابقة بمتابعة جديدة."""
        raise NotImplementedError(f"{self.name} لا يدعم استئناف الجلسات")

    # ── التطبيع ───────────────────────────────────────────────────────────
    @abc.abstractmethod
    def parse(self, stdout: str, stderr: str) -> EngineResult:
        """تطبيع مخرجات stdout النهائية إلى EngineResult."""

    def parse_stream_line(self, line: str) -> Optional[StreamStep]:
        """تحويل سطر بثّ حيّ واحد إلى StreamStep (أو None لتجاهله)."""
        return None

    def env_extra(self) -> Dict[str, str]:
        """متغيرات بيئة افتراضية لكل تشغيل لهذا المحرك."""
        return {}

    def validate_launch(self, launch: LaunchContext) -> None:
        """رمي ValueError إذا كان السياق غير مدعوم لهذا المحرك."""
        return

    # ── فحص الصحة ─────────────────────────────────────────────────────────
    def _hello_argv(self) -> List[str]:
        """argv لاستProbe حقيقي بجولة واحدة؛ [] يعني الرجوع لـ --version."""
        return []

    def _hello_ok(self, proc: "subprocess.CompletedProcess") -> bool:
        return proc.returncode == 0 and bool((proc.stdout or "").strip())

    def version_string(self) -> str:
        try:
            r = subprocess.run(
                self.version_argv(), capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=20,
                stdin=subprocess.DEVNULL)
            if r.returncode == 0:
                return (r.stdout or "").strip().splitlines()[0][:80]
        except (OSError, subprocess.TimeoutExpired, IndexError):
            pass
        return ""

    def health_detail(self, *, env: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
        """(صحي، التفاصيل) — Probe بجولة حقيقية يكشف مشاكل auth/quota."""
        argv = self._hello_argv()
        if not argv:
            try:
                r = subprocess.run(
                    self.version_argv(), capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=20,
                    stdin=subprocess.DEVNULL, env=env)
                if r.returncode == 0:
                    return True, ""
                return False, f"--version فشل (exit {r.returncode})"
            except FileNotFoundError:
                return False, "الثنائي غير موجود في PATH"
            except subprocess.TimeoutExpired:
                return False, "انتهت مهلة فحص الإصدار"
            except OSError as exc:
                return False, str(exc)[:160]

        last = "لا رد"
        for attempt in range(self._HELLO_RETRIES + 1):
            try:
                r = subprocess.run(
                    argv, capture_output=True, text=True,
                    encoding="utf-8", errors="replace",
                    timeout=self._HELLO_TIMEOUT, env=env)
            except FileNotFoundError:
                return False, "الثنائي غير موجود في PATH"
            except subprocess.TimeoutExpired:
                last = f"انتهت مهلة probe (>{self._HELLO_TIMEOUT}s)"
            except OSError as exc:
                last = str(exc)[:160]
            else:
                if self._hello_ok(r):
                    return True, ""
                if r.returncode != 0:
                    tail = (r.stderr or r.stdout or "").strip().splitlines()
                    last = f"hello خرج بـ {r.returncode}" + (f": {tail[-1][:300]}" if tail else "")
                else:
                    last = "hello أعاد بدون رد نموذج"
            if attempt < self._HELLO_RETRIES:
                time.sleep(1.0)
        return False, last

    def healthcheck(self, *, env: Optional[Dict[str, str]] = None) -> bool:
        return self.health_detail(env=env)[0]
