"""مشغّل المحركات غير المتزامن — قلب تنفيذ الوكلاء.

مسؤول عن: بناء البيئة الآمنة، حقن الأسرار عبر env (وليس argv)، تشغيل
subprocess مع timeout وإلغاء، بثّ الخطوات الحيّة، وتطبيع النتيجة النهائية.
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import AsyncIterator, Callable, Dict, Optional

from engines.base import EngineDriver, SecurePromptUnsupported
from engines.types import EngineResult, LaunchContext, StreamStep

logger = logging.getLogger(__name__)

# بيئة افتراضية معزولة: لا نمرّر متغيرات أسرار الجلسة إلا ما طُلب صراحة
_BASE_ENV_KEYS = (
    "PATH", "HOME", "USERPROFILE", "SystemRoot", "WINDIR", "COMSPEC",
    "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "LANG", "LC_ALL",
    "NODE_OPTIONS", "npm_config_registry",
)


def build_worker_env(
    driver: EngineDriver,
    extra: Optional[Dict[str, str]] = None,
    *,
    inherit_all: bool = False,
) -> Dict[str, str]:
    """بناء بيئة subprocess: أساس أنظمة صغير + متغيرات المحرك + الحسابات.

    الأسرار لا تُمرَّر أبدًا كأوامر argv (تظهر في جدول العمليات) بل عبر env.
    """
    if inherit_all:
        env = dict(os.environ)
    else:
        env = {k: os.environ[k] for k in _BASE_ENV_KEYS if k in os.environ}
    env.update(driver.env_extra())
    if extra:
        env.update(extra)
    return env


async def run_engine(
    driver: EngineDriver,
    prompt: str,
    *,
    session: Optional[str] = None,
    resume: bool = False,
    web_access: bool = True,
    stream: bool = False,
    launch: Optional[LaunchContext] = None,
    env_extra: Optional[Dict[str, str]] = None,
    timeout_s: float = 1800.0,
    cwd: str = "",
    on_step: Optional[Callable[[StreamStep], None]] = None,
    use_stdin: bool = True,
    inherit_all_env: bool = False,
    input_text: Optional[str] = None,
) -> EngineResult:
    """تشغيل مهمة واحدة على محرك وإعادة نتيجة مُطبَّعة.

    - resume=True يستأنف الجلسة عبر build_resume.
    - use_stdin=True يفضّل نقل prompt عبر stdin (أمان الأسرار) إن دعم المحرك.
    - on_step تُستدعى لكل خطوة حيّة عند stream=True.
    - input_text يُمرَّر كـ stdin إضافي (مثل ملف تحدي).
    """
    launch = launch or LaunchContext()
    started = time.time()

    if resume and session:
        argv = driver.build_resume(
            prompt, session, web_access=web_access, stream=stream, launch=launch)
    else:
        argv = driver.build_execute(
            prompt, session, web_access=web_access, stream=stream, launch=launch)
        if use_stdin and driver.secure_prompt_transport:
            try:
                argv = driver.build_execute_stdin(
                    prompt, session, web_access=web_access, stream=stream,
                    launch=launch)
            except SecurePromptUnsupported:
                pass  # الرجوع لـ argv — غير سري لكنه يعمل

    env = build_worker_env(driver, env_extra, inherit_all=inherit_all_env)
    stdin_text = None
    if "--" not in argv:  # الـ prompt لم يُمرَّر كمعلمة ⇒ نُرسله عبر stdin
        stdin_text = prompt

    logger.info("engine.run start: %s (timeout=%.0fs)", driver.name, timeout_s)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=cwd or None,
        )
    except FileNotFoundError:
        return EngineResult(
            ok=False, error=f"ثنائي المحرك غير موجود: {argv[0]}",
            duration_s=time.time() - started)
    except OSError as exc:
        return EngineResult(
            ok=False, error=f"فشل تشغيل المحرك: {exc}",
            duration_s=time.time() - started)

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    async def _pump_stdout() -> None:
        assert proc.stdout is not None
        if stream and driver.supports_streaming:
            while True:
                line_bytes = await proc.stdout.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace")
                stdout_chunks.append(line)
                if on_step is not None:
                    try:
                        step = driver.parse_stream_line(line)
                        if step is not None:
                            on_step(step)
                    except Exception:  # noqa: BLE001 — خطوة بثّ فاسدة لا توقف المهمة
                        pass
        else:
            data = await proc.stdout.read()
            stdout_chunks.append(data.decode("utf-8", errors="replace"))

    async def _pump_stderr() -> None:
        assert proc.stderr is not None
        data = await proc.stderr.read()
        stderr_chunks.append(data.decode("utf-8", errors="replace"))

    async def _feed_stdin() -> None:
        if proc.stdin is None:
            return
        try:
            payload = (input_text + "\n" if input_text else "") + (stdin_text or "")
            proc.stdin.write(payload.encode("utf-8"))
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            try:
                proc.stdin.close()
            except Exception:  # noqa: BLE001
                pass

    tasks = [
        asyncio.create_task(_pump_stdout()),
        asyncio.create_task(_pump_stderr()),
    ]
    if stdin_text is not None or input_text is not None:
        tasks.append(asyncio.create_task(_feed_stdin()))

    timed_out = False
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks), timeout=timeout_s)
        await proc.wait()
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
    except asyncio.CancelledError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        raise

    stdout = "".join(stdout_chunks)
    stderr = "".join(stderr_chunks)
    duration = time.time() - started

    if timed_out:
        return EngineResult(
            ok=False, error=f"انتهت مهلة المحرك ({timeout_s:.0f}s)",
            output_text=stdout[-2000:], duration_s=duration)

    result = driver.parse(stdout, stderr)
    result.exit_code = proc.returncode
    result.duration_s = duration
    if proc.returncode != 0 and not result.error:
        result.error = f"خرج برمز {proc.returncode}: {(stderr or stdout).strip()[-300:]}"
        result.ok = False
    return result


async def stream_engine(
    driver: EngineDriver,
    prompt: str,
    **kwargs,
) -> AsyncIterator[StreamStep]:
    """واجهة بثّ اختيارية: تُنتج الخطوات الحية ثم تُسلّم النتيجة النهائية.

    تستخدم نفس run_engine لكن تجمع الخطوات في قائمة قنوات بسيطة.
    """
    steps: asyncio.Queue = asyncio.Queue()
    sentinel = object()

    def _on_step(step: StreamStep) -> None:
        try:
            steps.put_nowait(step)
        except asyncio.QueueFull:
            pass

    async def _runner() -> EngineResult:
        return await run_engine(driver, prompt, on_step=_on_step, stream=True, **kwargs)

    runner_task = asyncio.create_task(_runner())
    while True:
        done, _ = await asyncio.wait(
            {runner_task}, timeout=0.05)
        try:
            step = steps.get_nowait()
            yield step
        except asyncio.QueueEmpty:
            if runner_task in done:
                # استنزاف ما تبقى في الطابور
                while True:
                    try:
                        yield steps.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                return
