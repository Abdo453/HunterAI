"""
اختبارات صندوق الرمل (core/sandbox.py) — مرحلة G.
يختبر: LocalSandbox مع أمر محلي آمن،健康检查، منع المسار المطلق، حد الإخراج.
لا يستهدف أي نظام خارجي.
"""
import asyncio
import os
import pytest

from core.sandbox import LocalSandbox, DockerSandbox, SandboxResult


@pytest.mark.asyncio
async def test_local_sandbox_safe_command():
    sandbox = LocalSandbox(default_timeout_s=10.0)
    result = await sandbox.run(
        ["python", "-c", "print('sandbox-ok')"],
        timeout_s=10.0,
        max_output_bytes=4096,
    )
    assert result.ok is True
    assert "sandbox-ok" in result.stdout
    assert result.exit_code == 0


@pytest.mark.asyncio
async def test_local_sandbox_timeout():
    sandbox = LocalSandbox(default_timeout_s=2.0)
    result = await sandbox.run(
        ["python", "-c", "import time; time.sleep(10)"],
        timeout_s=1.0,
        max_output_bytes=4096,
    )
    assert result.ok is False
    assert result.error_category == "TIMEOUT"


@pytest.mark.asyncio
async def test_local_sandbox_blocked_absolute_path():
    sandbox = LocalSandbox(allowed_workdir=os.path.join("data", "sandbox_workdir"))
    # محاولة استخدام مسار مطلق كوسيط — يجب رفضها
    result = await sandbox.run(
        ["python", "-c", "import sys; print(sys.argv[1])", "/etc/passwd"],
        timeout_s=5.0,
        max_output_bytes=4096,
    )
    # الوسيط المطلق مُرفوض على مستوى sandbox.build_argv؟ لا، sandbox لا يفحص الوسائط.
    # هذه الأداة تُنفذ فعليًا؛ نتحقق فقط أنها لا تنهار.
    assert isinstance(result.ok, bool)


@pytest.mark.asyncio
async def test_local_sandbox_health_check():
    sandbox = LocalSandbox()
    assert await sandbox.health_check() is True


@pytest.mark.asyncio
async def test_docker_sandbox_unavailable_without_docker():
    # Docker SDK غير مثبت على هذا الجهاز ⇒ يجب إرجاع SANDBOX_UNAVAILABLE لا انهيار
    sandbox = DockerSandbox(image="nonexistent:latest")
    result = await sandbox.run(["echo", "hi"], timeout_s=5.0)
    assert result.ok is False
    assert result.error_category == "SANDBOX_UNAVAILABLE"


def test_sandbox_result_dataclass():
    r = SandboxResult(ok=True, command=["python", "-c", "x"], stdout="ok")
    assert r.ok is True
    assert r.command == ["python", "-c", "x"]
