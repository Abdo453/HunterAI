"""
اختبارات محول الوكلاء البرمجيين (core/coding_agent_adapter.py) — مرحلة E.
يختبر: مصفوفة القدرات، التحقق من الملف التنفيذي، تنفيذ الأمر عبر argv (لا shell string),
التحقق من مساحة العمل، استخراج diff، الإلغاء، السجل.
لا يستهدف أي نظام خارجي.
"""
import asyncio
import os
import sys
import types
import pytest

from core.coding_agent_adapter import (
    AgentCapability, CodingAgentCapabilities, CodingAgentRequest,
    CodingAgentResult, CodingAgentError, ApprovalRequired,
    CLICodingAgentAdapter, CodingAgentRegistry,
    GLOBAL_CODING_AGENT_REGISTRY,
)


class FakeProcess:
    """عملية وهمية لاختبار CLICodingAgentAdapter.run."""
    def __init__(self, stdout=b"", stderr=b"", returncode=0, should_timeout=False):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.should_timeout = should_timeout
        self.killed = False

    async def communicate(self):
        if self.should_timeout:
            raise asyncio.TimeoutError()
        return self.stdout, self.stderr

    def kill(self):
        self.killed = True


def _make_agent(**overrides):
    caps = CodingAgentCapabilities(
        agent_id="test-agent", display_name="Test Agent",
        executable="test-cli",
        supports_file_read=True,
        supports_patch_suggestion=True,
        supports_patch_apply=True,
        supports_cancellation=True,
    )
    agent = CLICodingAgentAdapter(
        agent_id="test-agent",
        executable="test-cli",
        args_template=["run", "{prompt}", "--wd", "{workspace}"],
        capabilities=caps,
    )
    for k, v in overrides.items():
        setattr(agent, k, v)
    return agent


class TestCapabilities:
    def test_has_true(self):
        caps = CodingAgentCapabilities(
            agent_id="a", display_name="A", executable="x",
            supports_file_read=True)
        assert caps.has("read_files") is True

    def test_has_false(self):
        caps = CodingAgentCapabilities(
            agent_id="a", display_name="A", executable="x",
            supports_file_read=False)
        assert caps.has("read_files") is False

    def test_has_extra(self):
        caps = CodingAgentCapabilities(
            agent_id="a", display_name="A", executable="x",
            extra=[AgentCapability(name="custom-op")])
        assert caps.has("custom-op") is True


class TestAdapterRun:
    def test_workspace_missing_raises(self):
        agent = _make_agent()
        req = CodingAgentRequest(
            agent_id="test-agent", workspace="/nonexistent-dir-xyz",
            prompt="hello")
        with pytest.raises(CodingAgentError, match="غير موجودة"):
            agent._validate_workspace(req.workspace)

    @pytest.mark.asyncio
    async def test_run_success(self, monkeypatch):
        agent = _make_agent()
        fake_proc = FakeProcess(
            stdout=b"Done\n```diff\n--- a/file.py\n+++ b/file.py\n- old\n+ new\n```\n",
            stderr=b"", returncode=0)

        async def fake_exec(*argv, **kwargs):
            assert argv[0] == "test-cli"
            # لا shell string: 모든 الوسائط كقوائم منفصلة
            assert all(isinstance(a, str) for a in argv)
            return fake_proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

        import tempfile
        ws = tempfile.mkdtemp(prefix="agent_ws_")
        try:
            req = CodingAgentRequest(
                agent_id="test-agent", workspace=ws,
                prompt="add a feature", require_diff_review=True)
            result = await agent.run(req)
            assert result.ok is True
            assert "Done" in result.output
            assert result.diff is not None
            assert "- old" in result.diff
            assert result.needs_human_review is True
            assert result.requires_approval is True
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_run_timeout(self, monkeypatch):
        agent = _make_agent()
        fake_proc = FakeProcess(should_timeout=True)

        async def fake_exec(*argv, **kwargs):
            return fake_proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

        import tempfile
        ws = tempfile.mkdtemp(prefix="agent_ws_")
        try:
            req = CodingAgentRequest(
                agent_id="test-agent", workspace=ws,
                prompt="slow task", timeout_s=1.0)
            result = await agent.run(req)
            assert result.ok is False
            assert result.error_category == "TIMEOUT"
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_run_nonzero_exit(self, monkeypatch):
        agent = _make_agent()
        fake_proc = FakeProcess(stdout=b"", stderr=b"error happened",
                                returncode=1)

        async def fake_exec(*argv, **kwargs):
            return fake_proc

        monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)

        import tempfile
        ws = tempfile.mkdtemp(prefix="agent_ws_")
        try:
            req = CodingAgentRequest(
                agent_id="test-agent", workspace=ws, prompt="fail")
            result = await agent.run(req)
            assert result.ok is False
            assert result.error_category == "NONZERO_EXIT"
            assert "error happened" in result.error
        finally:
            import shutil
            shutil.rmtree(ws, ignore_errors=True)

    @pytest.mark.asyncio
    async def test_cancel(self):
        agent = _make_agent()
        run_id = "run-123"
        agent._register_cancel(run_id)
        assert agent.is_cancelled(run_id) is False
        await agent.cancel(run_id)
        assert agent.is_cancelled(run_id) is True


class TestRegistry:
    def test_register_and_list(self):
        reg = CodingAgentRegistry()
        agent = _make_agent()
        reg.register(agent)
        caps_list = reg.list_agents()
        assert len(caps_list) == 1
        assert caps_list[0].agent_id == "test-agent"

    def test_list_by_capability(self):
        reg = CodingAgentRegistry()
        agent = _make_agent()
        reg.register(agent)
        patch_agents = reg.list_by_capability("patch_apply")
        assert len(patch_agents) == 1
        read_agents = reg.list_by_capability("test_execution")
        assert len(read_agents) == 0

    def test_global_registry_has_defaults(self):
        # السجل العالمي يُسجل وكلاء افتراضيين عند الاستيراد
        caps = GLOBAL_CODING_AGENT_REGISTRY.list_agents()
        ids = {c.agent_id for c in caps}
        assert {"claude-code", "codex-cli", "opencode"} <= ids

    def test_health_check_all(self):
        reg = CodingAgentRegistry()
        agent = _make_agent()
        reg.register(agent)
        # الملف التنفيذي غير موجود ⇒ health_check False
        health = asyncio.run(reg.health_check_all())
        assert health["test-agent"] is False

    def test_snapshot(self):
        reg = CodingAgentRegistry()
        agent = _make_agent()
        reg.register(agent)
        snap = reg.snapshot()
        assert "test-agent" in snap
        assert snap["test-agent"]["executable"] == "test-cli"


class TestResultAndError:
    def test_result_structure(self):
        r = CodingAgentResult(
            ok=True, agent_id="a", output="done",
            diff="--- a\n+++ b", needs_human_review=True)
        assert r.ok is True
        assert r.needs_human_review is True

    def test_approval_required_error(self):
        err = ApprovalRequired(agent_id="a", operation="apply_patch")
        assert err.category == "APPROVAL_REQUIRED"
        assert "human approval required" in str(err)
