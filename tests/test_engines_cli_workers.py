"""
Unit Tests for CLI Engine Workers (engines package)
Tests: argv construction, output normalization, registry, health preflight,
       worker governance (scope/policy fail-closed), runner env isolation.
"""
import json
import os

import pytest

from engines.base import EngineDriver, SecurePromptUnsupported
from engines.registry import (
    DRIVERS, available_engines, driver_for, get_driver, ModelBoundDriver,
)
from engines.runner import build_worker_env
from engines.types import EngineResult, LaunchContext, StreamStep
from engines.worker import EngineWorker, EngineWorkerConfig


# ── Registry ──────────────────────────────────────────────────────────────

class TestRegistry:
    def test_builtin_engines_registered(self):
        assert set(available_engines()) >= {"claude", "codex", "opencode"}

    def test_get_driver_unknown_raises(self):
        with pytest.raises(ValueError, match="محرك غير معروف"):
            get_driver("nonexistent-engine")

    def test_driver_for_profile_wraps_with_model(self):
        d = driver_for({"engine": "claude", "model": "claude-sonnet-4-5"})
        assert isinstance(d, ModelBoundDriver)
        argv = d.build_execute("hi")
        assert "--model" in argv
        assert "claude-sonnet-4-5" in argv


# ── argv construction ─────────────────────────────────────────────────────

class TestArgvConstruction:
    def test_claude_execute_basic(self):
        d = get_driver("claude")
        argv = d.build_execute("find the vuln")
        assert argv[0].endswith("claude") or "claude" in argv[0]
        assert "-p" in argv
        assert "--output-format" in argv

    def test_claude_execute_stdin_hides_prompt(self):
        d = get_driver("claude")
        argv = d.build_execute_stdin("secret prompt", None)
        assert "secret prompt" not in argv  # لا يظهر في جدول العمليات

    def test_claude_web_access_disabled(self):
        d = get_driver("claude")
        argv = d.build_execute("x", web_access=False)
        assert "--disallowedTools" in argv

    def test_claude_invalid_permission_mode_raises(self):
        d = get_driver("claude")
        with pytest.raises(ValueError, match="وضع صلاحيات"):
            d.build_execute("x", launch=LaunchContext(permission_mode="bogus-mode"))

    def test_codex_default_sandbox_readonly_for_workers(self):
        d = get_driver("codex")
        argv = d.build_execute("scan target")
        assert "--sandbox" in argv
        assert "read-only" in argv

    def test_codex_resume_uses_session(self):
        d = get_driver("codex")
        argv = d.build_resume("continue", "sess-123")
        assert "resume" in argv
        assert "sess-123" in argv

    def test_codex_stdin_unsupported(self):
        d = get_driver("codex")
        with pytest.raises(SecurePromptUnsupported):
            d.build_execute_stdin("x")

    def test_opencode_model_arg(self):
        d = get_driver("opencode")
        argv = d.build_execute("x", launch=LaunchContext(model="anthropic/claude"))
        assert "--model" in argv


# ── Output normalization ──────────────────────────────────────────────────

class TestNormalization:
    def test_claude_parse_stream_json(self):
        d = get_driver("claude")
        stdout = "\n".join([
            json.dumps({"type": "assistant", "message": {"content": [
                {"type": "text", "text": "found SQLi on /login"}]}}),
            json.dumps({"type": "result", "result": "done",
                        "session_id": "abc-123", "total_cost_usd": 0.012}),
        ])
        r = d.parse(stdout, "")
        assert r.ok
        assert r.session_id == "abc-123"
        assert "SQLi" in r.output_text
        assert r.cost_usd == 0.012

    def test_claude_parse_stream_line_tool_call(self):
        d = get_driver("claude")
        line = json.dumps({"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Bash", "input": {"command": "nmap -sV x"}}]}})
        step = d.parse_stream_line(line)
        assert step is not None
        assert step.kind == "tool_call"
        assert step.tool_name == "Bash"

    def test_claude_parse_garbage_fails_gracefully(self):
        d = get_driver("claude")
        r = d.parse("not json at all", "some error")
        assert not r.ok
        assert r.error

    def test_codex_parse_session_created(self):
        d = get_driver("codex")
        stdout = "\n".join([
            json.dumps({"type": "session.created", "session_id": "codex-9"}),
            json.dumps({"type": "item.completed",
                        "item": {"text": "port 443 open"}}),
        ])
        r = d.parse(stdout, "")
        assert r.ok
        assert r.session_id == "codex-9"
        assert "443" in r.output_text


# ── Worker governance (fail-closed) ───────────────────────────────────────

class _DenyingScope:
    def is_in_scope(self, target):
        return False, "target not in authorized scope"


class _AllowingScope:
    def is_in_scope(self, target):
        return True, "ok"


class TestWorkerGovernance:
    def test_worker_rejects_out_of_scope_target(self):
        w = EngineWorker(
            EngineWorkerConfig(engine="claude"),
            scope_guard=_DenyingScope(),
        )
        import asyncio
        from agents.base_agent import AgentTask
        task = AgentTask(target="http://evil.example",
                         extra={"prompt": "scan it"})
        result = asyncio.run(w.run(task))
        assert not result.success
        assert any("خارج النطاق" in e for e in result.errors)

    def test_worker_requires_prompt(self):
        w = EngineWorker(
            EngineWorkerConfig(engine="claude"),
            scope_guard=_AllowingScope(),
        )
        import asyncio
        from agents.base_agent import AgentTask
        result = asyncio.run(w.run(AgentTask(target="http://t.local")))
        assert not result.success
        assert any("prompt" in e.lower() for e in result.errors)


# ── Runner env isolation ──────────────────────────────────────────────────

class TestRunnerEnv:
    def test_build_worker_env_excludes_secrets_by_default(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
        d = get_driver("claude")
        env = build_worker_env(d)
        assert "OPENAI_API_KEY" not in env
        assert "ANTHROPIC_API_KEY" not in env

    def test_build_worker_env_merges_credential_overlay(self, monkeypatch):
        monkeypatch.setenv("PATH", os.environ.get("PATH", ""))
        d = get_driver("claude")
        env = build_worker_env(d, {"ANTHROPIC_API_KEY": "sk-explicit"})
        assert env.get("ANTHROPIC_API_KEY") == "sk-explicit"

    def test_driver_env_extra_endpoint(self):
        d = driver_for({
            "engine": "claude",
            "base_url": "https://proxy.internal",
            "api_key": "sk-test",
        })
        env = d.env_extra()
        assert env.get("ANTHROPIC_BASE_URL") == "https://proxy.internal"
        assert env.get("ANTHROPIC_API_KEY") == "sk-test"


# ── Self-check plumbing ───────────────────────────────────────────────────

class TestSelfcheck:
    def test_selfcheck_report_shape(self):
        from engines.selfcheck import SelfCheckReport
        from engines.types import HealthStatus
        rep = SelfCheckReport()
        rep.results["claude"] = HealthStatus(healthy=True)
        rep.results["codex"] = HealthStatus(healthy=False, detail="not found")
        assert rep.healthy_count == 1
        assert rep.total == 2
        d = rep.to_dict()
        assert d["healthy_count"] == 1
        assert d["results"]["codex"]["detail"] == "not found"


# ── Shared Evidence Graph integration ─────────────────────────────────────

class TestEvidenceGraphWiring:
    """الرسم البياني المشترك يسجّل نتيجة كل تشغيل ناجح/فاشل."""

    def _run_with_graph(self, monkeypatch, ok=True):
        import asyncio
        from agents.base_agent import AgentTask
        from core.shared_evidence import SharedEvidenceGraph

        async def fake_run_engine(*a, **k):
            return EngineResult(
                ok=ok, exit_code=0 if ok else 1,
                output_text="done" if ok else "boom",
                error=None if ok else "boom",
            )

        monkeypatch.setattr("engines.worker.run_engine", fake_run_engine)
        graph = SharedEvidenceGraph()
        w = EngineWorker(
            EngineWorkerConfig(engine="claude"),
            scope_guard=_AllowingScope(),
            evidence_graph=graph,
        )
        task = AgentTask(target="http://t.local",
                         extra={"prompt": "scan it"})
        result = asyncio.run(w.run(task))
        return graph, result

    def test_successful_run_records_high_confidence_fact(self, monkeypatch):
        graph, result = self._run_with_graph(monkeypatch, ok=True)
        assert result.success
        fact = graph.get_fact("engine_run:claude:http://t.local")
        assert fact is not None
        assert fact.value == "ok"
        assert fact.confidence == 1.0
        assert fact.metadata["engine"] == "claude"

    def test_failed_run_records_low_confidence_fact(self, monkeypatch):
        graph, result = self._run_with_graph(monkeypatch, ok=False)
        assert not result.success
        fact = graph.get_fact("engine_run:claude:http://t.local")
        assert fact is not None
        assert fact.value == "failed"
        assert fact.confidence < 0.5

    def test_worker_without_graph_is_unaffected(self):
        w = EngineWorker(
            EngineWorkerConfig(engine="claude"),
            scope_guard=_AllowingScope(),
        )
        assert w.evidence_graph is None
