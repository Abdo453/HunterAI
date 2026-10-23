# -*- coding: utf-8 -*-
"""
اختبارات إدارة أدوات النظام (Phase 6 — tool_mgmt).
لا تنفيذ حقيقي لتثبيت هنا: executors وprobes مزيفة تمامًا.
القواعد: لا تثبيت صامت، الإثبات = probe READY (نص exit code لا يعني شيئًا).
"""
import json

import pytest

from core.readiness.tool_mgmt import (
    InstallPlan,
    InstallStep,
    NotApprovedError,
    apply_plan,
    build_installation_plan,
    load_installation_plan,
    plan_from_readiness_artifact,
    save_installation_plan,
)


def _plan(required=("ffuf", "nuclei"), platform="windows"):
    return build_installation_plan(
        missing_tools=["ffuf", "nuclei", "sqlmap", "xray_weird"],
        required_tools=list(required),
        target_platform=platform,
    )


class TestBuildPlan:
    def test_ordering_by_channel(self):
        plan = _plan()
        channels = [s.channel for s in plan.steps]
        go_idx = [i for i, c in enumerate(channels) if c == "go"]
        pipx_idx = [i for i, c in enumerate(channels) if c == "pipx"]
        assert go_idx and pipx_idx
        assert max(go_idx) < min(pipx_idx), "apt/go يجب أن تسبق pipx"

    def test_required_flags_from_manifest_list(self):
        plan = build_installation_plan(
            missing_tools=["ffuf", "sqlmap"], required_tools=["ffuf"],
        )
        by_tool = {s.tool: s for s in plan.steps}
        assert by_tool["ffuf"].required is True
        assert by_tool["sqlmap"].required is False

    def test_unknown_tool_not_fabricated(self):
        plan = _plan()
        assert not any(s.tool == "xray_weird" for s in plan.steps)
        assert any("xray_weird" in n for n in plan.notes), \
            "المجهول يُذكر في notes ولا يُختلق له أمر"

    def test_windows_platform_adds_prerequisite(self):
        plan = _plan(platform="windows")
        assert plan.prerequisites, "Windows host يحتاج WSL/Kali prerequisite hint"
        plan2 = build_installation_plan(missing_tools=[], required_tools=[], target_platform="windows")
        assert not plan2.prerequisites

    def test_no_tools_no_steps(self):
        plan = build_installation_plan(missing_tools=[], required_tools=[])
        assert plan.steps == [] and plan.summary["steps"] == 0


class TestApplyGuards:
    def test_apply_without_approval_raises(self):
        plan = _plan()
        with pytest.raises(NotApprovedError):
            apply_plan(plan, approved=False, executor=lambda c: 0)

    def test_verified_only_when_probe_ready(self):
        """القاعدة الجوهرية: الأمر نجح (exit=0) لكن probe فشل → NOT verified."""
        plan = _plan()

        def fake_executor(command):
            return 0  # التثبيت يقول تم

        def fake_probe(tool):
            return {"status": "MISSING", "name": tool}

        result = apply_plan(plan, approved=True, executor=fake_executor, probe_fn=fake_probe)
        assert all(s.executed for s in result.steps)
        assert not any(s.verified for s in result.steps), \
            "exit=0 وحده لا يثبت شيئًا — الـ probe فقط"
        assert result.approved is True
        assert all(s.probed_after == "MISSING" for s in result.steps)

    def test_verified_when_probe_ready(self):
        plan = build_installation_plan(missing_tools=["ffuf"], required_tools=["ffuf"])
        result = apply_plan(
            plan, approved=True,
            executor=lambda c: 0,
            probe_fn=lambda tool: {"status": "READY", "detail": "mock"},
        )
        assert result.steps[0].verified is True
        assert result.steps[0].probed_after == "READY"
        assert result.summary["verified"] == 1

    def test_executor_crash_marks_step_failed(self):
        plan = build_installation_plan(missing_tools=["nuclei"], required_tools=["nuclei"])
        def boom(command):
            raise OSError("sandbox denied")
        result = apply_plan(plan, approved=True, executor=boom,
                            probe_fn=lambda t: {"status": "MISSING"})
        step = result.steps[0]
        assert step.executed is False
        assert step.verified is False
        assert "denied" in step.note


class TestArtifact:
    def test_save_load_roundtrip(self, tmp_path):
        plan = _plan()
        path = save_installation_plan(plan, tmp_path)
        loaded = load_installation_plan(path)
        assert loaded.target_platform == plan.target_platform
        assert [s.tool for s in loaded.steps] == [s.tool for s in plan.steps]
        assert [s.command for s in loaded.steps] == [s.command for s in plan.steps]
        assert (tmp_path / "tool_installation_plan.json").exists()

    def test_plan_from_readiness_artifact(self, tmp_path):
        report = {
            "strict_ready": False,
            "blocked": [{"name": "ffuf"}, {"name": "nuclei"}],
            "results": [
                {"name": "ffuf", "status": "MISSING", "component": "kali_tool"},
                {"name": "nuclei", "status": "MISSING", "component": "kali_tool"},
                {"name": "nmap", "status": "READY", "component": "kali_tool"},
                {"name": "ollama_server", "status": "MISSING", "component": "ollama"},
            ],
        }
        rp = tmp_path / "report.json"
        rp.write_text(json.dumps(report), encoding="utf-8")
        plan = plan_from_readiness_artifact(rp)
        tools = [s.tool for s in plan.steps]
        assert tools == ["ffuf", "nuclei"], "kali_tool MISSING فقط (ollama ليس أداة)، وREADY لم يُعامل مفقودًا"
        assert all(s.required for s in plan.steps)
        assert any("strict_ready=False" in n for n in plan.notes)
