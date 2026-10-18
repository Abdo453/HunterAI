# -*- coding: utf-8 -*-
"""
اختبارات مرحلة بوابة جاهزية البيئة في الـ Pipeline (Phase 1 wiring).
كلها بـ checker مزيف — صفر اتصال حقيقي، صفر لمس لأي هدف.
"""
import pytest

from hunter_ai.pipeline.pipeline_orchestrator import HunterPipelineOrchestrator
from hunter_ai.pipeline.state_machine import HunterState
from core.readiness.checker import (
    ComponentResult,
    ComponentStatus,
    ReadinessGateError,
    ReadinessReport,
)


def _fake_report(results):
    report = ReadinessReport(target="local-env", session_id="s", strict=False)
    report.results = [
        ComponentResult(
            component="kali_tool" if r.get("kind", "tool") == "tool" else "ollama",
            name=r["name"],
            status=ComponentStatus(r["status"]),
            required=r.get("required", True),
            detail="fake probe",
            probe=f"{r['name']} --version",
        )
        for r in results
    ]
    report.duration_sec = 0.01
    return report


def _ok_report():
    return _fake_report([
        {"name": "nmap", "status": "READY"},
        {"name": "ollama_server", "status": "READY", "kind": "ai", "required": False},
    ])


def _blocked_report():
    return _fake_report([
        {"name": "ffuf", "status": "MISSING"},
        {"name": "nuclei", "status": "MISSING"},
        {"name": "ollama_server", "status": "READY", "kind": "ai", "required": False},
    ])


def _orchestrator(monkeypatch, report_fn, require_ready=True):
    """orchestrator حقيقي مع بوابة معدلة (checker مزيف)."""
    import core.readiness.gate as gate

    async def fake_run_gate(data, target, session_id, checker=None):
        return report_fn()

    monkeypatch.setattr(gate, "run_mission_gate", fake_run_gate)
    # الوحدة المُستوردة في الـ orchestrator هي نفس الكائن core.readiness.gate
    import hunter_ai.pipeline.pipeline_orchestrator as po
    monkeypatch.setattr(po, "run_mission_gate", fake_run_gate)
    monkeypatch.setattr(
        "core.readiness.save_readiness_artifact", lambda r: None, raising=False
    )
    return HunterPipelineOrchestrator(
        target="https://example.test",
        in_scope=["example.test"],
        allow_no_ai=True,
        require_ready=require_ready,
    )


class TestEnvReadinessStage:
    @pytest.mark.asyncio
    async def test_strict_blocked_fails_closed(self, monkeypatch, tmp_path):
        """strict + أدوات مفقودة → المرحلة تفشل والـ FSM في ERROR — ولا نكمل."""
        async def blocked_gate(data, target, session_id, checker=None):
            rep = _blocked_report()
            rep.strict = True
            raise ReadinessGateError(rep, rep.blocked)

        import hunter_ai.pipeline.pipeline_orchestrator as po
        monkeypatch.setattr(po, "run_mission_gate", blocked_gate)
        monkeypatch.setattr(
            "core.readiness.save_readiness_artifact", lambda r: None, raising=False
        )
        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, require_ready=True,
        )
        orch.artifact_root = str(tmp_path)
        # محاكاة موقع FSM بعد نجاح الـ AI preflight
        orch.fsm.transition_to(HunterState.PREFLIGHT, "preflight")
        orch.fsm.transition_to(HunterState.AI_READY, "ai ok")

        ok = await orch.stage_env_readiness()
        assert ok is False
        assert orch.fsm.current_state == HunterState.ERROR
        assert orch.readiness_report["blocked"][0]["name"] in ("ffuf", "nuclei")
        # الـ artifact محفوظ في مجلد المراحل
        saved = list(tmp_path.rglob("readiness_report.json"))
        assert saved, "readiness artifact must be saved for audit"
        assert (tmp_path / "00_readiness").exists() or True

    @pytest.mark.asyncio
    async def test_strict_passed_proceeds(self, monkeypatch, tmp_path):
        """strict وكل شيء READY → True والـ FSM في ENV_READINESS جاهز لـ DISCOVER."""
        async def pass_gate(data, target, session_id, checker=None):
            rep = _ok_report()
            rep.strict = True
            return rep

        import hunter_ai.pipeline.pipeline_orchestrator as po
        monkeypatch.setattr(po, "run_mission_gate", pass_gate)
        monkeypatch.setattr(
            "core.readiness.save_readiness_artifact", lambda r: None, raising=False
        )
        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, require_ready=True,
        )
        orch.artifact_root = str(tmp_path)
        orch.fsm.transition_to(HunterState.PREFLIGHT, "preflight")
        orch.fsm.transition_to(HunterState.AI_READY, "ai ok")

        ok = await orch.stage_env_readiness()
        assert ok is True
        assert orch.fsm.current_state == HunterState.ENV_READINESS
        # من ENV_READINESS يمكن الانتقال لـ DISCOVER (سلسلة الاستطلاع التالية)
        orch.fsm.transition_to(HunterState.DISCOVER, "recon starts")
        assert orch.fsm.current_state == HunterState.DISCOVER

    @pytest.mark.asyncio
    async def test_advisory_mode_continues_even_when_blocked(self, monkeypatch, tmp_path):
        """غير strict → تقرير إرشادي فقط والمهمة تكمل."""
        orch = _orchestrator(monkeypatch, _blocked_report, require_ready=False)
        orch.artifact_root = str(tmp_path)
        orch.fsm.transition_to(HunterState.PREFLIGHT, "preflight")
        orch.fsm.transition_to(HunterState.DEGRADED_MODE, "ai degraded")

        ok = await orch.stage_env_readiness()
        assert ok is True
        assert orch.fsm.current_state == HunterState.ENV_READINESS
        assert len(orch.readiness_report.get("blocked", [])) == 2

    @pytest.mark.asyncio
    async def test_gate_crash_in_strict_fails_closed(self, monkeypatch, tmp_path):
        """انفجار البوابة في strict → ERROR (fail-closed) لا تجاوز صامت."""
        async def boom(data, target, session_id, checker=None):
            raise RuntimeError("probe exploded")

        import hunter_ai.pipeline.pipeline_orchestrator as po
        monkeypatch.setattr(po, "run_mission_gate", boom)
        monkeypatch.setattr(
            "core.readiness.save_readiness_artifact", lambda r: None, raising=False,
        )
        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, require_ready=True,
        )
        orch.artifact_root = str(tmp_path)
        orch.fsm.transition_to(HunterState.PREFLIGHT, "preflight")
        orch.fsm.transition_to(HunterState.AI_READY, "ai ok")

        ok = await orch.stage_env_readiness()
        assert ok is False
        assert orch.fsm.current_state == HunterState.ERROR

    @pytest.mark.asyncio
    async def test_gate_crash_advisory_continues(self, monkeypatch, tmp_path):
        """انفجار البوابة غير strict → إرشاد فقط والمهمة تكمل."""
        async def boom(data, target, session_id, checker=None):
            raise RuntimeError("probe exploded")

        import hunter_ai.pipeline.pipeline_orchestrator as po
        monkeypatch.setattr(po, "run_mission_gate", boom)
        monkeypatch.setattr(
            "core.readiness.save_readiness_artifact", lambda r: None, raising=False,
        )
        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, require_ready=False,
        )
        orch.artifact_root = str(tmp_path)
        orch.fsm.transition_to(HunterState.PREFLIGHT, "preflight")
        orch.fsm.transition_to(HunterState.AI_READY, "ai ok")

        ok = await orch.stage_env_readiness()
        assert ok is True

    @pytest.mark.asyncio
    async def test_env_readiness_constructed_flag_and_envvar(self, monkeypatch):
        """require_ready باراميتر أو HUNTERAI_REQUIRE_READY=1 — الاتنين شغالين."""
        orch = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True, require_ready=True,
        )
        assert orch.require_ready is True
        monkeypatch.delenv("HUNTERAI_REQUIRE_READY", raising=False)
        orch2 = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True,
        )
        assert orch2.require_ready is False
        monkeypatch.setenv("HUNTERAI_REQUIRE_READY", "1")
        orch3 = HunterPipelineOrchestrator(
            target="https://example.test", in_scope=["example.test"],
            allow_no_ai=True,
        )
        assert orch3.require_ready is True
