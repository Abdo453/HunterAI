"""
Unit Tests for Browser Skill Adapters (agents/skills/browser_adapter_skills.py)
==============================================================================
Offline فقط — تُختبر محوّلات `_BrowserSkillAdapter` مع مهارات أصلية וهمية;
لا متصفح ولا شبكة حقيقية.
"""
import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from agents.skills.browser_adapter_skills import (
    BrowserReconAdapterSkill,
    FormIntelligenceAdapterSkill,
    NetworkIntelligenceAdapterSkill,
    BehaviorAnalysisAdapterSkill,
    BrowserSensorAdapterSkill,
    _BrowserSkillAdapter,
)


class FakeWrappedResult:
    """يُحاكي كائن skills.base_skill.SkillResult (يحتوي success/findings/output_files/...)."""

    def __init__(self, success=True, findings=None, output_files=None,
                 duration=1.5, raw_output=None):
        self.success = success
        self.findings = findings or []
        self.output_files = output_files or {}
        self.duration = duration
        self.raw_output = raw_output or {}


class FakeWrappedSkill:
    """مهارة أصلية وهمية تُعيد نتيجة محددة أو ترفع استثناءً (لا ترث من BaseSkill المجردة)."""

    def __init__(self, name="fake_browser", result: FakeWrappedResult | None = None,
                 should_raise: bool = False):
        self.name = name
        self._result = result or FakeWrappedResult()
        self._should_raise = should_raise

    async def execute(self, ctx):
        if self._should_raise:
            raise RuntimeError("simulated browser crash")
        await asyncio.sleep(0)
        return self._result


def _make_adapter(wrapped) -> _BrowserSkillAdapter:
    return _BrowserSkillAdapter(
        wrapped=wrapped,
        name="test_browser_adapter",
        vuln_type="browser_test",
        cwe="CWE-000",
        owasp_top10="A00:2021",
        default_severity="Info",
    )


# ════════════════════════════════════════════════════════════════════════════
# Tests
# ════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_adapter_converts_wrapped_result():
    wrapped = FakeWrappedSkill(
        name="fake_recon",
        result=FakeWrappedResult(
            success=True,
            findings=[{"title": "Insecure Cookie", "evidence": "sessionid missing Secure",
                       "severity": "Low", "vuln_type": "cookie_misconfiguration",
                       "url": "https://app.target.com/"}],
            output_files={"pages.txt": "/tmp/pages.txt"},
        ),
    )
    adapter = _make_adapter(wrapped)
    res = await adapter.run("https://app.target.com/", param_name="")

    assert res.verified is True
    assert res.vuln_type == "browser_test"
    assert "Insecure Cookie" in res.evidence
    assert "pages.txt" in str(res.extra["output_files"])
    assert res.tool == "test_browser_adapter"
    assert res.cwe == "CWE-000"


@pytest.mark.asyncio
async def test_adapter_unverified_when_no_findings():
    wrapped = FakeWrappedSkill(
        name="fake_form",
        result=FakeWrappedResult(success=True, findings=[]),
    )
    adapter = _make_adapter(wrapped)
    res = await adapter.run("https://app.target.com/", param_name="")
    assert res.verified is False


@pytest.mark.asyncio
async def test_adapter_handles_wrapped_crash_gracefully():
    wrapped = FakeWrappedSkill(name="fake_net", should_raise=True)
    adapter = _make_adapter(wrapped)
    res = await adapter.run("https://app.target.com/", param_name="")
    assert res.verified is False
    assert len(res.logs) >= 1
    assert "simulated browser crash" in res.logs[-1]


@pytest.mark.asyncio
async def test_concrete_adapters_can_handle_zero():
    for cls in (BrowserReconAdapterSkill, FormIntelligenceAdapterSkill,
                NetworkIntelligenceAdapterSkill, BehaviorAnalysisAdapterSkill,
                BrowserSensorAdapterSkill):
        inst = cls()
        assert inst.can_handle("anything") == 0.0


def test_browser_adapters_registered():
    from agents.skills.registry import bootstrap_builtin_skills
    reg = bootstrap_builtin_skills()
    for name in ("browser_recon", "form_intelligence", "network_intelligence",
                 "behavior_analysis", "browser_sensor"):
        assert name in reg, f"{name} not registered"
        meta = reg.get(name)
        assert meta.param_keywords == []


def test_exports():
    from agents.skills import (  # noqa: F401
        BrowserReconAdapterSkill, FormIntelligenceAdapterSkill,
        NetworkIntelligenceAdapterSkill, BehaviorAnalysisAdapterSkill,
        BrowserSensorAdapterSkill,
    )
    assert BrowserReconAdapterSkill
    assert FormIntelligenceAdapterSkill
    assert NetworkIntelligenceAdapterSkill
    assert BehaviorAnalysisAdapterSkill
    assert BrowserSensorAdapterSkill
