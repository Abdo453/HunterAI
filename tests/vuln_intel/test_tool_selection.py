"""Deterministic, authorization-aware tool selection (plan only)."""
from __future__ import annotations

import os
import subprocess

import pytest

from core.vuln_intel.models import Ecosystem
from core.vuln_intel.tool_capabilities import ToolAvailability, ToolCapability
from core.vuln_intel.tool_selection import SelectionScope, select_tools


def _capability(**overrides) -> ToolCapability:
    data = {
        "tool_id": "sqlmap",
        "name": "sqlmap",
        "vuln_classes": ["sqli"],
        "input_types": ["url", "parameter"],
        "risk_level": "high",
        "availability": ToolAvailability.INSTALLED,
        "requires_authorization": True,
        "active": True,
        "reliability": 0.7,
        "limitations": ["noisy"],
    }
    data.update(overrides)
    return ToolCapability(**data)


def _sqli_record(make_record):
    return make_record(cwes=["CWE-89"], description="A SQL injection flaw in the query builder")


def _passive_capability(**overrides) -> ToolCapability:
    data = {
        "tool_id": "semgrep",
        "name": "Semgrep",
        "active": False,
        "requires_authorization": False,
        "risk_level": "low",
        "input_types": ["source"],
        "reliability": 0.6,
    }
    data.update(overrides)
    return _capability(**data)


def test_unauthorized_scope_does_not_hide_a_missing_capability(make_record):
    # The only tool is passive but does not match the class, so authorization
    # was not the reason nothing was selected; the honest status is ``no_match``.
    capability = _passive_capability(tool_id="xxe-only", vuln_classes=["xxe"])
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=False, max_risk="high"),
        [capability],
    )
    assert result.status == "no_match"
    assert result.rejected[0].reason == "no matching vulnerability class"


def test_active_tool_requires_explicit_authorization(make_record):
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=False, max_risk="high"),
        [_capability()],
    )
    assert result.status == "not_authorized"
    assert result.selected == []
    assert result.rejected[0].tool_id == "sqlmap"
    assert "authorization" in result.rejected[0].reason


def test_authorized_scope_selects_the_matching_tool(make_record):
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="high"),
        [_capability()],
    )
    assert result.status == "selected"
    assert [item.tool_id for item in result.selected] == ["sqlmap"]
    assert result.selected[0].matched_classes == ["sqli"]
    assert result.selected[0].score > 0


def test_passive_tool_is_selectable_without_authorization(make_record):
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=False, max_risk="low"),
        [_passive_capability()],
    )
    assert result.status == "selected"
    assert [item.tool_id for item in result.selected] == ["semgrep"]


def test_risk_ceiling_blocks_higher_risk_tools(make_record):
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="medium"),
        [_capability()],
    )
    assert result.selected == []
    assert "exceeds the granted maximum" in result.rejected[0].reason


def test_unverified_availability_blocks_selection(make_record):
    capability = _capability(availability=ToolAvailability.UNKNOWN)
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="high"),
        [capability],
    )
    assert result.selected == []
    assert "not verified as installed" in result.rejected[0].reason


def test_availability_requirement_can_be_relaxed_explicitly(make_record):
    capability = _capability(availability=ToolAvailability.UNKNOWN)
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="high", require_installed=False),
        [capability],
    )
    assert [item.tool_id for item in result.selected] == ["sqlmap"]
    assert result.selected[0].availability == "unknown"


def test_ecosystem_mismatch_blocks_a_tool(make_record, make_project):
    capability = _capability(
        tool_id="npm-audit-tool",
        ecosystems=["npm"],
    )
    project = make_project(
        [{"name": "vendor/package", "version": "1.0.0", "ecosystem": "packagist"}]
    )
    result = select_tools(
        _sqli_record(make_record),
        project,
        SelectionScope(authorized=True, max_risk="high"),
        [capability],
    )
    assert result.selected == []
    assert "ecosystem mismatch" in result.rejected[0].reason


def test_matching_ecosystem_is_scored(make_record, make_project):
    capability = _capability(ecosystems=["packagist"])
    project = make_project(
        [{"name": "vendor/package", "version": "1.0.0", "ecosystem": "packagist"}]
    )
    result = select_tools(
        _sqli_record(make_record),
        project,
        SelectionScope(authorized=True, max_risk="high"),
        [capability],
    )
    assert [item.tool_id for item in result.selected] == ["sqlmap"]
    assert result.selected[0].matched_ecosystems == ["packagist"]


def test_allowlist_blocks_every_other_tool(make_record):
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="high", allowed_tools=["semgrep"]),
        [_capability(), _passive_capability()],
    )
    assert [item.tool_id for item in result.selected] == ["semgrep"]
    reasons = {item.tool_id: item.reason for item in result.rejected}
    assert "allowlist" in reasons["sqlmap"]


def test_advisory_without_class_evidence_selects_nothing(make_record):
    record = make_record(cwes=[], description=None, summary=None, title=None)
    result = select_tools(
        record,
        None,
        SelectionScope(authorized=True, max_risk="critical"),
        [_capability()],
    )
    assert result.status == "insufficient_evidence"
    assert result.selected == []
    assert result.vuln_classes == []


def test_tool_without_matching_class_is_rejected(make_record):
    capability = _capability(vuln_classes=["xss"])
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="high"),
        [capability],
    )
    assert result.selected == []
    assert result.rejected[0].reason == "no matching vulnerability class"


def test_tool_without_documented_limitations_is_rejected(make_record):
    capability = _capability(limitations=[])
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="high"),
        [capability],
    )
    assert result.selected == []
    assert "limitations" in result.rejected[0].reason


def test_not_applicable_advisory_blocks_any_selection(
    make_record, make_project, composer_package
):
    record = make_record(
        cwes=["CWE-89"],
        description="A SQL injection flaw in the query builder",
        affected=[composer_package("vendor/package", start_including="0")],
    )
    project = make_project(
        [{"name": "other/package", "version": "9.9.9", "ecosystem": "packagist"}]
    )
    result = select_tools(
        record,
        project,
        SelectionScope(authorized=True, max_risk="critical"),
        [_capability()],
    )
    assert result.status == "not_applicable"
    assert result.selected == []
    assert result.applicability == "NOT_APPLICABLE"


def test_selection_is_deterministic_and_breaks_ties_by_tool_id(make_record):
    capabilities = [
        _capability(tool_id="zeta", name="zeta", reliability=0.5),
        _capability(tool_id="alpha", name="alpha", reliability=0.5),
        _capability(tool_id="mid", name="mid", reliability=0.5),
    ]
    scope = SelectionScope(authorized=True, max_risk="high")
    record = _sqli_record(make_record)

    first = select_tools(record, None, scope, capabilities)
    second = select_tools(record, None, scope, list(reversed(capabilities)))

    assert [item.tool_id for item in first.selected] == ["alpha", "mid", "zeta"]
    assert [item.tool_id for item in second.selected] == ["alpha", "mid", "zeta"]
    assert [item.score for item in first.selected] == [item.score for item in second.selected]


def test_selection_never_executes_a_tool(make_record, monkeypatch):
    def _boom(*args, **kwargs):
        raise AssertionError("tool selection must not execute anything")

    monkeypatch.setattr(subprocess, "run", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(os, "system", _boom)

    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="critical"),
        [_capability(), _passive_capability()],
    )
    assert result.selected
    assert any("no tool was executed" in note for note in result.notes)


def test_scope_rejects_an_unknown_risk_ceiling():
    with pytest.raises(ValueError):
        SelectionScope(max_risk="extreme")


def test_scope_normalizes_the_tool_allowlist():
    scope = SelectionScope(allowed_tools=[" sqlmap ", "sqlmap", "nuclei"])
    assert scope.allowed_tools == ["sqlmap", "nuclei"]


def test_result_is_json_serializable(make_record):
    result = select_tools(
        _sqli_record(make_record),
        None,
        SelectionScope(authorized=True, max_risk="high"),
        [_capability()],
    )
    payload = result.to_dict()
    assert payload["status"] == "selected"
    assert payload["vuln_classes"] == ["sqli"]
    assert isinstance(payload["generated_at"], str)


def test_ecosystem_agnostic_tools_are_not_blocked_by_a_known_project(
    make_record, make_project
):
    project = make_project(
        [{"name": "vendor/package", "version": "1.0.0", "ecosystem": Ecosystem.PACKAGIST}]
    )
    result = select_tools(
        _sqli_record(make_record),
        project,
        SelectionScope(authorized=True, max_risk="high"),
        [_capability(ecosystems=[])],
    )
    assert [item.tool_id for item in result.selected] == ["sqlmap"]


def test_authorization_flaw_advisory_selects_an_authorization_capable_tool(make_record):
    record = make_record(
        cwes=["CWE-285"],
        description="The endpoint fails to enforce authorization checks.",
    )
    capability = _passive_capability(
        tool_id="authz-review",
        vuln_classes=["authorization_flaw"],
    )
    result = select_tools(
        record,
        None,
        SelectionScope(authorized=False, max_risk="low"),
        [capability],
    )
    assert result.vuln_classes == ["authorization_flaw"]
    assert [item.tool_id for item in result.selected] == ["authz-review"]
