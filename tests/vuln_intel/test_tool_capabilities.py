"""Tool capability metadata: catalog honesty and loading rules."""
from __future__ import annotations

import json

import pytest

from core.vuln_intel.tool_capabilities import (
    DEFAULT_CAPABILITIES,
    ToolAvailability,
    ToolCapability,
    capability_from_tool_definition,
    load_capability_catalog,
)


def test_default_catalog_is_unique_and_honest():
    ids = [item.tool_id for item in DEFAULT_CAPABILITIES]
    assert len(ids) == len(set(ids))
    assert ids, "the catalog must not be empty"
    for item in DEFAULT_CAPABILITIES:
        # Nothing is claimed as installed: this repository never verified the
        # binaries, so the catalog must say "unknown".
        assert item.availability == ToolAvailability.UNKNOWN
        assert item.last_validated is None
        assert item.limitations, f"{item.tool_id} must document its limitations"
        assert 0.0 <= item.reliability <= 1.0


def test_catalog_entries_declare_their_vulnerability_classes():
    by_id = {item.tool_id: item for item in DEFAULT_CAPABILITIES}
    assert "sqli" in by_id["sqlmap"].vuln_classes
    assert "xss" in by_id["dalfox"].vuln_classes
    assert by_id["semgrep"].active is False
    assert by_id["sqlmap"].active is True
    assert by_id["sqlmap"].requires_authorization is True
    assert by_id["semgrep"].requires_authorization is False


def test_capability_normalizes_lists_and_rejects_bad_values():
    capability = ToolCapability(
        tool_id="demo",
        vuln_classes=["SQLI", "sqli", " XSS "],
        risk_level="HIGH",
        reliability=0.5,
    )
    assert capability.vuln_classes == ["sqli", "xss"]
    assert capability.risk_level == "high"
    assert capability.name == "demo"

    with pytest.raises(ValueError):
        ToolCapability(tool_id="demo", risk_level="extreme")
    with pytest.raises(ValueError):
        ToolCapability(tool_id="demo", reliability=1.5)
    with pytest.raises(ValueError):
        ToolCapability(tool_id="demo", test_coverage=-0.1)
    with pytest.raises(ValueError):
        ToolCapability(tool_id="  ")


def test_load_capability_catalog_reads_a_json_array(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps(
            [
                {
                    "tool_id": "demo",
                    "name": "Demo",
                    "vuln_classes": ["sqli"],
                    "availability": "installed",
                    "limitations": ["sends requests"],
                }
            ]
        ),
        encoding="utf-8",
    )
    catalog = load_capability_catalog(path)
    assert len(catalog) == 1
    assert catalog[0].tool_id == "demo"
    assert catalog[0].availability == ToolAvailability.INSTALLED


def test_load_capability_catalog_accepts_a_tools_object(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(
        json.dumps({"tools": [{"tool_id": "demo", "limitations": ["x"]}]}),
        encoding="utf-8",
    )
    catalog = load_capability_catalog(path)
    assert [item.tool_id for item in catalog] == ["demo"]


def test_load_capability_catalog_fails_loudly(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_capability_catalog(bad_json)

    wrong_shape = tmp_path / "shape.json"
    wrong_shape.write_text(json.dumps({"catalog": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_capability_catalog(wrong_shape)

    bad_entry = tmp_path / "entry.json"
    bad_entry.write_text(json.dumps([{"tool_id": "demo", "risk_level": "extreme"}]), encoding="utf-8")
    with pytest.raises(ValueError):
        load_capability_catalog(bad_entry)

    duplicate = tmp_path / "dup.json"
    duplicate.write_text(
        json.dumps([{"tool_id": "demo"}, {"tool_id": "demo"}]), encoding="utf-8"
    )
    with pytest.raises(ValueError):
        load_capability_catalog(duplicate)


class _FakeDefinition:
    """Minimal stand-in for ``core.tool_registry.ToolDefinition``."""

    tool_id = "legacy-tool"
    name = "Legacy Tool"
    description = "An existing registry entry"
    risk_level = "high"
    approval_required = True
    required_permissions = ("network",)


def test_capability_from_tool_definition_is_conservative_by_default():
    capability = capability_from_tool_definition(_FakeDefinition())
    assert capability.tool_id == "legacy-tool"
    assert capability.name == "Legacy Tool"
    assert capability.risk_level == "high"
    assert capability.requires_authorization is True
    # No capability metadata means no vulnerability classes: the tool stays
    # ineligible for automatic selection.
    assert capability.vuln_classes == []
    assert capability.availability == ToolAvailability.UNKNOWN


def test_capability_from_tool_definition_reads_a_capabilities_mapping():
    class _WithCapabilities(_FakeDefinition):
        capabilities = {
            "vuln_classes": ["sqli"],
            "ecosystems": ["packagist"],
            "availability": "installed",
            "reliability": 0.4,
            "limitations": ["noisy"],
        }

    capability = capability_from_tool_definition(_WithCapabilities())
    assert capability.vuln_classes == ["sqli"]
    assert capability.ecosystems == ["packagist"]
    assert capability.availability == ToolAvailability.INSTALLED
    assert capability.reliability == 0.4
    assert capability.limitations == ["noisy"]


def test_capability_from_the_real_core_registry_definition():
    """Guard against drift in ``core.tool_registry.ToolDefinition``."""
    from core.tool_registry import RiskLevel, ToolDefinition

    definition = ToolDefinition(
        tool_id="registry-tool",
        name="Registry Tool",
        description="A real registry definition",
        input_schema={},
        risk_level=RiskLevel.HIGH,
        approval_required=True,
        required_permissions=("network",),
    )
    capability = capability_from_tool_definition(definition)
    assert capability.tool_id == "registry-tool"
    assert capability.risk_level == "high"
    assert capability.requires_authorization is True
    assert capability.permissions == ["network"]
    # No capability metadata in the core registry yet: still ineligible.
    assert capability.vuln_classes == []
    assert capability.availability == ToolAvailability.UNKNOWN
