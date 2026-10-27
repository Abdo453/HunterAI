"""Tool capability metadata (P6).

This module is **metadata only**.  It never installs a tool, never executes a
tool, and never touches a target.  It exists so that tool selection can be
deterministic and explainable instead of "popularity driven".

Honesty rules encoded here
--------------------------
* ``availability`` is explicit.  The built-in catalog ships every tool as
  ``unknown`` because this repository does not verify which binaries are
  installed on a given machine.  A caller must either provide a catalog that
  states the availability or explicitly relax the requirement.
* ``last_validated`` is ``None`` until a human validated the tool in a given
  environment.
* ``reliability`` and ``test_coverage`` are the *maintainer's* estimates and
  are always reported next to the selection, never hidden.
* ``limitations`` is not optional: a tool without stated limitations is not
  eligible for selection.

The core registry (``core.tool_registry.ToolDefinition``) is intentionally not
modified here; :func:`capability_from_tool_definition` adapts it instead, so
this increment does not disturb the in-flight work in that module.
"""
from __future__ import annotations

import json
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "DEFAULT_CAPABILITIES",
    "ToolAvailability",
    "ToolCapability",
    "capability_from_tool_definition",
    "load_capability_catalog",
]


class ToolAvailability(str, Enum):
    """Whether a tool is known to be usable on the current machine."""

    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    UNKNOWN = "unknown"


_RISK_LEVELS = {"low", "medium", "high", "critical"}


def _normalize_list(values: Sequence[Any]) -> List[str]:
    out: List[str] = []
    for value in values or []:
        text = str(value or "").strip().lower()
        if text and text not in out:
            out.append(text)
    return out


class ToolCapability(BaseModel):
    """Capability metadata for one security tool."""

    model_config = ConfigDict(extra="forbid", validate_default=True)

    tool_id: str
    name: str = ""
    description: str = ""
    languages: List[str] = Field(default_factory=list)
    ecosystems: List[str] = Field(default_factory=list)
    vuln_classes: List[str] = Field(default_factory=list)
    input_types: List[str] = Field(default_factory=list)
    output_types: List[str] = Field(default_factory=list)
    risk_level: str = "medium"
    availability: ToolAvailability = ToolAvailability.UNKNOWN
    requires_authorization: bool = False
    active: bool = True
    reliability: float = 0.0
    test_coverage: Optional[float] = None
    permissions: List[str] = Field(default_factory=list)
    constraints: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    license: Optional[str] = None
    last_validated: Optional[str] = None

    @field_validator("tool_id")
    @classmethod
    def _tool_id_required(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("tool_id is required")
        return text

    @field_validator("name")
    @classmethod
    def _name_default(cls, value: str, info) -> str:
        text = str(value or "").strip()
        return text or str(info.data.get("tool_id") or "")

    @field_validator(
        "languages",
        "ecosystems",
        "vuln_classes",
        "input_types",
        "output_types",
        "permissions",
        "constraints",
        "limitations",
    )
    @classmethod
    def _normalize(cls, value: List[str]) -> List[str]:
        return _normalize_list(value)

    @field_validator("risk_level")
    @classmethod
    def _risk_level(cls, value: str) -> str:
        text = str(value or "").strip().lower()
        if text not in _RISK_LEVELS:
            raise ValueError(f"risk_level must be one of {sorted(_RISK_LEVELS)}")
        return text

    @field_validator("reliability")
    @classmethod
    def _reliability(cls, value: float) -> float:
        number = float(value)
        if not 0.0 <= number <= 1.0:
            raise ValueError("reliability must be between 0 and 1")
        return number

    @field_validator("test_coverage")
    @classmethod
    def _coverage(cls, value: Optional[float]) -> Optional[float]:
        if value is None:
            return None
        number = float(value)
        if not 0.0 <= number <= 1.0:
            raise ValueError("test_coverage must be between 0 and 1")
        return number

    @field_validator("last_validated")
    @classmethod
    def _last_validated(cls, value: Optional[str]) -> Optional[str]:
        text = str(value or "").strip()
        return text or None


DEFAULT_CAPABILITIES: List[ToolCapability] = [
    ToolCapability(
        tool_id="sqlmap",
        name="sqlmap",
        description="Automated SQL injection detection and verification.",
        vuln_classes=["sqli"],
        input_types=["url", "parameter"],
        output_types=["finding"],
        risk_level="high",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=True,
        active=True,
        reliability=0.7,
        permissions=["network", "recon"],
        constraints=["requires an explicit, written authorization scope"],
        limitations=[
            "generates many requests and can be noisy",
            "may modify data with high risk levels",
        ],
        license="GPL-2.0",
    ),
    ToolCapability(
        tool_id="dalfox",
        name="Dalfox",
        description="XSS scanner and verifier.",
        vuln_classes=["xss"],
        input_types=["url", "parameter"],
        output_types=["finding"],
        risk_level="medium",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=True,
        active=True,
        reliability=0.6,
        permissions=["network", "recon"],
        constraints=["requires an explicit, written authorization scope"],
        limitations=["crawls by default; keep the scope tight"],
        license="MIT",
    ),
    ToolCapability(
        tool_id="nuclei",
        name="Nuclei",
        description="Template-driven vulnerability scanner.",
        vuln_classes=[
            "sqli",
            "xss",
            "ssrf",
            "path_traversal",
            "file_upload",
            "misconfiguration",
            "idor",
            "authorization_flaw",
            "known_vulnerable_component",
        ],
        input_types=["url"],
        output_types=["finding"],
        risk_level="high",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=True,
        active=True,
        reliability=0.7,
        permissions=["network", "recon"],
        constraints=["requires an explicit, written authorization scope"],
        limitations=["template quality varies; a template hit is a lead, not a verdict"],
        license="MIT",
    ),
    ToolCapability(
        tool_id="semgrep",
        name="Semgrep",
        description="Static analysis over source code.",
        languages=["python", "php", "javascript", "typescript", "go", "ruby", "java"],
        vuln_classes=[
            "sqli",
            "xss",
            "ssrf",
            "path_traversal",
            "deserialization",
            "command_injection",
            "authorization_flaw",
        ],
        input_types=["source"],
        output_types=["finding"],
        risk_level="low",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=False,
        active=False,
        reliability=0.6,
        permissions=["filesystem"],
        limitations=["static findings need manual verification before reporting"],
        license="LGPL-2.1",
    ),
    ToolCapability(
        tool_id="trivy",
        name="Trivy",
        description="Dependency and misconfiguration scanner for files/images.",
        vuln_classes=[
            "known_vulnerable_dependency",
            "known_vulnerable_component",
            "misconfiguration",
        ],
        input_types=["filesystem", "image"],
        output_types=["finding"],
        risk_level="low",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=False,
        active=False,
        reliability=0.6,
        permissions=["filesystem"],
        limitations=["a dependency hit is not proof that the deployed code path is reachable"],
        license="Apache-2.0",
    ),
    ToolCapability(
        tool_id="composer.audit",
        name="Composer audit",
        description="Checks composer.lock against the Packagist security advisories.",
        languages=["php"],
        ecosystems=["composer", "packagist"],
        vuln_classes=["known_vulnerable_dependency"],
        input_types=["composer_lock"],
        output_types=["finding"],
        risk_level="low",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=False,
        active=False,
        reliability=0.5,
        permissions=["filesystem"],
        limitations=["only covers dependencies present in the lock file"],
        license="MIT",
    ),
    ToolCapability(
        tool_id="gitleaks",
        name="Gitleaks",
        description="Finds hard-coded secrets in source history.",
        vuln_classes=["secret_exposure", "hardcoded_credentials"],
        input_types=["source"],
        output_types=["finding"],
        risk_level="low",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=False,
        active=False,
        reliability=0.6,
        permissions=["filesystem"],
        limitations=["needs manual verification to avoid false positives"],
        license="MIT",
    ),
    ToolCapability(
        tool_id="feroxbuster",
        name="feroxbuster",
        description="Content discovery for hidden paths and files.",
        vuln_classes=["content_discovery", "misconfiguration"],
        input_types=["url"],
        output_types=["finding"],
        risk_level="medium",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=True,
        active=True,
        reliability=0.5,
        permissions=["network", "recon"],
        constraints=["requires an explicit, written authorization scope"],
        limitations=["produces many requests; keep the wordlist small and the scope tight"],
        license="MIT",
    ),
    ToolCapability(
        tool_id="arjun",
        name="Arjun",
        description="Discovers hidden HTTP parameters.",
        vuln_classes=["parameter_discovery"],
        input_types=["url"],
        output_types=["finding"],
        risk_level="medium",
        availability=ToolAvailability.UNKNOWN,
        requires_authorization=True,
        active=True,
        reliability=0.4,
        permissions=["network", "recon"],
        constraints=["requires an explicit, written authorization scope"],
        limitations=["parameter discovery is a lead, not a vulnerability"],
        license="GPL-3.0",
    ),
]


def load_capability_catalog(path: str | Path) -> List[ToolCapability]:
    """Load a capability catalog from a JSON file.

    The file may contain a JSON array of tool objects or an object with a
    ``tools`` array.  Every entry is validated; an invalid entry fails loudly
    instead of being silently dropped.
    """
    raw = Path(path).read_text(encoding="utf-8")
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"capability catalog {path} is not valid JSON") from exc

    if isinstance(data, dict):
        entries = data.get("tools")
    elif isinstance(data, list):
        entries = data
    else:
        entries = None
    if not isinstance(entries, list):
        raise ValueError("capability catalog must be a JSON array or an object with 'tools'")

    catalog: List[ToolCapability] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"capability catalog entry {index} must be an object")
        try:
            capability = ToolCapability.model_validate(entry)
        except Exception as exc:  # noqa: BLE001 - re-raised with context
            raise ValueError(f"invalid capability catalog entry {index}: {exc}") from exc
        if capability.tool_id in seen:
            raise ValueError(f"duplicate tool_id in capability catalog: {capability.tool_id}")
        seen.add(capability.tool_id)
        catalog.append(capability)
    return catalog


def capability_from_tool_definition(definition: Any) -> ToolCapability:
    """Adapt a ``core.tool_registry.ToolDefinition`` into a capability record.

    The core registry is left untouched; this adapter reads an optional
    ``capabilities`` mapping when a definition provides one and otherwise
    returns conservative defaults (unknown availability, no vulnerability
    classes), which makes the tool ineligible for automatic selection.
    """
    data: Dict[str, Any] = {}
    raw = getattr(definition, "capabilities", None)
    if isinstance(raw, dict):
        data.update(raw)

    tool_id = str(getattr(definition, "tool_id", "") or data.get("tool_id") or "").strip()
    name = str(getattr(definition, "name", "") or data.get("name") or "").strip()
    raw_risk = getattr(definition, "risk_level", "") or data.get("risk_level") or "medium"
    risk = str(getattr(raw_risk, "value", raw_risk))
    availability = data.get("availability", ToolAvailability.UNKNOWN)
    requires_auth = bool(
        getattr(definition, "approval_required", False)
        or getattr(definition, "requires_authorization", False)
        or data.get("requires_authorization", False)
    )
    active = bool(data.get("active", True))

    payload: Dict[str, Any] = {
        "tool_id": tool_id,
        "name": name,
        "description": str(getattr(definition, "description", "") or ""),
        "languages": data.get("languages", []),
        "ecosystems": data.get("ecosystems", []),
        "vuln_classes": data.get("vuln_classes", []),
        "input_types": data.get("input_types", []),
        "output_types": data.get("output_types", []),
        "risk_level": risk,
        "availability": availability,
        "requires_authorization": requires_auth,
        "active": active,
        "reliability": data.get("reliability", 0.0),
        "test_coverage": data.get("test_coverage"),
        "permissions": list(getattr(definition, "required_permissions", []) or []),
        "constraints": data.get("constraints", []),
        "limitations": data.get("limitations", []),
        "license": data.get("license"),
        "last_validated": data.get("last_validated"),
    }
    return ToolCapability.model_validate(payload)
