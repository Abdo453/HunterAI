"""Deterministic tool selection for authorized testing (P6).

What this module does
---------------------
It ranks security tools for **one advisory** against **one project profile**
and **one authorization scope**, and it explains every decision.

What this module does **not** do
--------------------------------
* It never executes a tool, spawns a process, opens a socket, or touches a
  target.  The output is a *plan*.
* It never recommends an active tool without explicit authorization.
* It never recommends a tool whose risk is above the granted risk ceiling.
* It never guesses a vulnerability class: if the advisory carries no class
  evidence, the result is ``insufficient_evidence`` and nothing is selected.
* It refuses to plan active testing for an advisory that does not apply to the
  project inventory (``NOT_APPLICABLE``): no theoretical hunting.

Scoring is deterministic and fully explainable.  Ties are broken by
``tool_id`` so two runs with the same inputs always produce the same order.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Sequence, Set

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .models import Applicability, ProjectProfile, VulnerabilityRecord, utc_now
from .tool_capabilities import ToolAvailability, ToolCapability
from .triage import triage_project
from .vuln_classes import classify_vuln_classes

__all__ = [
    "RejectedTool",
    "SelectionScope",
    "ToolSelection",
    "ToolSelectionResult",
    "select_tools",
]


_RISK_ORDER: Dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_CLASS_SCORE = 40.0
_MAX_CLASS_BONUS = 2
_ECOSYSTEM_SCORE = 20.0
_INPUT_SCORE = 10.0
_AVAILABILITY_SCORE = 10.0
_RELIABILITY_WEIGHT = 10.0
_COVERAGE_WEIGHT = 5.0
_RISK_BONUS = {"low": 5.0, "medium": 0.0, "high": -5.0, "critical": -10.0}

# Acceptable input kinds per vulnerability class.  A tool qualifies when its
# declared input types intersect this set (an empty set means "agnostic").
_CLASS_INPUTS: Dict[str, Set[str]] = {
    "sqli": {"url", "parameter", "source"},
    "xss": {"url", "parameter", "source"},
    "ssrf": {"url", "source"},
    "path_traversal": {"url", "source"},
    "file_upload": {"url", "source"},
    "deserialization": {"url", "source"},
    "command_injection": {"url", "source"},
    "code_injection": {"url", "source"},
    "template_injection": {"url", "source"},
    "xxe": {"url", "source"},
    "idor": {"url", "source"},
    "authorization_flaw": {"url", "source"},
    "missing_authorization": {"url", "source"},
    "auth_bypass": {"url", "source"},
    "csrf": {"url", "source"},
    "open_redirect": {"url", "source"},
    "origin_validation": {"url", "source"},
    "info_disclosure": {"url", "source"},
    "weak_crypto": {"url", "source"},
    "weak_credentials": {"url", "source"},
    "sensitive_cookie": {"url", "source"},
    "hardcoded_credentials": {"source", "filesystem"},
    "secret_exposure": {"source", "filesystem"},
    "known_vulnerable_dependency": {"package", "filesystem", "composer_lock", "image"},
    "known_vulnerable_component": {"package", "filesystem", "image"},
    "misconfiguration": {"url", "filesystem", "image", "source"},
    "prototype_pollution": {"url", "source"},
    "content_discovery": {"url"},
    "parameter_discovery": {"url"},
    "denial_of_service": {"url", "source"},
    "request_smuggling": {"url", "source"},
    "race_condition": {"url", "source"},
}


class SelectionScope(BaseModel):
    """The authorization envelope a selection must stay inside."""

    model_config = ConfigDict(extra="forbid")

    authorized: bool = False
    max_risk: str = "low"
    allowed_tools: Optional[List[str]] = None
    require_installed: bool = True
    require_limitations: bool = True

    @field_validator("max_risk")
    @classmethod
    def _max_risk(cls, value: str) -> str:
        text = str(value or "").strip().lower()
        if text not in _RISK_ORDER:
            raise ValueError(f"max_risk must be one of {sorted(_RISK_ORDER)}")
        return text

    @field_validator("allowed_tools")
    @classmethod
    def _allowed_tools(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        out: List[str] = []
        for item in value:
            text = str(item or "").strip()
            if text and text not in out:
                out.append(text)
        return out

    @classmethod
    def build(cls, **kwargs) -> "SelectionScope":
        return cls(**kwargs)


class ToolSelection(BaseModel):
    """One recommended tool with its score and the reasons behind it."""

    model_config = ConfigDict(extra="forbid")

    tool_id: str
    name: str
    score: float
    risk_level: str
    availability: str
    matched_classes: List[str] = Field(default_factory=list)
    matched_ecosystems: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)


class RejectedTool(BaseModel):
    """One tool that was considered and refused, with the reason."""

    model_config = ConfigDict(extra="forbid")

    tool_id: str
    reason: str


class ToolSelectionResult(BaseModel):
    """The full, explainable outcome of a selection run."""

    model_config = ConfigDict(extra="forbid")

    vuln_id: str
    project_id: str
    status: str
    authorized: bool
    vuln_classes: List[str] = Field(default_factory=list)
    class_evidence: List[str] = Field(default_factory=list)
    applicability: Optional[str] = None
    selected: List[ToolSelection] = Field(default_factory=list)
    rejected: List[RejectedTool] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, object]:
        return self.model_dump(mode="json")


def _project_ecosystems(project: Optional[ProjectProfile]) -> Set[str]:
    """The ecosystems the project actually uses."""
    if project is None:
        return set()
    ecosystems: Set[str] = set()
    for package in project.packages or []:
        value = getattr(package.ecosystem, "value", package.ecosystem)
        ecosystems.add(str(value or "").strip().lower())
    if not ecosystems and project.ecosystem is not None:
        value = getattr(project.ecosystem, "value", project.ecosystem)
        ecosystems.add(str(value or "").strip().lower())
    if project.php_version:
        ecosystems.add("php")
    for framework in (project.frameworks or {}):
        if str(framework or "").strip().lower() in {
            "laravel",
            "symfony",
            "wordpress",
            "drupal",
            "magento",
            "php",
        }:
            ecosystems.add("php")
    return {item for item in ecosystems if item}


def _required_inputs(classes: Sequence[str]) -> Set[str]:
    inputs: Set[str] = set()
    for name in classes:
        inputs |= _CLASS_INPUTS.get(name, set())
    return inputs


def select_tools(
    record: VulnerabilityRecord,
    project: Optional[ProjectProfile] = None,
    scope: Optional[SelectionScope] = None,
    capabilities: Optional[Sequence[ToolCapability]] = None,
    *,
    min_score: float = 0.0,
) -> ToolSelectionResult:
    """Select the tools that may test ``record`` inside ``scope``.

    The function is pure: it reads the advisory, the project profile, the
    scope, and the capability catalog, and returns a plan.  Nothing is
    executed.
    """
    scope = scope or SelectionScope()
    catalog = list(capabilities or [])
    project_id = project.project_id if project is not None else "unknown"

    analysis = classify_vuln_classes(record)
    notes: List[str] = [
        "Selection is advisory only: no tool was executed and no target was contacted."
    ]

    if not analysis.classes:
        return ToolSelectionResult(
            vuln_id=record.record_id,
            project_id=project_id,
            status="insufficient_evidence",
            authorized=scope.authorized,
            vuln_classes=[],
            class_evidence=analysis.evidence,
            selected=[],
            rejected=[],
            notes=notes + ["the advisory carries no vulnerability-class evidence"],
        )

    applicability: Optional[Applicability] = None
    if project is not None:
        triage = triage_project(project, record)
        applicability = triage.classification
        if triage.classification == Applicability.NOT_APPLICABLE:
            return ToolSelectionResult(
                vuln_id=record.record_id,
                project_id=project_id,
                status="not_applicable",
                authorized=scope.authorized,
                vuln_classes=analysis.classes,
                class_evidence=analysis.evidence,
                applicability=triage.classification.value,
                selected=[],
                rejected=[],
                notes=notes
                + [
                    "the advisory does not apply to the project inventory; "
                    "no tool was selected"
                ],
            )
        if triage.classification == Applicability.INSUFFICIENT_EVIDENCE:
            notes.append(
                "applicability is INSUFFICIENT_EVIDENCE: the selection is a "
                "hypothesis, not a confirmed finding"
            )
        else:
            notes.append(f"applicability: {triage.classification.value}")

    target_ecosystems = _project_ecosystems(project)
    required_inputs = _required_inputs(analysis.classes)

    selected: List[ToolSelection] = []
    rejected: List[RejectedTool] = []

    for capability in sorted(catalog, key=lambda item: item.tool_id):
        reason = _reject_reason(
            capability,
            scope=scope,
            classes=analysis.classes,
            target_ecosystems=target_ecosystems,
            required_inputs=required_inputs,
        )
        if reason is not None:
            rejected.append(RejectedTool(tool_id=capability.tool_id, reason=reason))
            continue

        matched_classes = sorted(set(capability.vuln_classes) & set(analysis.classes))
        matched_ecosystems = sorted(set(capability.ecosystems) & target_ecosystems)
        matched_inputs = sorted(set(capability.input_types) & required_inputs)

        score = _CLASS_SCORE * min(len(matched_classes), _MAX_CLASS_BONUS)
        reasons = [
            f"matches vulnerability class(es): {', '.join(matched_classes)}",
        ]
        if matched_ecosystems:
            score += _ECOSYSTEM_SCORE
            reasons.append(f"matches project ecosystem(s): {', '.join(matched_ecosystems)}")
        elif not capability.ecosystems:
            reasons.append("tool is ecosystem agnostic")
        elif not target_ecosystems:
            reasons.append("target ecosystem is unknown; ecosystem match not scored")
        if matched_inputs:
            score += _INPUT_SCORE
            reasons.append(f"accepts input type(s): {', '.join(matched_inputs)}")
        if capability.availability == ToolAvailability.INSTALLED:
            score += _AVAILABILITY_SCORE
            reasons.append("tool is available on this machine")
        else:
            reasons.append(
                f"availability is '{capability.availability.value}' (assumed available by the caller)"
            )
        score += round(capability.reliability * _RELIABILITY_WEIGHT, 2)
        reasons.append(f"reliability estimate: {capability.reliability:.2f}")
        if capability.test_coverage is not None:
            score += round(capability.test_coverage * _COVERAGE_WEIGHT, 2)
            reasons.append(f"test coverage estimate: {capability.test_coverage:.2f}")
        score += _RISK_BONUS.get(capability.risk_level, 0.0)
        reasons.append(f"risk level: {capability.risk_level}")

        if score < min_score:
            rejected.append(
                RejectedTool(
                    tool_id=capability.tool_id,
                    reason=f"score {round(score, 2)} is below the minimum score {min_score}",
                )
            )
            continue

        selected.append(
            ToolSelection(
                tool_id=capability.tool_id,
                name=capability.name or capability.tool_id,
                score=round(score, 2),
                risk_level=capability.risk_level,
                availability=capability.availability.value,
                matched_classes=matched_classes,
                matched_ecosystems=matched_ecosystems,
                reasons=reasons,
                limitations=list(capability.limitations),
            )
        )

    selected.sort(key=lambda item: (-item.score, item.tool_id))
    rejected.sort(key=lambda item: item.tool_id)

    if selected:
        status = "selected"
    elif not scope.authorized and any(
        "authorization" in item.reason for item in rejected
    ):
        # Authorization was an actual blocker, not just a missing capability.
        status = "not_authorized"
    else:
        status = "no_match"

    return ToolSelectionResult(
        vuln_id=record.record_id,
        project_id=project_id,
        status=status,
        authorized=scope.authorized,
        vuln_classes=analysis.classes,
        class_evidence=analysis.evidence,
        applicability=applicability.value if applicability is not None else None,
        selected=selected,
        rejected=rejected,
        notes=notes,
    )


def _reject_reason(
    capability: ToolCapability,
    *,
    scope: SelectionScope,
    classes: Sequence[str],
    target_ecosystems: Set[str],
    required_inputs: Set[str],
) -> Optional[str]:
    """Return the reason this tool must not be selected, or ``None``."""
    if capability.active and not scope.authorized:
        return "active testing requires explicit authorization"
    if capability.requires_authorization and not scope.authorized:
        return "tool requires explicit authorization"
    tool_risk = _RISK_ORDER.get(capability.risk_level, _RISK_ORDER["medium"])
    max_risk = _RISK_ORDER.get(scope.max_risk, _RISK_ORDER["low"])
    if tool_risk > max_risk:
        return (
            f"risk level '{capability.risk_level}' exceeds the granted maximum "
            f"'{scope.max_risk}'"
        )
    if scope.allowed_tools is not None and capability.tool_id not in scope.allowed_tools:
        return "not in the authorized tool allowlist"
    if scope.require_installed and capability.availability != ToolAvailability.INSTALLED:
        return (
            f"availability is '{capability.availability.value}'; the tool was not "
            "verified as installed on this machine"
        )
    if scope.require_limitations and not capability.limitations:
        return "tool has no documented limitations"
    if not (set(capability.vuln_classes) & set(classes)):
        return "no matching vulnerability class"
    if capability.ecosystems and target_ecosystems:
        if not (set(capability.ecosystems) & target_ecosystems):
            return (
                f"ecosystem mismatch: tool supports {', '.join(sorted(capability.ecosystems))}, "
                f"project uses {', '.join(sorted(target_ecosystems))}"
            )
    if capability.input_types and required_inputs:
        if not (set(capability.input_types) & required_inputs):
            return (
                f"input type mismatch: tool accepts {', '.join(sorted(capability.input_types))}, "
                f"the class needs {', '.join(sorted(required_inputs))}"
            )
    return None
