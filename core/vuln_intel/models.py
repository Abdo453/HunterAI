"""Normalized vulnerability-intelligence models.

Design rules
------------
* Missing information is ``None``/``unknown``; it is never invented.
* ``published_at`` (source) and ``imported_at`` (ours) are separate fields.
* ``confidence`` describes source evidence, not model opinion.
* Advisory text is data.  Nothing in this module executes or interprets it as
  an instruction.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .versions import compare_versions, normalize_package_name, parse_version, version_in_range


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: Optional[datetime]) -> Optional[datetime]:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Confidence(str, Enum):
    CONFIRMED_BY_AUTHORITATIVE_SOURCE = "CONFIRMED_BY_AUTHORITATIVE_SOURCE"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    PROVISIONAL = "PROVISIONAL"
    UNVERIFIED = "UNVERIFIED"
    CONTRADICTED_BY_EVIDENCE = "CONTRADICTED_BY_EVIDENCE"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"
    UNKNOWN = "unknown"


class VulnStatus(str, Enum):
    ANALYZED = "analyzed"
    MODIFIED = "modified"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    UNKNOWN = "unknown"


class Ecosystem(str, Enum):
    CPE = "cpe"
    COMPOSER = "composer"
    PACKAGIST = "packagist"
    NPM = "npm"
    PYPI = "pypi"
    GO = "go"
    MAVEN = "maven"
    NUGET = "nuget"
    RUBYGEMS = "rubygems"
    CRATES = "crates"
    WORDPRESS = "wordpress"
    DRUPAL = "drupal"
    MAGENTO = "magento"
    PHP = "php"
    OTHER = "other"
    UNKNOWN = "unknown"


class PhpComponent(str, Enum):
    RUNTIME = "runtime"
    EXTENSION = "extension"
    FRAMEWORK = "framework"
    PACKAGE = "package"
    APPLICATION = "application"
    SERVER_CONFIG = "server_config"
    UNKNOWN = "unknown"


class Applicability(str, Enum):
    CONFIRMED_APPLICABLE = "CONFIRMED_APPLICABLE"
    LIKELY_APPLICABLE = "LIKELY_APPLICABLE"
    POSSIBLY_APPLICABLE = "POSSIBLY_APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class CvssData(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Optional[str] = None
    score: Optional[float] = None
    vector: Optional[str] = None
    severity: Optional[Severity] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None

    @field_validator("score")
    @classmethod
    def _score_range(cls, value: Optional[float]) -> Optional[float]:
        if value is None:
            return None
        if not 0.0 <= float(value) <= 10.0:
            raise ValueError("CVSS score must be between 0 and 10")
        return float(value)


class AffectedPackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem: Ecosystem = Ecosystem.UNKNOWN
    vendor: Optional[str] = None
    product: Optional[str] = None
    package_name: Optional[str] = None
    cpe: Optional[str] = None
    cpe_version: Optional[str] = None
    version_start_including: Optional[str] = None
    version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    fixed_version: Optional[str] = None
    configuration: Dict[str, Any] = Field(default_factory=dict)

    @property
    def dedupe_key(self) -> str:
        parts = [
            self.ecosystem.value if isinstance(self.ecosystem, Ecosystem) else str(self.ecosystem),
            self.vendor or "",
            self.product or "",
            self.package_name or "",
            self.cpe or "",
            self.cpe_version or "",
            self.version_start_including or "",
            self.version_start_excluding or "",
            self.version_end_including or "",
            self.version_end_excluding or "",
        ]
        return "|".join(parts).lower()

    def matches_version(self, installed_version: Optional[str]) -> Optional[bool]:
        """Return True/False, or None when the version is unknown.

        A fixed version is honoured first: if the installed version is at or
        above the documented fixed version, it is not affected by this range.
        """
        if not installed_version:
            return None

        if self.fixed_version:
            cmp_fixed = compare_versions(installed_version, self.fixed_version)
            if cmp_fixed is None:
                return None
            if cmp_fixed >= 0:
                return False

        has_range = any(
            [
                self.version_start_including,
                self.version_start_excluding,
                self.version_end_including,
                self.version_end_excluding,
            ]
        )
        if has_range:
            return version_in_range(
                installed_version,
                start_including=self.version_start_including,
                start_excluding=self.version_start_excluding,
                end_including=self.version_end_including,
                end_excluding=self.version_end_excluding,
            )

        if self.cpe_version and self.cpe_version not in {"*", "-"}:
            cmp_exact = compare_versions(installed_version, self.cpe_version)
            if cmp_exact is None:
                return None
            return cmp_exact == 0

        return None


class Reference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    ref_type: str = "web"  # advisory | patch | exploit | web | other
    source: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class Provenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    source_record_id: str
    url: Optional[str] = None
    retrieved_at: datetime = Field(default_factory=utc_now)
    raw_sha256: Optional[str] = None
    license: str = "unknown"

    @field_validator("retrieved_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return ensure_utc(value)  # type: ignore[return-value]


class VulnerabilityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    source_record_id: str
    canonical_id: str

    title: Optional[str] = None
    description: Optional[str] = None
    summary: Optional[str] = None

    published_at: Optional[datetime] = None
    last_modified_at: Optional[datetime] = None
    discovery_at: Optional[datetime] = None
    disclosed_at: Optional[datetime] = None
    imported_at: datetime = Field(default_factory=utc_now)

    vuln_status: VulnStatus = VulnStatus.UNKNOWN
    severity: Severity = Severity.UNKNOWN
    cvss: Optional[CvssData] = None
    cwes: List[str] = Field(default_factory=list)

    affected: List[AffectedPackage] = Field(default_factory=list)
    references: List[Reference] = Field(default_factory=list)
    aliases: List[str] = Field(default_factory=list)

    known_exploited: Optional[bool] = None
    remediation: Optional[str] = None
    workarounds: List[str] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)

    confidence: Confidence = Confidence.UNVERIFIED
    provenance: List[Provenance] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "published_at",
        "last_modified_at",
        "discovery_at",
        "disclosed_at",
        "imported_at",
        mode="before",
    )
    @classmethod
    def _parse_datetime(cls, value: Any) -> Any:
        if value is None or isinstance(value, datetime):
            return ensure_utc(value) if isinstance(value, datetime) else None
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return None
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError:
                return None
            return ensure_utc(parsed)
        return value

    @field_validator("cwes")
    @classmethod
    def _normalize_cwes(cls, values: List[str]) -> List[str]:
        out: List[str] = []
        for value in values:
            text = str(value).strip().upper()
            if text and text not in out:
                out.append(text)
        return out

    @field_validator("aliases")
    @classmethod
    def _normalize_aliases(cls, values: List[str]) -> List[str]:
        out: List[str] = []
        for value in values:
            text = str(value).strip().upper()
            if text and text not in out:
                out.append(text)
        return out

    @property
    def record_id(self) -> str:
        """Stable primary key used by the store."""
        canonical = (self.canonical_id or "").strip().upper()
        if canonical:
            return canonical
        return f"{self.source_id}:{self.source_record_id}".upper()

    def all_identifiers(self) -> List[str]:
        ids = {self.record_id, (self.canonical_id or "").strip().upper()}
        ids.update(alias.upper() for alias in self.aliases)
        return sorted(item for item in ids if item)

    def compute_content_hash(self) -> str:
        payload = self.model_dump(mode="json", exclude={"imported_at", "provenance"})
        payload["cwes"] = sorted(set(payload.get("cwes") or []))
        payload["aliases"] = sorted(set(payload.get("aliases") or []))
        payload["affected"] = sorted(
            payload.get("affected") or [],
            key=lambda item: json.dumps(item, sort_keys=True, default=str),
        )
        payload["references"] = sorted(
            payload.get("references") or [],
            key=lambda item: (item.get("url") or "", json.dumps(item, sort_keys=True, default=str)),
        )
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class SyncStatus(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


class SyncReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    source_id: str
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: Optional[datetime] = None
    status: SyncStatus = SyncStatus.RUNNING
    requested_start: Optional[datetime] = None
    requested_end: Optional[datetime] = None

    pages_fetched: int = 0
    records_retrieved: int = 0
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0
    duplicates: int = 0
    rejected: int = 0
    errors: int = 0

    coverage_by_year: Dict[str, int] = Field(default_factory=dict)
    missing_intervals: List[str] = Field(default_factory=list)
    notes: List[str] = Field(default_factory=list)

    def finish(self, status: SyncStatus, notes: Optional[List[str]] = None) -> "SyncReport":
        self.finished_at = utc_now()
        self.status = status
        if notes:
            self.notes.extend(notes)
        return self

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class CoverageReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    requested_start: datetime
    requested_end: datetime
    measured_start: Optional[datetime] = None
    measured_end: Optional[datetime] = None
    records_total: int = 0
    months_requested: int = 0
    months_covered: int = 0
    missing_months: List[str] = Field(default_factory=list)
    by_year: Dict[str, int] = Field(default_factory=dict)
    complete: bool = False
    source_limitations: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)
    notes: List[str] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class ProjectPackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: Optional[str] = None
    ecosystem: Ecosystem = Ecosystem.COMPOSER
    source: Optional[str] = None

    @field_validator("name")
    @classmethod
    def _name_not_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("package name must not be empty")
        return value


class ProjectProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str
    name: Optional[str] = None
    ecosystem: Ecosystem = Ecosystem.COMPOSER
    packages: List[ProjectPackage] = Field(default_factory=list)
    php_version: Optional[str] = None
    frameworks: Dict[str, str] = Field(default_factory=dict)
    manifests: List[str] = Field(default_factory=list)
    inventory_complete: bool = True
    last_scan: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TriageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vuln_id: str
    project_id: str
    classification: Applicability
    confidence: Confidence
    reasons: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    matched_packages: List[str] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)
    recommended_action: str = ""
    evaluated_at: datetime = Field(default_factory=utc_now)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class PhpAnalysis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    involves_php: bool = False
    component_type: PhpComponent = PhpComponent.UNKNOWN
    component_names: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    confidence: Confidence = Confidence.UNVERIFIED
    notes: List[str] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json")


class UpsertResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    record_id: str
    status: str  # inserted | updated | unchanged | duplicate
    aliases_added: int = 0
    message: str = ""


def record_from_stored(data: Dict[str, Any]) -> VulnerabilityRecord:
    """Rebuild a validated record from a hydrated store row.

    Store rows contain bookkeeping columns (``record_id``, ``content_hash``,
    ``created_at`` ...) that are not part of the normalized model.  This helper
    filters them so triage/CLI code never has to hand-build a record.
    """
    allowed = set(VulnerabilityRecord.model_fields)
    payload: Dict[str, Any] = {key: data[key] for key in allowed if key in data}

    if "affected" in payload and isinstance(payload["affected"], list):
        pkg_fields = set(AffectedPackage.model_fields)
        payload["affected"] = [
            {key: value for key, value in item.items() if key in pkg_fields}
            for item in payload["affected"]
            if isinstance(item, dict)
        ]
    if "references" in payload and isinstance(payload["references"], list):
        ref_fields = set(Reference.model_fields)
        payload["references"] = [
            {key: value for key, value in item.items() if key in ref_fields}
            for item in payload["references"]
            if isinstance(item, dict)
        ]
    if "provenance" in payload and isinstance(payload["provenance"], list):
        prov_fields = set(Provenance.model_fields)
        payload["provenance"] = [
            {key: value for key, value in item.items() if key in prov_fields}
            for item in payload["provenance"]
            if isinstance(item, dict)
        ]
    if "cvss" in payload and isinstance(payload["cvss"], dict):
        cvss_fields = set(CvssData.model_fields)
        payload["cvss"] = {
            key: value for key, value in payload["cvss"].items() if key in cvss_fields
        }
    return VulnerabilityRecord.model_validate(payload)


__all__ = [
    "AffectedPackage",
    "Applicability",
    "Confidence",
    "CoverageReport",
    "CvssData",
    "Ecosystem",
    "PhpAnalysis",
    "PhpComponent",
    "ProjectPackage",
    "ProjectProfile",
    "Provenance",
    "Reference",
    "Severity",
    "SyncReport",
    "SyncStatus",
    "TriageResult",
    "UpsertResult",
    "VulnStatus",
    "VulnerabilityRecord",
    "ensure_utc",
    "normalize_package_name",
    "parse_version",
    "record_from_stored",
    "utc_now",
]
