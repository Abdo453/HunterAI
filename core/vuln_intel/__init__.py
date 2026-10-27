"""HunterAI vulnerability intelligence.

A small, evidence-first subsystem:

* normalized advisory records (not raw blobs),
* SQLite source of truth with migrations,
* rate-limited/resumable connectors,
* honest coverage reporting,
* PHP-specific classification,
* project-aware applicability triage,
* OSV/GHSA package lookups,
* deterministic, authorization-aware tool selection.

It deliberately reuses the existing authorization/sandbox layers for any
active action; this package only performs read-only intelligence work and
never executes a tool.
"""
from __future__ import annotations

__version__ = "0.2.0"

from .models import (  # noqa: F401
    AffectedPackage,
    Applicability,
    Confidence,
    CoverageReport,
    CvssData,
    Ecosystem,
    PhpAnalysis,
    PhpComponent,
    ProjectPackage,
    ProjectProfile,
    Provenance,
    Reference,
    Severity,
    SyncReport,
    SyncStatus,
    TriageResult,
    UpsertResult,
    VulnStatus,
    VulnerabilityRecord,
)
from .tool_capabilities import (  # noqa: F401
    DEFAULT_CAPABILITIES,
    ToolAvailability,
    ToolCapability,
)
from .tool_selection import (  # noqa: F401
    RejectedTool,
    SelectionScope,
    ToolSelection,
    ToolSelectionResult,
)
from .vuln_classes import VulnClassAnalysis, classify_vuln_classes  # noqa: F401

__all__ = [
    "AffectedPackage",
    "Applicability",
    "Confidence",
    "CoverageReport",
    "CvssData",
    "DEFAULT_CAPABILITIES",
    "Ecosystem",
    "PhpAnalysis",
    "PhpComponent",
    "ProjectPackage",
    "ProjectProfile",
    "Provenance",
    "Reference",
    "RejectedTool",
    "SelectionScope",
    "Severity",
    "SyncReport",
    "SyncStatus",
    "ToolAvailability",
    "ToolCapability",
    "ToolSelection",
    "ToolSelectionResult",
    "TriageResult",
    "UpsertResult",
    "VulnClassAnalysis",
    "VulnStatus",
    "VulnerabilityRecord",
    "classify_vuln_classes",
]
