"""HunterAI vulnerability intelligence.

A small, evidence-first subsystem:

* normalized advisory records (not raw blobs),
* SQLite source of truth with migrations,
* rate-limited/resumable connectors,
* honest coverage reporting,
* PHP-specific classification,
* project-aware applicability triage.

It deliberately reuses the existing authorization/sandbox layers for any
active action; this package only performs read-only intelligence work.
"""
from __future__ import annotations

__version__ = "0.1.0"

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
]
