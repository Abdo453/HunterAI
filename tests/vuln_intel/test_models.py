"""Normalized model behavior: ranges, hashing, and store round-trips."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.vuln_intel.models import (
    AffectedPackage,
    Applicability,
    Confidence,
    CvssData,
    Ecosystem,
    ProjectPackage,
    ProjectProfile,
    Provenance,
    Reference,
    Severity,
    VulnerabilityRecord,
    record_from_stored,
)


def test_affected_package_range_and_fixed_version():
    pkg = AffectedPackage(
        ecosystem=Ecosystem.COMPOSER,
        package_name="laravel/framework",
        version_start_including="10.0.0",
        version_end_excluding="10.2.1",
        fixed_version="10.2.1",
    )
    assert pkg.matches_version("10.1.0") is True
    assert pkg.matches_version("10.2.1") is False
    assert pkg.matches_version("9.9.9") is False
    assert pkg.matches_version("10.3.0") is False
    assert pkg.matches_version(None) is None
    assert pkg.matches_version("not-a-version") is None


def test_affected_package_exact_cpe_version():
    pkg = AffectedPackage(
        ecosystem=Ecosystem.CPE,
        vendor="php",
        product="php",
        cpe="cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*",
        cpe_version="8.1.0",
    )
    assert pkg.matches_version("8.1.0") is True
    assert pkg.matches_version("8.1.1") is False
    assert pkg.matches_version("8.1.0-1ubuntu1") is True


def test_affected_package_without_usable_version_returns_none():
    pkg = AffectedPackage(ecosystem=Ecosystem.CPE, vendor="php", product="php")
    assert pkg.matches_version("8.1.0") is None


def test_content_hash_is_stable_and_ignores_import_time_and_provenance(make_record):
    first = make_record(
        imported_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        provenance=[
            Provenance(
                source_id="nvd",
                source_record_id="CVE-2024-0001",
                retrieved_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )
        ],
    )
    second = make_record(
        imported_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
        provenance=[
            Provenance(
                source_id="nvd",
                source_record_id="CVE-2024-0001",
                retrieved_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
            )
        ],
    )
    assert first.compute_content_hash() == second.compute_content_hash()


def test_content_hash_changes_when_evidence_changes(make_record):
    first = make_record(description="one")
    second = make_record(description="two")
    assert first.compute_content_hash() != second.compute_content_hash()


def test_record_from_stored_round_trips_a_hydrated_row(store, make_record):
    record = make_record(
        severity=Severity.CRITICAL,
        cvss=CvssData(version="3.1", score=9.8, severity=Severity.CRITICAL),
        affected=[
            AffectedPackage(
                ecosystem=Ecosystem.COMPOSER,
                package_name="laravel/framework",
                version_start_including="10.0.0",
                version_end_excluding="10.2.1",
            )
        ],
        references=[Reference(url="https://example.test/a", tags=["advisory"])],
    )
    store.upsert_vulnerability(record)
    row = store.get("CVE-2024-0001")
    assert row is not None
    restored = record_from_stored(row)
    assert restored.record_id == record.record_id
    assert restored.description == record.description
    assert restored.severity == Severity.CRITICAL
    assert restored.cvss is not None
    assert restored.cvss.score == 9.8
    assert restored.cvss.severity == Severity.CRITICAL
    assert restored.affected[0].package_name == "laravel/framework"
    assert restored.references[0].tags == ["advisory"]


def test_project_profile_rejects_extra_fields():
    with pytest.raises(Exception):
        ProjectProfile.model_validate(
            {"project_id": "demo", "packages": [], "unexpected": True}
        )


def test_project_package_rejects_empty_name():
    with pytest.raises(Exception):
        ProjectPackage(name="   ")


def test_triage_result_serializes_enums():
    from core.vuln_intel.models import TriageResult

    result = TriageResult(
        vuln_id="CVE-2024-0001",
        project_id="demo",
        classification=Applicability.CONFIRMED_APPLICABLE,
        confidence=Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE,
    )
    payload = result.to_dict()
    assert payload["classification"] == "CONFIRMED_APPLICABLE"
    assert payload["confidence"] == "CONFIRMED_BY_AUTHORITATIVE_SOURCE"


def test_vulnerability_record_rejects_extra_fields(make_record):
    with pytest.raises(Exception):
        VulnerabilityRecord(
            source_id="nvd",
            source_record_id="CVE-2024-0001",
            canonical_id="CVE-2024-0001",
            unexpected=True,
        )
