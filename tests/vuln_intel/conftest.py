"""Shared fixtures for the vulnerability-intelligence tests.

These tests are hermetic: they use a temporary SQLite file and never touch the
network.  The opt-in live NVD test lives under ``tests/integration``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pytest

from core.vuln_intel.db import VulnerabilityStore
from core.vuln_intel.models import (
    AffectedPackage,
    Ecosystem,
    ProjectPackage,
    ProjectProfile,
    Reference,
    Severity,
    VulnerabilityRecord,
)


@pytest.fixture
def store(tmp_path):
    return VulnerabilityStore(tmp_path / "vuln_intel.sqlite3")


@pytest.fixture
def make_record():
    def _make(**overrides: Any) -> VulnerabilityRecord:
        source_record_id = overrides.pop("source_record_id", "CVE-2024-0001")
        canonical_id = overrides.pop("canonical_id", source_record_id)
        data: Dict[str, Any] = {
            "source_id": "nvd",
            "source_record_id": source_record_id,
            "canonical_id": canonical_id,
            "description": "A test advisory.",
            "published_at": datetime(2024, 1, 15, tzinfo=timezone.utc),
            "severity": Severity.HIGH,
            "cwes": ["CWE-79"],
            "affected": [],
            "references": [],
        }
        data.update(overrides)
        return VulnerabilityRecord(**data)

    return _make


@pytest.fixture
def make_package():
    def _make(
        name: str,
        version: Optional[str] = None,
        *,
        ecosystem: Ecosystem = Ecosystem.COMPOSER,
    ) -> ProjectPackage:
        return ProjectPackage(name=name, version=version, ecosystem=ecosystem)

    return _make


@pytest.fixture
def make_project(make_package):
    def _make(
        packages: Optional[List[Any]] = None,
        *,
        php_version: Optional[str] = None,
        inventory_complete: bool = True,
        project_id: str = "demo",
    ) -> ProjectProfile:
        normalized = []
        for pkg in packages or []:
            if isinstance(pkg, ProjectPackage):
                normalized.append(pkg)
            elif isinstance(pkg, dict):
                normalized.append(ProjectPackage(**pkg))
            else:
                normalized.append(make_package(*pkg))
        return ProjectProfile(
            project_id=project_id,
            packages=normalized,
            php_version=php_version,
            inventory_complete=inventory_complete,
        )

    return _make


@pytest.fixture
def cpe_package():
    def _make(
        vendor: str,
        product: str,
        *,
        version: Optional[str] = None,
        start_including: Optional[str] = None,
        start_excluding: Optional[str] = None,
        end_including: Optional[str] = None,
        end_excluding: Optional[str] = None,
        fixed_version: Optional[str] = None,
    ) -> AffectedPackage:
        cpe = f"cpe:2.3:a:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"
        return AffectedPackage(
            ecosystem=Ecosystem.CPE,
            vendor=vendor,
            product=product,
            package_name=product,
            cpe=cpe,
            cpe_version=version,
            version_start_including=start_including,
            version_start_excluding=start_excluding,
            version_end_including=end_including,
            version_end_excluding=end_excluding,
            fixed_version=fixed_version,
        )

    return _make


@pytest.fixture
def composer_package():
    def _make(
        name: str,
        *,
        start_including: Optional[str] = None,
        start_excluding: Optional[str] = None,
        end_including: Optional[str] = None,
        end_excluding: Optional[str] = None,
        fixed_version: Optional[str] = None,
    ) -> AffectedPackage:
        return AffectedPackage(
            ecosystem=Ecosystem.COMPOSER,
            package_name=name,
            version_start_including=start_including,
            version_start_excluding=start_excluding,
            version_end_including=end_including,
            version_end_excluding=end_excluding,
            fixed_version=fixed_version,
        )

    return _make


@pytest.fixture
def reference():
    def _make(url: str = "https://example.test/advisory", **kwargs: Any) -> Reference:
        return Reference(url=url, **kwargs)

    return _make
