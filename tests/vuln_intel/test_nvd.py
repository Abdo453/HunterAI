"""NVD 2.0 connector: normalization and pagination without network access."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.vuln_intel.models import Confidence, Ecosystem, Severity, VulnStatus
from core.vuln_intel.sources.base import Cursor, SourceParseError
from core.vuln_intel.sources.nvd import NVDConnector, _parse_cpe


def _sample_cve() -> dict:
    return {
        "cve": {
            "id": "CVE-2024-1234",
            "sourceIdentifier": "security@example.test",
            "published": "2024-01-02T03:04:05.123",
            "lastModified": "2024-01-03T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [
                {"lang": "es", "value": "Texto en español"},
                {
                    "lang": "en",
                    "value": "A PHP application using laravel/framework is vulnerable to XSS.",
                },
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "availabilityImpact": "HIGH",
                        },
                    }
                ]
            },
            "weaknesses": [
                {"description": [{"lang": "en", "value": "CWE-79"}]},
                {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]},
            ],
            "configurations": [
                {
                    "source": "nvd@nist.gov",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "8.1.0",
                                    "versionEndExcluding": "8.1.27",
                                    "matchCriteriaId": "ABC",
                                },
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                                },
                            ],
                        }
                    ],
                }
            ],
            "references": [
                {
                    "url": "https://example.test/patch",
                    "source": "vendor",
                    "tags": ["Patch"],
                },
                {
                    "url": "https://example.test/advisory",
                    "source": "vendor",
                    "tags": ["Vendor Advisory"],
                },
            ],
        }
    }


def test_normalize_full_record():
    connector = NVDConnector()
    record = connector.normalize(_sample_cve())

    assert record.source_id == "nvd"
    assert record.source_record_id == "CVE-2024-1234"
    assert record.canonical_id == "CVE-2024-1234"
    assert record.description.startswith("A PHP application")
    assert record.published_at == datetime(2024, 1, 2, 3, 4, 5, 123000, tzinfo=timezone.utc)
    assert record.vuln_status == VulnStatus.ANALYZED
    assert record.severity == Severity.CRITICAL
    assert record.cvss is not None
    assert record.cvss.version == "3.1"
    assert record.cvss.score == 9.8
    assert record.cvss.attack_vector == "NETWORK"
    assert record.cwes == ["CWE-79"]
    assert len(record.affected) == 1
    pkg = record.affected[0]
    assert pkg.ecosystem == Ecosystem.CPE
    assert pkg.vendor == "php"
    assert pkg.product == "php"
    assert pkg.cpe_version == "8.1.0"
    assert pkg.version_start_including == "8.1.0"
    assert pkg.version_end_excluding == "8.1.27"
    assert pkg.configuration["match_criteria_id"] == "ABC"
    assert [ref.ref_type for ref in record.references] == ["patch", "advisory"]
    assert record.confidence == Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
    assert len(record.provenance) == 1
    assert len(record.provenance[0].raw_sha256 or "") == 64


def test_normalize_missing_optional_fields_is_honest():
    connector = NVDConnector()
    record = connector.normalize(
        {
            "cve": {
                "id": "CVE-2024-9999",
                "published": "2024-01-01T00:00:00.000",
                "vulnStatus": "Received",
                "descriptions": [{"lang": "en", "value": "An issue."}],
            }
        }
    )
    assert record.severity == Severity.UNKNOWN
    assert record.cvss is None
    assert record.cwes == []
    assert record.affected == []
    assert record.references == []
    assert record.vuln_status == VulnStatus.MODIFIED


def test_normalize_rejects_non_object():
    connector = NVDConnector()
    with pytest.raises(SourceParseError):
        connector.normalize([])  # type: ignore[arg-type]


def test_normalize_rejects_missing_cve_id():
    connector = NVDConnector()
    with pytest.raises(SourceParseError):
        connector.normalize({"cve": {"descriptions": []}})


def test_cvss_v2_fallback_version():
    raw = _sample_cve()
    raw["cve"]["metrics"] = {
        "cvssMetricV2": [
            {
                "type": "Primary",
                "cvssData": {
                    "baseScore": 5.0,
                    "baseSeverity": "MEDIUM",
                    "accessVector": "NETWORK",
                },
            }
        ]
    }
    record = NVDConnector().normalize(raw)
    assert record.cvss is not None
    assert record.cvss.version == "2.0"
    assert record.cvss.score == 5.0
    assert record.severity == Severity.MEDIUM


def test_parse_cpe_handles_escaped_colon():
    parts = _parse_cpe("cpe:2.3:a:vendor:product\\:name:1.0:*:*:*:*:*:*:*")
    assert parts["vendor"] == "vendor"
    assert parts["product"] == "product:name"
    assert parts["version"] == "1.0"


@pytest.mark.asyncio
async def test_fetch_page_builds_cursor_and_headers():
    calls = []

    async def fake_fetch(url, params, headers):
        calls.append((url, params, headers))
        return {
            "totalResults": 2,
            "vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}],
        }

    connector = NVDConnector(api_key="secret", fetch_json=fake_fetch)
    page = await connector.fetch_page(
        start=datetime(2024, 1, 1, tzinfo=timezone.utc),
        end=datetime(2024, 1, 31, 23, 59, 59, tzinfo=timezone.utc),
        cursor=Cursor(),
        page_size=1,
    )
    assert len(page.records) == 1
    assert page.total_results == 2
    assert page.next_cursor is not None
    assert page.next_cursor.start_index == 1
    assert page.next_cursor.page == 1
    assert calls[0][0] == "https://services.nvd.nist.gov/rest/json/cves/2.0"
    assert calls[0][1]["pubStartDate"] == "2024-01-01T00:00:00.000Z"
    assert calls[0][1]["pubEndDate"] == "2024-01-31T23:59:59.000Z"
    assert calls[0][1]["resultsPerPage"] == 1
    assert calls[0][2] == {"apiKey": "secret"}


@pytest.mark.asyncio
async def test_fetch_page_last_page_has_no_cursor():
    async def fake_fetch(url, params, headers):
        return {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}

    connector = NVDConnector(fetch_json=fake_fetch)
    page = await connector.fetch_page(
        start=datetime(2024, 1, 1, tzinfo=timezone.utc),
        end=datetime(2024, 1, 2, tzinfo=timezone.utc),
        cursor=Cursor(),
        page_size=1,
    )
    assert page.next_cursor is None


@pytest.mark.asyncio
async def test_fetch_page_validates_inputs():
    connector = NVDConnector(fetch_json=lambda *args: None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        await connector.fetch_page(
            start=datetime(2024, 1, 2, tzinfo=timezone.utc),
            end=datetime(2024, 1, 1, tzinfo=timezone.utc),
            cursor=Cursor(),
            page_size=1,
        )
    with pytest.raises(ValueError):
        await connector.fetch_page(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            cursor=Cursor(),
            page_size=0,
        )
    with pytest.raises(ValueError):
        await connector.fetch_page(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            cursor=Cursor(),
            page_size=2001,
        )


@pytest.mark.asyncio
async def test_fetch_page_rejects_malformed_payloads():
    async def not_a_dict(url, params, headers):
        return []

    connector = NVDConnector(fetch_json=not_a_dict)
    with pytest.raises(SourceParseError):
        await connector.fetch_page(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            cursor=Cursor(),
            page_size=1,
        )

    async def bad_vulnerabilities(url, params, headers):
        return {"totalResults": 1, "vulnerabilities": "not-a-list"}

    connector = NVDConnector(fetch_json=bad_vulnerabilities)
    with pytest.raises(SourceParseError):
        await connector.fetch_page(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            cursor=Cursor(),
            page_size=1,
        )
