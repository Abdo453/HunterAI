"""OSV.dev connector and normalizer (GHSA-capable, query based)."""
from __future__ import annotations

import json

import httpx
import pytest

from core.vuln_intel.db import VulnerabilityStore
from core.vuln_intel.models import Confidence, Ecosystem, Severity, VulnStatus
from core.vuln_intel.sources.base import (
    HttpClient,
    RateLimiter,
    RetryPolicy,
    SourceError,
    SourceParseError,
)
from core.vuln_intel.sources.osv import (
    OSV_METADATA,
    OSVConnector,
    normalize_osv_record,
)
from core.vuln_intel.triage import triage_project


def _ghsa_payload(**overrides):
    payload = {
        "id": "GHSA-abcd-1234-5678",
        "aliases": ["CVE-2024-12345"],
        "summary": "SQL injection in example/package",
        "details": "A SQL injection vulnerability affects example/package before 1.2.3.",
        "published": "2024-01-02T00:00:00Z",
        "modified": "2024-02-01T00:00:00Z",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ],
        "database_specific": {
            "severity": "HIGH",
            "cwe_ids": ["CWE-89"],
            "source": "GHSA",
        },
        "affected": [
            {
                "package": {"ecosystem": "Packagist", "name": "example/package"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                    }
                ],
            }
        ],
        "references": [
            {
                "type": "ADVISORY",
                "url": "https://github.com/advisories/GHSA-abcd-1234-5678",
            }
        ],
    }
    payload.update(overrides)
    return payload


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True)


def _http(client) -> HttpClient:
    return HttpClient(
        OSV_METADATA,
        client=client,
        rate_limiter=RateLimiter(1000, 0.0),
        retry_policy=RetryPolicy(max_attempts=1),
    )


def test_metadata_marks_osv_as_query_based():
    assert OSV_METADATA.source_id == "osv"
    assert OSV_METADATA.supports_incremental is False
    assert OSV_METADATA.max_window_days == 0
    assert OSV_METADATA.allowed_hosts == ("api.osv.dev",)


def test_normalize_uses_cve_as_canonical_and_keeps_ghsa_alias():
    record = normalize_osv_record(_ghsa_payload())
    assert record.source_id == "osv"
    assert record.source_record_id == "GHSA-abcd-1234-5678"
    assert record.canonical_id == "CVE-2024-12345"
    assert record.record_id == "CVE-2024-12345"
    assert "GHSA-ABCD-1234-5678" in record.aliases
    assert record.confidence == Confidence.STRONGLY_SUPPORTED


def test_normalize_extracts_severity_score_cwes_and_fix():
    record = normalize_osv_record(_ghsa_payload())
    assert record.severity == Severity.CRITICAL
    assert record.cvss is not None
    assert record.cvss.score == 9.8
    assert record.cvss.version == "3.1"
    assert record.cwes == ["CWE-89"]
    assert record.fixed_versions == ["1.2.3"]
    assert record.published_at is not None
    assert record.provenance[0].raw_sha256


def test_normalize_maps_packagist_ranges():
    record = normalize_osv_record(_ghsa_payload())
    assert len(record.affected) == 1
    affected = record.affected[0]
    assert affected.ecosystem == Ecosystem.PACKAGIST
    assert affected.package_name == "example/package"
    assert affected.version_start_including is None  # "0" means "all versions"
    assert affected.version_end_excluding == "1.2.3"
    assert affected.fixed_version == "1.2.3"


def test_normalize_uses_exact_versions_when_no_range_exists():
    payload = _ghsa_payload(
        affected=[
            {
                "package": {"ecosystem": "Packagist", "name": "example/package"},
                "versions": ["1.0.0", "1.1.0"],
            }
        ]
    )
    record = normalize_osv_record(payload)
    assert [item.cpe_version for item in record.affected] == ["1.0.0", "1.1.0"]
    assert record.fixed_versions == []


def test_normalize_never_turns_git_ranges_into_version_ranges():
    payload = _ghsa_payload(
        affected=[
            {
                "package": {"ecosystem": "GitHub Actions", "name": "org/repo"},
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [{"introduced": "0"}, {"fixed": "abc123"}],
                    }
                ],
            }
        ]
    )
    record = normalize_osv_record(payload)
    assert record.affected == []
    assert record.metadata["osv_git_ranges"]


def test_normalize_reads_cwes_from_ecosystem_specific():
    payload = _ghsa_payload(
        database_specific={"severity": "MODERATE"},
        severity=[],
        affected=[
            {
                "package": {"ecosystem": "Packagist", "name": "example/package"},
                "ecosystem_specific": {"cwe_ids": ["CWE-285"]},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                    }
                ],
            }
        ],
    )
    record = normalize_osv_record(payload)
    assert record.cwes == ["CWE-285"]
    assert record.severity == Severity.MEDIUM


def test_normalize_merges_cwes_from_every_machine_readable_location():
    payload = _ghsa_payload(
        database_specific={"severity": "HIGH", "cwe_ids": ["CWE-89"]},
        affected=[
            {
                "package": {"ecosystem": "Packagist", "name": "example/package"},
                "database_specific": {"cwe_ids": ["CWE-79"]},
                "ecosystem_specific": {"cwe_ids": ["CWE-285"]},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                    }
                ],
            }
        ],
    )
    record = normalize_osv_record(payload)
    assert record.cwes == ["CWE-285", "CWE-79", "CWE-89"]


def test_normalize_marks_withdrawn_records():
    record = normalize_osv_record(_ghsa_payload(withdrawn="2024-03-01T00:00:00Z"))
    assert record.vuln_status == VulnStatus.WITHDRAWN
    assert record.metadata["osv_withdrawn_at"].startswith("2024-03-01")


def test_normalize_rejects_records_without_id():
    with pytest.raises(SourceParseError):
        normalize_osv_record({"summary": "no id"})


def test_normalize_rejects_non_objects():
    with pytest.raises(SourceParseError):
        normalize_osv_record(["not", "an", "object"])


@pytest.mark.asyncio
async def test_query_package_posts_to_osv_and_returns_records():
    seen = {}

    async def handler(request):
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode("utf-8")
        return httpx.Response(200, json={"vulns": [_ghsa_payload()]})

    client = _client(handler)
    connector = OSVConnector(http_client=_http(client))
    try:
        records = await connector.query_package("example/package", "Packagist")
    finally:
        await client.aclose()

    assert seen["method"] == "POST"
    assert seen["url"].endswith("/v1/query")
    assert json.loads(seen["body"]) == {
        "package": {"name": "example/package", "ecosystem": "Packagist"}
    }
    assert len(records) == 1
    assert records[0]["id"] == "GHSA-abcd-1234-5678"


@pytest.mark.asyncio
async def test_query_package_includes_the_requested_version():
    seen = {}

    async def handler(request):
        seen["body"] = request.content.decode("utf-8")
        return httpx.Response(200, json=[])

    client = _client(handler)
    connector = OSVConnector(http_client=_http(client))
    try:
        records = await connector.query_package("example/package", "Packagist", "1.0.0")
    finally:
        await client.aclose()

    assert records == []
    assert json.loads(seen["body"])["package"]["version"] == "1.0.0"


@pytest.mark.asyncio
async def test_get_vuln_fetches_one_advisory():
    seen = {}

    async def handler(request):
        seen["url"] = str(request.url)
        return httpx.Response(200, json=_ghsa_payload())

    client = _client(handler)
    connector = OSVConnector(http_client=_http(client))
    try:
        raw = await connector.get_vuln("GHSA-abcd-1234-5678")
    finally:
        await client.aclose()

    assert seen["url"].endswith("/v1/vulns/GHSA-abcd-1234-5678")
    assert raw["id"] == "GHSA-abcd-1234-5678"


@pytest.mark.asyncio
async def test_fetch_page_is_refused_because_osv_has_no_date_ranges():
    connector = OSVConnector()
    with pytest.raises(SourceError):
        await connector.fetch_page(start=None, end=None, cursor=None, page_size=10)


def test_osv_record_merges_with_the_same_cve_from_another_source(store):
    osv_record = normalize_osv_record(_ghsa_payload())
    nvd_record = osv_record.model_copy(
        update={
            "source_id": "nvd",
            "source_record_id": "CVE-2024-12345",
            "canonical_id": "CVE-2024-12345",
            "aliases": ["CVE-2024-12345"],
        }
    )
    first = store.upsert_vulnerability(osv_record)
    second = store.upsert_vulnerability(nvd_record)
    assert first.status == "inserted"
    assert second.status == "updated"
    assert store.count() == 1
    assert store.get("GHSA-abcd-1234-5678") is not None


def test_osv_record_triages_against_a_project_inventory(store, make_project):
    record = normalize_osv_record(_ghsa_payload())
    store.upsert_vulnerability(record)
    project = make_project(
        [{"name": "example/package", "version": "1.0.0", "ecosystem": "packagist"}]
    )
    result = triage_project(project, record)
    assert result.classification.value == "CONFIRMED_APPLICABLE"
    assert result.matched_packages == ["example/package@1.0.0"]
    assert result.fixed_versions == ["1.2.3"]
