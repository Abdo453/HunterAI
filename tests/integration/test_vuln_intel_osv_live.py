"""Opt-in live OSV.dev smoke test (which also exercises GHSA data).

Run explicitly::

    $env:RUN_LIVE_OSV = "1"
    python -m pytest tests/integration/test_vuln_intel_osv_live.py -q

It is skipped by default so the normal suite stays hermetic.  The test only
performs read-only queries against the public OSV API.
"""
from __future__ import annotations

import os

import pytest

from core.vuln_intel.sources.osv import OSVConnector, normalize_osv_record

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_LIVE_OSV") != "1",
        reason="set RUN_LIVE_OSV=1 to allow real OSV.dev requests",
    ),
]

# A widely mirrored package: the exact advisory set changes over time, so the
# assertions below check shape and consistency, never a fixed count.
PACKAGE = "symfony/http-kernel"
ECOSYSTEM = "Packagist"


@pytest.mark.asyncio
async def test_live_osv_package_query_returns_advisories():
    connector = OSVConnector()
    try:
        records = await connector.query_package(PACKAGE, ECOSYSTEM)
    finally:
        await connector.aclose()

    assert isinstance(records, list)
    for raw in records:
        assert isinstance(raw, dict)
        assert raw.get("id")

    if not records:
        pytest.skip("OSV currently returns no advisory for the probe package")


@pytest.mark.asyncio
async def test_live_osv_single_advisory_normalizes():
    connector = OSVConnector()
    try:
        records = await connector.query_package(PACKAGE, ECOSYSTEM)
        if not records:
            pytest.skip("OSV currently returns no advisory for the probe package")
        raw = await connector.get_vuln(records[0]["id"])
    finally:
        await connector.aclose()

    record = normalize_osv_record(raw)
    assert record.source_id == "osv"
    assert record.source_record_id == raw["id"]
    assert record.record_id
    assert record.provenance[0].raw_sha256
    assert record.confidence is not None
