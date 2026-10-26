"""Opt-in live NVD smoke test.

Run explicitly::

    $env:RUN_LIVE_NVD = "1"
    python -m pytest tests/integration/test_vuln_intel_nvd_live.py -q

It is skipped by default so the normal suite stays hermetic.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

from core.vuln_intel.sources.base import Cursor
from core.vuln_intel.sources.nvd import NVDConnector

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_LIVE_NVD") != "1",
        reason="set RUN_LIVE_NVD=1 to allow one real NVD request",
    ),
]


@pytest.mark.asyncio
async def test_live_nvd_one_day_one_page():
    connector = NVDConnector()
    try:
        page = await connector.fetch_page(
            start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            cursor=Cursor(),
            page_size=1,
        )
    finally:
        await connector.aclose()

    assert isinstance(page.records, list)
    assert page.raw_count == len(page.records)
    if page.records:
        record = connector.normalize(page.records[0])
        assert record.source_id == "nvd"
        assert record.canonical_id.startswith("CVE-")
