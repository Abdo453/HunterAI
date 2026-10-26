"""Resumable sync engine: checkpoints, idempotency, rejection, and failures."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List

import pytest

from core.vuln_intel.models import SyncStatus, VulnerabilityRecord
from core.vuln_intel.sources.base import (
    Cursor,
    Page,
    SourceConnector,
    SourceMetadata,
)
from core.vuln_intel.sync import SyncEngine, SyncInterrupted, split_windows


class FakeConnector(SourceConnector):
    metadata = SourceMetadata(
        source_id="fake",
        name="Fake source",
        base_url="https://example.test",
        max_window_days=120,
        rate_limit_requests=1000,
        rate_limit_period_seconds=0.0,
    )

    def __init__(self, pages: List[List[Any]], *, fail_on_page: int | None = None):
        self.pages = pages
        self.fail_on_page = fail_on_page
        self.calls: List[dict] = []

    async def fetch_page(self, *, start, end, cursor: Cursor, page_size: int) -> Page:
        self.calls.append(
            {
                "start": start,
                "end": end,
                "cursor": cursor.to_dict(),
                "page_size": page_size,
            }
        )
        if self.fail_on_page is not None and cursor.start_index == self.fail_on_page:
            raise RuntimeError("simulated source failure")
        index = int(cursor.start_index)
        records = self.pages[index] if index < len(self.pages) else []
        next_cursor = (
            Cursor(start_index=index + 1, page=int(cursor.page) + 1)
            if index + 1 < len(self.pages)
            else None
        )
        return Page(records=records, next_cursor=next_cursor, total_results=None)

    def normalize(self, raw: Any) -> VulnerabilityRecord:
        if isinstance(raw, VulnerabilityRecord):
            record = raw
        else:
            record = VulnerabilityRecord.model_validate(raw)
        # Real connectors stamp their own source id; the fake must do the same
        # so source-scoped queries exercise the intended rows.
        return record.model_copy(update={"source_id": self.metadata.source_id})


def _window() -> tuple[datetime, datetime]:
    return (
        datetime(2024, 1, 1, tzinfo=timezone.utc),
        datetime(2024, 1, 31, 23, 59, 59, tzinfo=timezone.utc),
    )


@pytest.mark.asyncio
async def test_sync_inserts_all_pages_and_completes(store, make_record):
    start, end = _window()
    pages = [
        [make_record(source_record_id="CVE-2024-0001")],
        [
            make_record(source_record_id="CVE-2024-0002"),
            make_record(source_record_id="CVE-2024-0003"),
        ],
    ]
    connector = FakeConnector(pages)
    report = await SyncEngine(store, connector, page_size=10).run(start, end)

    assert report.status == SyncStatus.COMPLETED
    assert report.pages_fetched == 2
    assert report.records_retrieved == 3
    assert report.inserted == 3
    assert report.errors == 0
    assert report.coverage_by_year == {"2024": 3}
    assert store.count("fake") == 3

    checkpoint = store.get_checkpoint("fake", "2024-01-01..2024-01-31")
    assert checkpoint is not None
    assert checkpoint["completed"] is True


@pytest.mark.asyncio
async def test_sync_resumes_from_last_committed_page(store, make_record):
    start, end = _window()
    pages = [
        [make_record(source_record_id="CVE-2024-0001")],
        [make_record(source_record_id="CVE-2024-0002")],
        [make_record(source_record_id="CVE-2024-0003")],
    ]
    connector = FakeConnector(pages)

    first = await SyncEngine(store, connector, page_size=1, max_pages=1).run(start, end)
    assert first.status == SyncStatus.INTERRUPTED
    assert first.pages_fetched == 1
    assert first.inserted == 1
    assert store.count("fake") == 1
    checkpoint = store.get_checkpoint("fake", "2024-01-01..2024-01-31")
    assert checkpoint is not None
    assert checkpoint["completed"] is False
    assert checkpoint["cursor"]["start_index"] == 1

    second = await SyncEngine(store, connector, page_size=1, max_pages=None).run(start, end)
    assert second.status == SyncStatus.COMPLETED
    assert second.inserted == 2
    assert store.count("fake") == 3
    # The resumed run did not re-fetch page 0.
    assert connector.calls[1]["cursor"]["start_index"] == 1


@pytest.mark.asyncio
async def test_sync_is_idempotent_when_checkpoint_is_complete(store, make_record):
    start, end = _window()
    pages = [[make_record(source_record_id="CVE-2024-0001")]]
    connector = FakeConnector(pages)

    first = await SyncEngine(store, connector, page_size=10).run(start, end)
    assert first.inserted == 1

    second = await SyncEngine(store, connector, page_size=10).run(start, end)
    assert second.status == SyncStatus.COMPLETED
    assert second.pages_fetched == 0
    assert second.inserted == 0
    assert store.count("fake") == 1


@pytest.mark.asyncio
async def test_sync_resume_false_replays_and_deduplicates(store, make_record):
    start, end = _window()
    pages = [[make_record(source_record_id="CVE-2024-0001")]]
    connector = FakeConnector(pages)

    await SyncEngine(store, connector, page_size=10).run(start, end)
    replay = await SyncEngine(store, connector, page_size=10, resume=False).run(start, end)
    assert replay.status == SyncStatus.COMPLETED
    assert replay.pages_fetched == 1
    assert replay.unchanged == 1
    assert store.count("fake") == 1


@pytest.mark.asyncio
async def test_sync_rejects_invalid_records_and_continues(store, make_record):
    start, end = _window()
    pages = [[make_record(source_record_id="CVE-2024-0001"), {"bad": "record"}]]
    connector = FakeConnector(pages)
    report = await SyncEngine(store, connector, page_size=10).run(start, end)

    assert report.status == SyncStatus.COMPLETED
    assert report.inserted == 1
    assert report.rejected == 1
    assert report.errors == 1
    assert store.count("fake") == 1
    with store._connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sync_errors").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_sync_reports_source_failure(store):
    start, end = _window()
    connector = FakeConnector([[]], fail_on_page=0)
    report = await SyncEngine(store, connector, page_size=10).run(start, end)

    assert report.status == SyncStatus.FAILED
    assert report.notes
    assert "simulated source failure" in report.notes[0]
    row = store.get_sync_run(report.run_id)
    assert row is not None
    assert row["status"] == "failed"
    with store._connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM sync_errors").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_sync_validates_range(store):
    connector = FakeConnector([[]])
    with pytest.raises(ValueError):
        await SyncEngine(store, connector).run(
            datetime(2024, 1, 2, tzinfo=timezone.utc),
            datetime(2024, 1, 1, tzinfo=timezone.utc),
        )


def test_split_windows_overlaps_only_at_boundary():
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    windows = split_windows(start, end, 120)
    assert len(windows) == 4
    assert windows[0][0] == start
    assert windows[-1][1] == end
    for first, second in zip(windows, windows[1:]):
        assert first[1] == second[0]


def test_split_windows_without_limit_is_one_window():
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 12, 31, tzinfo=timezone.utc)
    assert split_windows(start, end, None) == [(start, end)]
    assert split_windows(start, end, 0) == [(start, end)]
    assert split_windows(start, end, -1) == [(start, end)]


def test_split_windows_rejects_reversed_range():
    with pytest.raises(ValueError):
        split_windows(
            datetime(2024, 1, 2, tzinfo=timezone.utc),
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            120,
        )


@pytest.mark.asyncio
async def test_sync_interrupts_between_windows_when_page_budget_is_spent(
    store, make_record
):
    connector = FakeConnector([[make_record(source_record_id="CVE-2024-0001")]])
    connector.metadata = SourceMetadata(
        source_id="fake",
        name="Fake source",
        base_url="https://example.test",
        max_window_days=1,
        rate_limit_requests=1000,
        rate_limit_period_seconds=0.0,
    )
    start = datetime(2024, 1, 1, tzinfo=timezone.utc)
    end = datetime(2024, 1, 3, tzinfo=timezone.utc)
    report = await SyncEngine(store, connector, page_size=10, max_pages=1).run(start, end)
    assert report.status == SyncStatus.INTERRUPTED
    assert report.pages_fetched == 1
    assert store.count("fake") == 1
