"""Resumable synchronization engine.

The engine is deliberately source-agnostic: it drives a ``SourceConnector``,
validates normalized records, writes them through ``VulnerabilityStore``, and
persists a checkpoint after every successful page.

If a run is interrupted (max-pages guard, test-injected interruption, or
cancellation), the checkpoint remains at the last committed page.  A later run
with ``resume=True`` continues from there and does not duplicate records.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .db import VulnerabilityStore
from .models import (
    SyncReport,
    SyncStatus,
    VulnerabilityRecord,
    ensure_utc,
    utc_now,
)
from .sources.base import Cursor, SourceConnector

logger = logging.getLogger("core.vuln_intel.sync")


class SyncInterrupted(Exception):
    """Raised by the engine (or a test connector) to stop at a page boundary."""


class SyncEngine:
    def __init__(
        self,
        store: VulnerabilityStore,
        connector: SourceConnector,
        *,
        page_size: int = 2000,
        max_pages: Optional[int] = None,
        resume: bool = True,
        run_id: Optional[str] = None,
        clock=utc_now,
    ):
        self.store = store
        self.connector = connector
        self.page_size = int(page_size)
        self.max_pages = max_pages
        self.resume = resume
        self.run_id = run_id or uuid.uuid4().hex
        self.clock = clock

    async def run(self, start: datetime, end: datetime) -> SyncReport:
        start = ensure_utc(start)  # type: ignore[assignment]
        end = ensure_utc(end)  # type: ignore[assignment]
        if start is None or end is None:
            raise ValueError("start and end are required")
        if start > end:
            raise ValueError("start must be <= end")

        report = SyncReport(
            run_id=self.run_id,
            source_id=self.connector.metadata.source_id,
            started_at=self.clock(),
            requested_start=start,
            requested_end=end,
        )
        self.store.save_sync_run(report)

        windows = split_windows(start, end, self.connector.metadata.max_window_days)
        try:
            for window_start, window_end in windows:
                range_key = self._range_key(window_start, window_end)
                checkpoint = (
                    self.store.get_checkpoint(report.source_id, range_key)
                    if self.resume
                    else None
                )
                if checkpoint and checkpoint.get("completed"):
                    continue
                cursor = (
                    Cursor.from_dict(checkpoint.get("cursor"))
                    if checkpoint
                    else Cursor()
                )
                retrieved_before = report.records_retrieved
                await self._run_window(
                    report=report,
                    start=window_start,
                    end=window_end,
                    range_key=range_key,
                    cursor=cursor,
                )
                if report.records_retrieved == retrieved_before:
                    report.missing_intervals.append(
                        f"{window_start.date().isoformat()}..{window_end.date().isoformat()}"
                    )
                if (
                    self.max_pages is not None
                    and report.pages_fetched >= self.max_pages
                    and (window_start, window_end) != windows[-1]
                ):
                    raise SyncInterrupted(
                        f"max_pages={self.max_pages} reached; checkpoint saved"
                    )

            report.coverage_by_year = self._coverage_by_year(start, end)
            report.finish(SyncStatus.COMPLETED)
            self.store.save_sync_run(report)
            return report
        except SyncInterrupted as exc:
            report.finish(SyncStatus.INTERRUPTED, notes=[str(exc) or "interrupted"])
            self.store.save_sync_run(report)
            return report
        except asyncio.CancelledError:
            report.finish(SyncStatus.INTERRUPTED, notes=["cancelled"])
            self.store.save_sync_run(report)
            raise
        except Exception as exc:
            report.finish(SyncStatus.FAILED, notes=[f"{type(exc).__name__}: {exc}"])
            self.store.add_sync_error(
                run_id=report.run_id,
                source_id=report.source_id,
                source_record_id=None,
                error_class=type(exc).__name__,
                message=str(exc),
            )
            self.store.save_sync_run(report)
            logger.exception("sync run %s failed", report.run_id)
            return report

    async def _run_window(
        self,
        *,
        report: SyncReport,
        start: datetime,
        end: datetime,
        range_key: str,
        cursor: Cursor,
    ) -> None:
        while True:
            page = await self.connector.fetch_page(
                start=start,
                end=end,
                cursor=cursor,
                page_size=self.page_size,
            )
            report.pages_fetched += 1
            report.records_retrieved += len(page.records)

            last_published: Optional[str] = None
            for raw in page.records:
                try:
                    record = self.connector.normalize(raw)
                    self._validate(record)
                    result = self.store.upsert_vulnerability(record, raw_payload=raw)
                    if result.status == "inserted":
                        report.inserted += 1
                    elif result.status == "updated":
                        report.updated += 1
                    elif result.status == "unchanged":
                        report.unchanged += 1
                    elif result.status == "duplicate":
                        report.duplicates += 1
                    if record.published_at is not None:
                        iso = record.published_at.isoformat()
                        if last_published is None or iso > last_published:
                            last_published = iso
                except Exception as exc:
                    report.rejected += 1
                    report.errors += 1
                    source_record_id = None
                    if isinstance(raw, dict):
                        source_record_id = str(
                            (raw.get("cve") or {}).get("id")
                            or raw.get("id")
                            or ""
                        ) or None
                    self.store.add_sync_error(
                        run_id=report.run_id,
                        source_id=report.source_id,
                        source_record_id=source_record_id,
                        error_class=type(exc).__name__,
                        message=str(exc),
                    )

            next_cursor = page.next_cursor
            # An empty page cannot make progress.  Treat it as the end of this
            # window even if a malformed source reported a next cursor.
            completed = next_cursor is None or not page.records
            saved_cursor = (next_cursor or cursor).to_dict()
            self.store.set_checkpoint(
                report.source_id,
                range_key,
                saved_cursor,
                completed=completed,
                last_published_at=last_published,
            )
            if completed:
                return
            if self.max_pages is not None and report.pages_fetched >= self.max_pages:
                raise SyncInterrupted(
                    f"max_pages={self.max_pages} reached; checkpoint saved at page {cursor.page}"
                )
            cursor = next_cursor  # type: ignore[assignment]

    def _validate(self, record: VulnerabilityRecord) -> None:
        if not record.source_id:
            raise ValueError("normalized record has no source_id")
        if not record.source_record_id:
            raise ValueError("normalized record has no source_record_id")
        if not record.canonical_id:
            raise ValueError("normalized record has no canonical_id")

    def _range_key(self, start: datetime, end: datetime) -> str:
        return f"{start.date().isoformat()}..{end.date().isoformat()}"

    def _coverage_by_year(self, start: datetime, end: datetime) -> Dict[str, int]:
        try:
            months = self.store.count_by_month(
                self.connector.metadata.source_id, start, end
            )
        except Exception:
            return {}
        by_year: Dict[str, int] = {}
        for month, count in months.items():
            year = month[:4]
            by_year[year] = by_year.get(year, 0) + int(count)
        return dict(sorted(by_year.items()))


def split_windows(
    start: datetime, end: datetime, max_window_days: Optional[int]
) -> List[Tuple[datetime, datetime]]:
    """Split a date range into windows that overlap only at the boundary.

    A ``None`` or non-positive ``max_window_days`` means one window.  Adjacent
    windows share the boundary instant; the store deduplicates a record that
    appears in both.  Skipping the boundary would silently lose a record
    published at that instant.
    """
    start = ensure_utc(start)  # type: ignore[assignment]
    end = ensure_utc(end)  # type: ignore[assignment]
    if start is None or end is None:
        raise ValueError("start and end are required")
    if start > end:
        raise ValueError("start must be <= end")
    if not max_window_days or int(max_window_days) <= 0:
        return [(start, end)]

    windows: List[Tuple[datetime, datetime]] = []
    cursor = start
    step = timedelta(days=int(max_window_days))
    while cursor <= end:
        window_end = min(end, cursor + step)
        windows.append((cursor, window_end))
        if window_end >= end:
            break
        # Deliberately overlap the boundary instant rather than skip it: a
        # record published at the boundary is deduped by the store, while a gap
        # would silently lose it.
        cursor = window_end
    return windows


__all__ = ["SyncEngine", "SyncInterrupted", "split_windows"]
