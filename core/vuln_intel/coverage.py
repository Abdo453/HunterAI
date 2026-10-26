"""Honest coverage measurement for a vulnerability source.

The report answers: *for the requested months, how many stored records do we
have, and which months are empty?*  It never claims that a source contains every
vulnerability ever published.

``complete`` is only ``True`` when the caller supplies a denominator
(``expected_total``) and every month has records and the counts match.  For
open-ended/current-year data it is always ``False``.
"""
from __future__ import annotations

import calendar
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .db import VulnerabilityStore
from .models import CoverageReport, ensure_utc, utc_now
from .sources.base import SourceMetadata


def _month_range(start: datetime, end: datetime) -> List[str]:
    start = ensure_utc(start)  # type: ignore[assignment]
    end = ensure_utc(end)  # type: ignore[assignment]
    if start is None or end is None:
        raise ValueError("start and end are required")
    if start > end:
        raise ValueError("start must be <= end")
    months: List[str] = []
    year, month = start.year, start.month
    while (year, month) <= (end.year, end.month):
        months.append(f"{year:04d}-{month:02d}")
        month += 1
        if month > 12:
            month = 1
            year += 1
    return months


def _month_start(key: str) -> datetime:
    year, month = key.split("-")
    return datetime(int(year), int(month), 1, tzinfo=timezone.utc)


def _month_end(key: str) -> datetime:
    year, month = (int(part) for part in key.split("-"))
    day = calendar.monthrange(year, month)[1]
    return datetime(year, month, day, 23, 59, 59, 999999, tzinfo=timezone.utc)


def build_coverage(
    store: VulnerabilityStore,
    source_id: str,
    start: datetime,
    end: datetime,
    *,
    source_metadata: Optional[SourceMetadata] = None,
    expected_total: Optional[int] = None,
    clock=utc_now,
) -> CoverageReport:
    start = ensure_utc(start)  # type: ignore[assignment]
    end = ensure_utc(end)  # type: ignore[assignment]
    if start is None or end is None:
        raise ValueError("start and end are required")
    if start > end:
        raise ValueError("start must be <= end")

    months = store.count_by_month(source_id, start, end)
    requested_months = _month_range(start, end)
    covered = [month for month in requested_months if int(months.get(month, 0)) > 0]
    missing = [month for month in requested_months if int(months.get(month, 0)) == 0]

    by_year: Dict[str, int] = {}
    for month, count in months.items():
        year = month[:4]
        by_year[year] = by_year.get(year, 0) + int(count)

    records_total = sum(int(count) for count in months.values())
    measured_start = _month_start(covered[0]) if covered else None
    measured_end = _month_end(covered[-1]) if covered else None

    now = clock()
    limitations: List[str] = [
        "Coverage is measured from records stored for this source; an empty "
        "month is not proof that no vulnerability existed.",
    ]
    if source_metadata is not None:
        if source_metadata.notes:
            limitations.append(source_metadata.notes)
        if source_metadata.historical_start not in {"", "unknown", None}:
            limitations.append(
                f"Nominal source start: {source_metadata.historical_start}; "
                "actual record availability is measured, not assumed."
            )
        if source_metadata.source_id == "nvd" and start.year < 2002:
            limitations.append(
                "NVD coverage before 2002 is sparse; the CVE Program itself began in 1999."
            )
    if end.year >= now.year:
        limitations.append(
            f"{now.year} is still in progress; current-year coverage is never complete."
        )

    complete = False
    notes: List[str] = []
    if expected_total is not None:
        try:
            expected = int(expected_total)
        except (TypeError, ValueError):
            expected = None
        if expected is not None:
            if records_total == expected and not missing:
                complete = True
                notes.append(
                    f"Complete relative to the supplied denominator ({expected} records)."
                )
            else:
                notes.append(
                    f"Supplied denominator={expected}; stored records={records_total}; "
                    f"missing months={len(missing)}. Not complete."
                )
    else:
        notes.append(
            "No denominator was supplied, so completeness cannot be asserted. "
            "Use a source-provided total for a closed range to measure completeness."
        )
    if end.year >= now.year:
        complete = False
        notes.append("Forced complete=False because the requested range includes the current year.")

    return CoverageReport(
        source_id=source_id,
        requested_start=start,
        requested_end=end,
        measured_start=measured_start,
        measured_end=measured_end,
        records_total=records_total,
        months_requested=len(requested_months),
        months_covered=len(covered),
        missing_months=missing,
        by_year=dict(sorted(by_year.items())),
        complete=complete,
        source_limitations=limitations,
        generated_at=now,
        notes=notes,
    )


__all__ = ["build_coverage"]
