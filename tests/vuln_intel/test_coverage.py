"""Coverage is measured, not assumed."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.vuln_intel.coverage import build_coverage
from core.vuln_intel.sources.nvd import NVD_METADATA


def _dt(year: int, month: int, day: int = 1) -> datetime:
    return datetime(year, month, day, tzinfo=timezone.utc)


def _clock():
    return _dt(2026, 1, 1)


def test_coverage_reports_measured_months_and_gaps(store, make_record):
    store.upsert_vulnerability(
        make_record(published_at=_dt(2024, 1, 15))
    )
    store.upsert_vulnerability(
        make_record(
            source_record_id="CVE-2024-0002",
            published_at=_dt(2024, 3, 2),
        )
    )
    report = build_coverage(
        store,
        "nvd",
        _dt(2024, 1, 1),
        _dt(2024, 3, 31),
        clock=_clock,
    )
    assert report.records_total == 2
    assert report.months_requested == 3
    assert report.months_covered == 2
    assert report.missing_months == ["2024-02"]
    assert report.by_year == {"2024": 2}
    assert report.measured_start == _dt(2024, 1, 1)
    assert report.measured_end == datetime(
        2024, 3, 31, 23, 59, 59, 999999, tzinfo=timezone.utc
    )
    assert report.complete is False
    assert any("not proof" in item for item in report.source_limitations)


def test_coverage_is_complete_only_against_a_denominator(store, make_record):
    store.upsert_vulnerability(make_record(published_at=_dt(2024, 1, 1)))
    store.upsert_vulnerability(
        make_record(source_record_id="CVE-2024-0002", published_at=_dt(2024, 2, 1))
    )
    report = build_coverage(
        store,
        "nvd",
        _dt(2024, 1, 1),
        _dt(2024, 2, 29),
        expected_total=2,
        clock=_clock,
    )
    assert report.complete is True
    assert "Complete relative to the supplied denominator" in " ".join(report.notes)


def test_coverage_without_denominator_is_never_complete(store, make_record):
    store.upsert_vulnerability(make_record(published_at=_dt(2024, 1, 1)))
    report = build_coverage(
        store,
        "nvd",
        _dt(2024, 1, 1),
        _dt(2024, 1, 31),
        clock=_clock,
    )
    assert report.complete is False
    assert any("No denominator" in note for note in report.notes)


def test_coverage_with_missing_month_is_not_complete(store, make_record):
    store.upsert_vulnerability(make_record(published_at=_dt(2024, 1, 1)))
    report = build_coverage(
        store,
        "nvd",
        _dt(2024, 1, 1),
        _dt(2024, 3, 31),
        expected_total=1,
        clock=_clock,
    )
    assert report.complete is False
    assert report.missing_months == ["2024-02", "2024-03"]


def test_current_year_is_never_complete(store, make_record):
    store.upsert_vulnerability(make_record(published_at=_dt(2026, 1, 15)))
    report = build_coverage(
        store,
        "nvd",
        _dt(2026, 1, 1),
        _dt(2026, 1, 31),
        expected_total=1,
        clock=_clock,
    )
    assert report.complete is False
    assert any("still in progress" in item for item in report.source_limitations)
    assert any("Forced complete=False" in note for note in report.notes)


def test_coverage_is_scoped_to_the_source(store, make_record):
    store.upsert_vulnerability(make_record(published_at=_dt(2024, 1, 1)))
    store.upsert_vulnerability(
        make_record(
            source_record_id="OTHER-1",
            source_id="other",
            published_at=_dt(2024, 2, 1),
        )
    )
    report = build_coverage(
        store,
        "nvd",
        _dt(2024, 1, 1),
        _dt(2024, 2, 29),
        clock=_clock,
    )
    assert report.records_total == 1
    assert report.missing_months == ["2024-02"]


def test_empty_coverage_has_no_measured_range(store):
    report = build_coverage(
        store,
        "nvd",
        _dt(2024, 1, 1),
        _dt(2024, 12, 31),
        clock=_clock,
    )
    assert report.records_total == 0
    assert report.months_covered == 0
    assert report.measured_start is None
    assert report.measured_end is None
    assert report.missing_months[0] == "2024-01"
    assert report.missing_months[-1] == "2024-12"


def test_coverage_includes_source_limitations(store):
    report = build_coverage(
        store,
        "nvd",
        _dt(2000, 1, 1),
        _dt(2001, 12, 31),
        source_metadata=NVD_METADATA,
        clock=_clock,
    )
    joined = " ".join(report.source_limitations)
    assert "before 2002" in joined
    assert "Nominal source start" in joined
    assert NVD_METADATA.notes in joined


def test_coverage_rejects_reversed_range(store):
    with pytest.raises(ValueError):
        build_coverage(
            store,
            "nvd",
            _dt(2024, 2, 1),
            _dt(2024, 1, 1),
            clock=_clock,
        )
