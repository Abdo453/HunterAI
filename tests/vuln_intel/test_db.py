"""SQLite store: idempotency, aliases, filters, checkpoints, and export."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from core.vuln_intel.db import SCHEMA_VERSION, VulnerabilityStore
from core.vuln_intel.models import (
    AffectedPackage,
    Ecosystem,
    Severity,
    SyncReport,
    SyncStatus,
    VulnerabilityRecord,
)


def test_schema_is_versioned_and_migration_is_idempotent(store):
    assert store.schema_version == SCHEMA_VERSION
    store.migrate()
    store.migrate()
    assert store.schema_version == SCHEMA_VERSION
    assert store.stats()["vulnerabilities"] == 0


def test_upsert_insert_unchanged_update_and_get(store, make_record):
    record = make_record(description="first")
    first = store.upsert_vulnerability(record)
    assert first.status == "inserted"
    assert first.record_id == "CVE-2024-0001"
    assert store.count() == 1

    second = store.upsert_vulnerability(make_record(description="first"))
    assert second.status == "unchanged"
    assert store.count() == 1

    third = store.upsert_vulnerability(make_record(description="second"))
    assert third.status == "updated"
    assert store.count() == 1
    row = store.get("CVE-2024-0001")
    assert row is not None
    assert row["description"] == "second"
    assert row["updated_at"] >= row["created_at"]


def test_alias_aware_dedupe_merges_without_overwriting(store, make_record):
    store.upsert_vulnerability(make_record(description="canonical"))
    duplicate = make_record(
        source_record_id="GHSA-aaaa-bbbb-cccc",
        canonical_id="GHSA-aaaa-bbbb-cccc",
        aliases=["CVE-2024-0001"],
        description="duplicate source",
    )
    result = store.upsert_vulnerability(duplicate)
    assert result.status == "duplicate"
    assert result.record_id == "CVE-2024-0001"
    assert store.count() == 1
    # The alias resolves to the canonical record, and the original facts win.
    row = store.get("GHSA-aaaa-bbbb-cccc")
    assert row is not None
    assert row["record_id"] == "CVE-2024-0001"
    assert row["description"] == "canonical"
    assert "GHSA-AAAA-BBBB-CCCC" in row["aliases"]


def test_get_record_returns_validated_model(store, make_record):
    store.upsert_vulnerability(make_record(description="hello"))
    record = store.get_record("CVE-2024-0001")
    assert record is not None
    assert record.description == "hello"
    assert store.get_record("missing") is None
    assert store.get("") is None


def test_search_filters_and_sql_injection_safety(store, make_record):
    store.upsert_vulnerability(
        make_record(
            description="Laravel framework XSS",
            severity=Severity.CRITICAL,
            cwes=["CWE-79"],
            affected=[
                AffectedPackage(
                    ecosystem=Ecosystem.COMPOSER,
                    package_name="laravel/framework",
                )
            ],
        )
    )
    store.upsert_vulnerability(
        make_record(
            source_record_id="CVE-2024-0002",
            description="A kernel issue",
            severity=Severity.LOW,
            cwes=["CWE-20"],
        )
    )

    assert [row["record_id"] for row in store.search(text="Laravel")] == [
        "CVE-2024-0001"
    ]
    assert [row["record_id"] for row in store.search(cwe="CWE-79")] == [
        "CVE-2024-0001"
    ]
    assert [row["record_id"] for row in store.search(severity="CRITICAL")] == [
        "CVE-2024-0001"
    ]
    assert [
        row["record_id"]
        for row in store.search(package="laravel/framework", ecosystem="composer")
    ] == ["CVE-2024-0001"]
    assert [row["record_id"] for row in store.search(source_id="nvd")] == [
        "CVE-2024-0001",
        "CVE-2024-0002",
    ]
    assert [
        row["record_id"]
        for row in store.search(
            published_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
            published_to=datetime(2024, 1, 31, tzinfo=timezone.utc),
        )
    ] == ["CVE-2024-0001", "CVE-2024-0002"]

    # Every filter is a bound parameter.  These strings must be treated as
    # data, not SQL.
    assert store.search(text="' OR 1=1 --") == []
    assert store.search(cwe="CWE-79' OR 1=1 --") == []
    assert store.search(vendor="' OR 1=1 --") == []
    assert store.count() == 2


def test_count_by_month_is_scoped_to_source(store, make_record):
    store.upsert_vulnerability(
        make_record(published_at=datetime(2024, 1, 2, tzinfo=timezone.utc))
    )
    store.upsert_vulnerability(
        make_record(
            source_record_id="CVE-2024-0002",
            published_at=datetime(2024, 1, 20, tzinfo=timezone.utc),
        )
    )
    store.upsert_vulnerability(
        make_record(
            source_record_id="CVE-2024-0003",
            source_id="other",
            published_at=datetime(2024, 2, 1, tzinfo=timezone.utc),
        )
    )
    counts = store.count_by_month(
        "nvd",
        datetime(2024, 1, 1, tzinfo=timezone.utc),
        datetime(2024, 2, 28, tzinfo=timezone.utc),
    )
    assert counts == {"2024-01": 2}


def test_checkpoint_round_trip(store):
    store.set_checkpoint(
        "nvd",
        "2024-01-01..2024-01-31",
        {"start_index": 40, "page": 2, "token": None},
        completed=False,
        last_published_at="2024-01-15T00:00:00+00:00",
    )
    checkpoint = store.get_checkpoint("nvd", "2024-01-01..2024-01-31")
    assert checkpoint is not None
    assert checkpoint["cursor"]["start_index"] == 40
    assert checkpoint["completed"] is False
    assert checkpoint["last_published_at"] == "2024-01-15T00:00:00+00:00"

    store.set_checkpoint(
        "nvd",
        "2024-01-01..2024-01-31",
        {"start_index": 0, "page": 0, "token": None},
        completed=True,
    )
    checkpoint = store.get_checkpoint("nvd", "2024-01-01..2024-01-31")
    assert checkpoint is not None
    assert checkpoint["completed"] is True


def test_sync_run_round_trip(store):
    report = SyncReport(
        run_id="run-1",
        source_id="nvd",
        status=SyncStatus.COMPLETED,
        inserted=2,
        records_retrieved=2,
    )
    report.finish(SyncStatus.COMPLETED)
    store.save_sync_run(report)
    row = store.get_sync_run("run-1")
    assert row is not None
    assert row["status"] == "completed"
    assert row["report"]["inserted"] == 2


def test_export_json_and_csv(store, make_record, tmp_path):
    store.upsert_vulnerability(
        make_record(
            description="Laravel XSS",
            cwes=["CWE-79"],
            affected=[
                AffectedPackage(
                    ecosystem=Ecosystem.COMPOSER,
                    package_name="laravel/framework",
                )
            ],
        )
    )
    json_path = tmp_path / "out.json"
    rows = store.export_json(json_path)
    assert len(rows) == 1
    assert json.loads(json_path.read_text(encoding="utf-8"))[0]["record_id"] == "CVE-2024-0001"

    csv_path = tmp_path / "out.csv"
    text = store.export_csv(csv_path)
    assert "record_id,canonical_id" in text
    assert "CVE-2024-0001" in text
    assert csv_path.read_text(encoding="utf-8") == text


def test_raw_payload_is_only_stored_when_opted_in(tmp_path, make_record):
    path = tmp_path / "raw.sqlite3"
    normal = VulnerabilityStore(path)
    normal.upsert_vulnerability(make_record(), raw_payload={"raw": True})
    with normal._connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM raw_records").fetchone()[0] == 0

    opted_in = VulnerabilityStore(path, store_raw=True)
    opted_in.upsert_vulnerability(make_record(), raw_payload={"raw": True})
    with opted_in._connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM raw_records").fetchone()[0] == 1


def test_stats_counts_children(store, make_record):
    store.upsert_vulnerability(
        make_record(
            cwes=["CWE-79"],
            affected=[AffectedPackage(ecosystem=Ecosystem.CPE, vendor="php", product="php")],
        )
    )
    stats = store.stats()
    assert stats["vulnerabilities"] == 1
    assert stats["aliases"] >= 1
    assert stats["affected_packages"] == 1
