"""SQLite store for normalized vulnerability records.

The database is the source of truth for advisories.  It is deliberately
separate from the engagement knowledge DB and from the legacy JSON CVE cache.

Guarantees
----------
* versioned, idempotent migrations;
* one transaction per upsert;
* alias-aware dedupe (CVE <-> GHSA <-> OSV);
* a content hash so an unchanged record is not rewritten;
* ``published_at`` and ``imported_at`` are distinct columns;
* provenance is merged, not lost, when the same record arrives from a second
  source;
* all SQL uses bound parameters (advisory text is never interpolated).
"""
from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .models import (
    SyncReport,
    UpsertResult,
    VulnerabilityRecord,
    ensure_utc,
    record_from_stored,
    utc_now,
)

logger = logging.getLogger("core.vuln_intel.db")

SCHEMA_VERSION = 1

_MIGRATIONS: Dict[int, str] = {
    1: """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        record_id TEXT PRIMARY KEY,
        canonical_id TEXT NOT NULL,
        source_id TEXT NOT NULL,
        source_record_id TEXT NOT NULL,
        title TEXT,
        description TEXT,
        summary TEXT,
        published_at TEXT,
        last_modified_at TEXT,
        discovery_at TEXT,
        disclosed_at TEXT,
        imported_at TEXT NOT NULL,
        vuln_status TEXT NOT NULL DEFAULT 'unknown',
        severity TEXT NOT NULL DEFAULT 'unknown',
        cvss_version TEXT,
        cvss_score REAL,
        cvss_vector TEXT,
        attack_vector TEXT,
        attack_complexity TEXT,
        privileges_required TEXT,
        user_interaction TEXT,
        confidentiality_impact TEXT,
        integrity_impact TEXT,
        availability_impact TEXT,
        known_exploited INTEGER,
        remediation TEXT,
        workarounds_json TEXT NOT NULL DEFAULT '[]',
        fixed_versions_json TEXT NOT NULL DEFAULT '[]',
        confidence TEXT NOT NULL DEFAULT 'UNVERIFIED',
        content_hash TEXT NOT NULL,
        provenance_json TEXT NOT NULL DEFAULT '[]',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(source_id, source_record_id)
    );

    CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_at);
    CREATE INDEX IF NOT EXISTS idx_vuln_canonical ON vulnerabilities(canonical_id);
    CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
    CREATE INDEX IF NOT EXISTS idx_vuln_source ON vulnerabilities(source_id);

    CREATE TABLE IF NOT EXISTS vulnerability_aliases (
        record_id TEXT NOT NULL REFERENCES vulnerabilities(record_id) ON DELETE CASCADE,
        alias TEXT NOT NULL,
        alias_type TEXT NOT NULL DEFAULT 'identifier',
        source_id TEXT,
        PRIMARY KEY (record_id, alias)
    );
    CREATE INDEX IF NOT EXISTS idx_alias_alias ON vulnerability_aliases(alias);

    CREATE TABLE IF NOT EXISTS affected_packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id TEXT NOT NULL REFERENCES vulnerabilities(record_id) ON DELETE CASCADE,
        dedupe_key TEXT NOT NULL,
        ecosystem TEXT NOT NULL DEFAULT 'unknown',
        vendor TEXT,
        product TEXT,
        package_name TEXT,
        cpe TEXT,
        cpe_version TEXT,
        version_start_including TEXT,
        version_start_excluding TEXT,
        version_end_including TEXT,
        version_end_excluding TEXT,
        fixed_version TEXT,
        configuration_json TEXT NOT NULL DEFAULT '{}',
        UNIQUE(record_id, dedupe_key)
    );
    CREATE INDEX IF NOT EXISTS idx_affected_package ON affected_packages(ecosystem, package_name);
    CREATE INDEX IF NOT EXISTS idx_affected_product ON affected_packages(vendor, product);

    CREATE TABLE IF NOT EXISTS vulnerability_cwes (
        record_id TEXT NOT NULL REFERENCES vulnerabilities(record_id) ON DELETE CASCADE,
        cwe_id TEXT NOT NULL,
        PRIMARY KEY (record_id, cwe_id)
    );
    CREATE INDEX IF NOT EXISTS idx_cwe ON vulnerability_cwes(cwe_id);

    CREATE TABLE IF NOT EXISTS vulnerability_references (
        record_id TEXT NOT NULL REFERENCES vulnerabilities(record_id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        ref_type TEXT NOT NULL DEFAULT 'web',
        source TEXT,
        tags_json TEXT NOT NULL DEFAULT '[]',
        PRIMARY KEY (record_id, url)
    );

    CREATE TABLE IF NOT EXISTS raw_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        record_id TEXT NOT NULL,
        source_id TEXT NOT NULL,
        source_record_id TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        retrieved_at TEXT NOT NULL,
        UNIQUE(record_id, sha256)
    );

    CREATE TABLE IF NOT EXISTS sync_runs (
        run_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        status TEXT NOT NULL,
        requested_start TEXT,
        requested_end TEXT,
        pages_fetched INTEGER NOT NULL DEFAULT 0,
        records_retrieved INTEGER NOT NULL DEFAULT 0,
        inserted INTEGER NOT NULL DEFAULT 0,
        updated INTEGER NOT NULL DEFAULT 0,
        unchanged INTEGER NOT NULL DEFAULT 0,
        duplicates INTEGER NOT NULL DEFAULT 0,
        rejected INTEGER NOT NULL DEFAULT 0,
        errors INTEGER NOT NULL DEFAULT 0,
        report_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS sync_checkpoints (
        source_id TEXT NOT NULL,
        range_key TEXT NOT NULL,
        cursor_json TEXT NOT NULL DEFAULT '{}',
        completed INTEGER NOT NULL DEFAULT 0,
        last_success_at TEXT,
        last_published_at TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (source_id, range_key)
    );

    CREATE TABLE IF NOT EXISTS sync_errors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT,
        source_id TEXT,
        source_record_id TEXT,
        error_class TEXT,
        message TEXT,
        occurred_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_sync_errors_run ON sync_errors(run_id);
    """,
}


class VulnerabilityStore:
    """SQLite-backed normalized advisory store."""

    def __init__(self, db_path: str | Path, *, store_raw: bool = False):
        self.db_path = Path(db_path)
        self.store_raw = bool(store_raw)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    # ------------------------------------------------------------------ SQL
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            isolation_level=None,  # explicit BEGIN/COMMIT below
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    @contextmanager
    def _connection(self):
        """Yield a connection and always close it.

        ``with sqlite3.connect(...)`` commits but does not close; relying on GC
        leaks handles and keeps the database file locked on Windows.
        """
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def migrate(self) -> None:
        """Apply pending migrations. Idempotent and safe to call repeatedly."""
        with self._connection() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            applied = {
                int(row[0])
                for row in conn.execute("SELECT version FROM schema_migrations").fetchall()
            }
            for version in sorted(_MIGRATIONS):
                if version in applied:
                    continue
                conn.executescript(_MIGRATIONS[version])
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                    (version, utc_now().isoformat()),
                )
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @property
    def schema_version(self) -> int:
        with self._connection() as conn:
            row = conn.execute("PRAGMA user_version").fetchone()
            return int(row[0]) if row else 0

    # --------------------------------------------------------------- upsert
    def upsert_vulnerability(
        self,
        record: VulnerabilityRecord,
        *,
        raw_payload: Optional[Dict[str, Any]] = None,
        source_url: Optional[str] = None,
    ) -> UpsertResult:
        """Insert, update, or dedupe a normalized record atomically."""
        content_hash = record.compute_content_hash()
        record_id = record.record_id
        now = utc_now().isoformat()

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = self._find_by_identifier(conn, record)
            aliases_added = 0

            if existing is None:
                self._insert_record(conn, record, content_hash, now)
                status = "inserted"
                target_id = record_id
            elif existing["record_id"] == record_id:
                target_id = record_id
                if existing["content_hash"] == content_hash:
                    aliases_added = self._merge_aliases(conn, record_id, record.all_identifiers())
                    self._merge_provenance(conn, record_id, record)
                    status = "unchanged"
                else:
                    self._update_record(conn, record, content_hash, now)
                    aliases_added = self._merge_aliases(conn, record_id, record.all_identifiers())
                    self._merge_provenance(conn, record_id, record)
                    status = "updated"
            else:
                # An alias already belongs to another canonical record.  Merge
                # provenance/aliases but do not overwrite the existing core
                # facts (a later, evidence-aware merge can decide precedence).
                target_id = existing["record_id"]
                aliases_added = self._merge_aliases(
                    conn, target_id, record.all_identifiers() + [record_id]
                )
                self._merge_provenance(conn, target_id, record)
                status = "duplicate"

            if raw_payload is not None and self.store_raw:
                self._insert_raw(conn, target_id, record, raw_payload, source_url)

            conn.execute("COMMIT")
            return UpsertResult(
                record_id=target_id,
                status=status,
                aliases_added=aliases_added,
                message="" if status != "duplicate" else "merged into existing canonical record",
            )
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def _find_by_identifier(
        self, conn: sqlite3.Connection, record: VulnerabilityRecord
    ) -> Optional[sqlite3.Row]:
        row = conn.execute(
            "SELECT * FROM vulnerabilities WHERE record_id = ?", (record.record_id,)
        ).fetchone()
        if row:
            return row

        identifiers = record.all_identifiers()
        if not identifiers:
            return None
        placeholders = ",".join("?" for _ in identifiers)
        row = conn.execute(
            f"SELECT v.* FROM vulnerabilities v "
            f"JOIN vulnerability_aliases a ON a.record_id = v.record_id "
            f"WHERE a.alias IN ({placeholders}) LIMIT 1",
            identifiers,
        ).fetchone()
        return row

    def _insert_record(
        self,
        conn: sqlite3.Connection,
        record: VulnerabilityRecord,
        content_hash: str,
        now: str,
    ) -> None:
        data = record.model_dump(mode="json")
        cvss = data.get("cvss") or {}
        conn.execute(
            """
            INSERT INTO vulnerabilities (
                record_id, canonical_id, source_id, source_record_id,
                title, description, summary,
                published_at, last_modified_at, discovery_at, disclosed_at, imported_at,
                vuln_status, severity,
                cvss_version, cvss_score, cvss_vector,
                attack_vector, attack_complexity, privileges_required, user_interaction,
                confidentiality_impact, integrity_impact, availability_impact,
                known_exploited, remediation, workarounds_json, fixed_versions_json,
                confidence, content_hash, provenance_json, metadata_json,
                created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?
            )
            """,
            (
                record.record_id,
                record.canonical_id,
                record.source_id,
                record.source_record_id,
                record.title,
                record.description,
                record.summary,
                _iso(record.published_at),
                _iso(record.last_modified_at),
                _iso(record.discovery_at),
                _iso(record.disclosed_at),
                record.imported_at.isoformat(),
                record.vuln_status.value,
                record.severity.value,
                cvss.get("version"),
                cvss.get("score"),
                cvss.get("vector"),
                cvss.get("attack_vector"),
                cvss.get("attack_complexity"),
                cvss.get("privileges_required"),
                cvss.get("user_interaction"),
                cvss.get("confidentiality_impact"),
                cvss.get("integrity_impact"),
                cvss.get("availability_impact"),
                None if record.known_exploited is None else int(record.known_exploited),
                record.remediation,
                json.dumps(record.workarounds, ensure_ascii=False),
                json.dumps(record.fixed_versions, ensure_ascii=False),
                record.confidence.value,
                content_hash,
                json.dumps(
                    [p.model_dump(mode="json") for p in record.provenance],
                    ensure_ascii=False,
                ),
                json.dumps(record.metadata, ensure_ascii=False, default=str),
                now,
                now,
            ),
        )
        self._replace_children(conn, record)
        self._merge_aliases(conn, record.record_id, record.all_identifiers())

    def _update_record(
        self,
        conn: sqlite3.Connection,
        record: VulnerabilityRecord,
        content_hash: str,
        now: str,
    ) -> None:
        data = record.model_dump(mode="json")
        cvss = data.get("cvss") or {}
        conn.execute(
            """
            UPDATE vulnerabilities SET
                canonical_id = ?, source_id = ?, source_record_id = ?,
                title = ?, description = ?, summary = ?,
                published_at = ?, last_modified_at = ?, discovery_at = ?, disclosed_at = ?,
                imported_at = ?,
                vuln_status = ?, severity = ?,
                cvss_version = ?, cvss_score = ?, cvss_vector = ?,
                attack_vector = ?, attack_complexity = ?, privileges_required = ?,
                user_interaction = ?, confidentiality_impact = ?, integrity_impact = ?,
                availability_impact = ?,
                known_exploited = ?, remediation = ?,
                workarounds_json = ?, fixed_versions_json = ?,
                confidence = ?, content_hash = ?, provenance_json = ?, metadata_json = ?,
                updated_at = ?
            WHERE record_id = ?
            """,
            (
                record.canonical_id,
                record.source_id,
                record.source_record_id,
                record.title,
                record.description,
                record.summary,
                _iso(record.published_at),
                _iso(record.last_modified_at),
                _iso(record.discovery_at),
                _iso(record.disclosed_at),
                record.imported_at.isoformat(),
                record.vuln_status.value,
                record.severity.value,
                cvss.get("version"),
                cvss.get("score"),
                cvss.get("vector"),
                cvss.get("attack_vector"),
                cvss.get("attack_complexity"),
                cvss.get("privileges_required"),
                cvss.get("user_interaction"),
                cvss.get("confidentiality_impact"),
                cvss.get("integrity_impact"),
                cvss.get("availability_impact"),
                None if record.known_exploited is None else int(record.known_exploited),
                record.remediation,
                json.dumps(record.workarounds, ensure_ascii=False),
                json.dumps(record.fixed_versions, ensure_ascii=False),
                record.confidence.value,
                content_hash,
                json.dumps(
                    [p.model_dump(mode="json") for p in record.provenance],
                    ensure_ascii=False,
                ),
                json.dumps(record.metadata, ensure_ascii=False, default=str),
                now,
                record.record_id,
            ),
        )
        self._replace_children(conn, record)

    def _replace_children(self, conn: sqlite3.Connection, record: VulnerabilityRecord) -> None:
        rid = record.record_id
        conn.execute("DELETE FROM affected_packages WHERE record_id = ?", (rid,))
        conn.execute("DELETE FROM vulnerability_cwes WHERE record_id = ?", (rid,))
        conn.execute("DELETE FROM vulnerability_references WHERE record_id = ?", (rid,))

        seen: set[str] = set()
        for pkg in record.affected:
            key = pkg.dedupe_key
            if key in seen:
                continue
            seen.add(key)
            conn.execute(
                """
                INSERT INTO affected_packages (
                    record_id, dedupe_key, ecosystem, vendor, product, package_name,
                    cpe, cpe_version,
                    version_start_including, version_start_excluding,
                    version_end_including, version_end_excluding,
                    fixed_version, configuration_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rid,
                    key,
                    pkg.ecosystem.value,
                    pkg.vendor,
                    pkg.product,
                    pkg.package_name,
                    pkg.cpe,
                    pkg.cpe_version,
                    pkg.version_start_including,
                    pkg.version_start_excluding,
                    pkg.version_end_including,
                    pkg.version_end_excluding,
                    pkg.fixed_version,
                    json.dumps(pkg.configuration, ensure_ascii=False, default=str),
                ),
            )

        for cwe in record.cwes:
            conn.execute(
                "INSERT OR IGNORE INTO vulnerability_cwes(record_id, cwe_id) VALUES (?, ?)",
                (rid, cwe),
            )

        for ref in record.references:
            conn.execute(
                """
                INSERT OR IGNORE INTO vulnerability_references(
                    record_id, url, ref_type, source, tags_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    rid,
                    ref.url,
                    ref.ref_type,
                    ref.source,
                    json.dumps(ref.tags, ensure_ascii=False),
                ),
            )

    def _merge_aliases(
        self, conn: sqlite3.Connection, record_id: str, aliases: Iterable[str]
    ) -> int:
        added = 0
        for alias in aliases:
            text = str(alias).strip().upper()
            if not text:
                continue
            cur = conn.execute(
                "INSERT OR IGNORE INTO vulnerability_aliases(record_id, alias, alias_type, source_id) "
                "VALUES (?, ?, 'identifier', NULL)",
                (record_id, text),
            )
            added += int(cur.rowcount or 0)
        return added

    def _merge_provenance(
        self, conn: sqlite3.Connection, record_id: str, record: VulnerabilityRecord
    ) -> None:
        row = conn.execute(
            "SELECT provenance_json FROM vulnerabilities WHERE record_id = ?", (record_id,)
        ).fetchone()
        if row is None:
            return
        try:
            existing = json.loads(row[0] or "[]")
        except Exception:
            existing = []
        keys = {
            (
                item.get("source_id"),
                item.get("source_record_id"),
                item.get("raw_sha256"),
            )
            for item in existing
            if isinstance(item, dict)
        }
        changed = False
        for prov in record.provenance:
            key = (prov.source_id, prov.source_record_id, prov.raw_sha256)
            if key in keys:
                continue
            existing.append(prov.model_dump(mode="json"))
            keys.add(key)
            changed = True
        if changed:
            conn.execute(
                "UPDATE vulnerabilities SET provenance_json = ?, updated_at = ? WHERE record_id = ?",
                (json.dumps(existing, ensure_ascii=False), utc_now().isoformat(), record_id),
            )

    def _insert_raw(
        self,
        conn: sqlite3.Connection,
        record_id: str,
        record: VulnerabilityRecord,
        payload: Dict[str, Any],
        source_url: Optional[str],
    ) -> None:
        import hashlib

        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        digest = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        conn.execute(
            """
            INSERT OR IGNORE INTO raw_records(
                record_id, source_id, source_record_id, sha256, payload_json, retrieved_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                record_id,
                record.source_id,
                record.source_record_id,
                digest,
                blob,
                utc_now().isoformat(),
            ),
        )

    # ------------------------------------------------------------------ read
    def get(self, identifier: str) -> Optional[Dict[str, Any]]:
        ident = str(identifier).strip().upper()
        if not ident:
            return None
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM vulnerabilities WHERE record_id = ? OR canonical_id = ?",
                (ident, ident),
            ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT v.* FROM vulnerabilities v "
                    "JOIN vulnerability_aliases a ON a.record_id = v.record_id "
                    "WHERE a.alias = ? LIMIT 1",
                    (ident,),
                ).fetchone()
            if row is None:
                return None
            return self._hydrate(conn, row)

    def get_record(self, identifier: str) -> Optional[VulnerabilityRecord]:
        """Return a validated model, not a raw row dictionary."""
        data = self.get(identifier)
        if data is None:
            return None
        return record_from_stored(data)

    def _hydrate(self, conn: sqlite3.Connection, row: sqlite3.Row) -> Dict[str, Any]:
        data = dict(row)
        rid = data["record_id"]
        data["cwes"] = [
            r["cwe_id"]
            for r in conn.execute(
                "SELECT cwe_id FROM vulnerability_cwes WHERE record_id = ? ORDER BY cwe_id",
                (rid,),
            ).fetchall()
        ]
        data["affected"] = []
        for pkg in conn.execute(
            "SELECT * FROM affected_packages WHERE record_id = ? ORDER BY id", (rid,)
        ).fetchall():
            item = dict(pkg)
            try:
                item["configuration"] = json.loads(item.pop("configuration_json") or "{}")
            except Exception:
                item["configuration"] = {}
            data["affected"].append(item)
        data["references"] = []
        for ref in conn.execute(
            "SELECT * FROM vulnerability_references WHERE record_id = ? ORDER BY url", (rid,)
        ).fetchall():
            item = dict(ref)
            try:
                item["tags"] = json.loads(item.pop("tags_json") or "[]")
            except Exception:
                item["tags"] = []
            data["references"].append(item)
        data["aliases"] = [
            r["alias"]
            for r in conn.execute(
                "SELECT alias FROM vulnerability_aliases WHERE record_id = ? ORDER BY alias",
                (rid,),
            ).fetchall()
        ]
        data["provenance"] = _load_json(data.pop("provenance_json", "[]"), [])
        data["metadata"] = _load_json(data.pop("metadata_json", "{}"), {})
        data["workarounds"] = _load_json(data.pop("workarounds_json", "[]"), [])
        data["fixed_versions"] = _load_json(data.pop("fixed_versions_json", "[]"), [])
        cvss_keys = [
            "cvss_version",
            "cvss_score",
            "cvss_vector",
            "attack_vector",
            "attack_complexity",
            "privileges_required",
            "user_interaction",
            "confidentiality_impact",
            "integrity_impact",
            "availability_impact",
        ]
        if any(data.get(key) is not None for key in cvss_keys):
            data["cvss"] = {
                "version": data.get("cvss_version"),
                "score": data.get("cvss_score"),
                "vector": data.get("cvss_vector"),
                "severity": data.get("severity"),
                "attack_vector": data.get("attack_vector"),
                "attack_complexity": data.get("attack_complexity"),
                "privileges_required": data.get("privileges_required"),
                "user_interaction": data.get("user_interaction"),
                "confidentiality_impact": data.get("confidentiality_impact"),
                "integrity_impact": data.get("integrity_impact"),
                "availability_impact": data.get("availability_impact"),
            }
        else:
            data["cvss"] = None
        return data

    def search(
        self,
        *,
        text: Optional[str] = None,
        published_from: Optional[datetime] = None,
        published_to: Optional[datetime] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        package: Optional[str] = None,
        ecosystem: Optional[str] = None,
        cwe: Optional[str] = None,
        severity: Optional[str] = None,
        source_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        clauses: List[str] = ["1=1"]
        params: List[Any] = []
        joins: List[str] = []

        if text:
            clauses.append(
                "(v.title LIKE ? OR v.description LIKE ? OR v.summary LIKE ? OR v.canonical_id LIKE ?)"
            )
            needle = f"%{text}%"
            params.extend([needle, needle, needle, needle])
        if published_from:
            clauses.append("v.published_at >= ?")
            params.append(ensure_utc(published_from).isoformat())  # type: ignore[union-attr]
        if published_to:
            clauses.append("v.published_at <= ?")
            params.append(ensure_utc(published_to).isoformat())  # type: ignore[union-attr]
        if severity:
            clauses.append("v.severity = ?")
            params.append(str(severity).lower())
        if source_id:
            clauses.append("v.source_id = ?")
            params.append(str(source_id))
        if cwe:
            joins.append("JOIN vulnerability_cwes c ON c.record_id = v.record_id")
            clauses.append("c.cwe_id = ?")
            params.append(str(cwe).upper())
        if vendor or product or package or ecosystem:
            joins.append("JOIN affected_packages a ON a.record_id = v.record_id")
            if vendor:
                clauses.append("lower(a.vendor) = lower(?)")
                params.append(vendor)
            if product:
                clauses.append("lower(a.product) = lower(?)")
                params.append(product)
            if package:
                clauses.append("lower(a.package_name) = lower(?)")
                params.append(package)
            if ecosystem:
                clauses.append("a.ecosystem = ?")
                params.append(str(ecosystem).lower())

        sql = (
            "SELECT DISTINCT v.* FROM vulnerabilities v "
            + " ".join(joins)
            + " WHERE "
            + " AND ".join(clauses)
            + " ORDER BY v.published_at DESC, v.record_id ASC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        with self._connection() as conn:
            rows = conn.execute(sql, params).fetchall()
            return [self._hydrate(conn, row) for row in rows]

    def count(self, source_id: Optional[str] = None) -> int:
        with self._connection() as conn:
            if source_id:
                row = conn.execute(
                    "SELECT COUNT(*) FROM vulnerabilities WHERE source_id = ?", (source_id,)
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()
            return int(row[0]) if row else 0

    def count_by_month(
        self, source_id: str, start: datetime, end: datetime
    ) -> Dict[str, int]:
        start_date = ensure_utc(start).date().isoformat()  # type: ignore[union-attr]
        end_date = ensure_utc(end).date().isoformat()  # type: ignore[union-attr]
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT substr(published_at, 1, 7) AS month, COUNT(*) AS n "
                "FROM vulnerabilities "
                "WHERE source_id = ? AND published_at IS NOT NULL "
                "AND substr(published_at, 1, 10) BETWEEN ? AND ? "
                "GROUP BY month ORDER BY month",
                (source_id, start_date, end_date),
            ).fetchall()
            return {row["month"]: int(row["n"]) for row in rows}

    # ------------------------------------------------------------ checkpoints
    def get_checkpoint(self, source_id: str, range_key: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM sync_checkpoints WHERE source_id = ? AND range_key = ?",
                (source_id, range_key),
            ).fetchone()
            if row is None:
                return None
            data = dict(row)
            data["cursor"] = _load_json(data.pop("cursor_json", "{}"), {})
            data["completed"] = bool(data.get("completed"))
            return data

    def set_checkpoint(
        self,
        source_id: str,
        range_key: str,
        cursor: Dict[str, Any],
        *,
        completed: bool = False,
        last_published_at: Optional[str] = None,
    ) -> None:
        now = utc_now().isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO sync_checkpoints(
                    source_id, range_key, cursor_json, completed,
                    last_success_at, last_published_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_id, range_key) DO UPDATE SET
                    cursor_json = excluded.cursor_json,
                    completed = excluded.completed,
                    last_success_at = excluded.last_success_at,
                    last_published_at = excluded.last_published_at,
                    updated_at = excluded.updated_at
                """,
                (
                    source_id,
                    range_key,
                    json.dumps(cursor, sort_keys=True),
                    int(completed),
                    now,
                    last_published_at,
                    now,
                ),
            )

    # --------------------------------------------------------------- sync run
    def save_sync_run(self, report: SyncReport) -> None:
        payload = report.to_dict()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO sync_runs(
                    run_id, source_id, started_at, finished_at, status,
                    requested_start, requested_end,
                    pages_fetched, records_retrieved, inserted, updated, unchanged,
                    duplicates, rejected, errors, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    finished_at = excluded.finished_at,
                    status = excluded.status,
                    pages_fetched = excluded.pages_fetched,
                    records_retrieved = excluded.records_retrieved,
                    inserted = excluded.inserted,
                    updated = excluded.updated,
                    unchanged = excluded.unchanged,
                    duplicates = excluded.duplicates,
                    rejected = excluded.rejected,
                    errors = excluded.errors,
                    report_json = excluded.report_json
                """,
                (
                    report.run_id,
                    report.source_id,
                    report.started_at.isoformat(),
                    _iso(report.finished_at),
                    report.status.value,
                    _iso(report.requested_start),
                    _iso(report.requested_end),
                    report.pages_fetched,
                    report.records_retrieved,
                    report.inserted,
                    report.updated,
                    report.unchanged,
                    report.duplicates,
                    report.rejected,
                    report.errors,
                    json.dumps(payload, ensure_ascii=False, default=str),
                ),
            )

    def get_sync_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM sync_runs WHERE run_id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            data = dict(row)
            data["report"] = _load_json(data.pop("report_json", "{}"), {})
            return data

    def add_sync_error(
        self,
        *,
        run_id: Optional[str],
        source_id: Optional[str],
        source_record_id: Optional[str],
        error_class: str,
        message: str,
    ) -> None:
        with self._connection() as conn:
            conn.execute(
                "INSERT INTO sync_errors(run_id, source_id, source_record_id, error_class, message, occurred_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    source_id,
                    source_record_id,
                    error_class,
                    str(message)[:4000],
                    utc_now().isoformat(),
                ),
            )

    # ----------------------------------------------------------------- export
    def export_json(self, path: Optional[str | Path] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        offset = 0
        while True:
            batch = self.search(limit=1000, offset=offset)
            if not batch:
                break
            out.extend(batch)
            offset += len(batch)
        if path:
            # newline="" keeps the JSON newlines stable on Windows.
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(json.dumps(out, ensure_ascii=False, indent=2, default=str))
        return out

    def export_csv(self, path: Optional[str | Path] = None) -> str:
        rows = self.export_json()
        buffer = io.StringIO()
        # Deterministic LF output; the file is written with newline="" so
        # Windows does not turn LF into CRLF (which would double the CR in a
        # CSV that already used CRLF).
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(
            [
                "record_id",
                "canonical_id",
                "source_id",
                "published_at",
                "last_modified_at",
                "imported_at",
                "severity",
                "cvss_score",
                "cwes",
                "packages",
                "title",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.get("record_id"),
                    row.get("canonical_id"),
                    row.get("source_id"),
                    row.get("published_at"),
                    row.get("last_modified_at"),
                    row.get("imported_at"),
                    row.get("severity"),
                    (row.get("cvss") or {}).get("score"),
                    ";".join(row.get("cwes") or []),
                    ";".join(
                        sorted(
                            {
                                pkg.get("package_name") or pkg.get("product") or ""
                                for pkg in (row.get("affected") or [])
                            }
                        )
                    ),
                    row.get("title"),
                ]
            )
        text = buffer.getvalue()
        if path:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
        return text

    def stats(self) -> Dict[str, int]:
        with self._connection() as conn:
            vulns = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
            aliases = conn.execute("SELECT COUNT(*) FROM vulnerability_aliases").fetchone()[0]
            packages = conn.execute("SELECT COUNT(*) FROM affected_packages").fetchone()[0]
            refs = conn.execute("SELECT COUNT(*) FROM vulnerability_references").fetchone()[0]
            runs = conn.execute("SELECT COUNT(*) FROM sync_runs").fetchone()[0]
            return {
                "vulnerabilities": int(vulns),
                "aliases": int(aliases),
                "affected_packages": int(packages),
                "references": int(refs),
                "sync_runs": int(runs),
            }


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return ensure_utc(value).isoformat()  # type: ignore[union-attr]


def _load_json(text: Optional[str], default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except Exception:
        return default


__all__ = ["VulnerabilityStore", "SCHEMA_VERSION"]
