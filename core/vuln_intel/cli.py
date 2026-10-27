"""Command-line interface for the vulnerability-intelligence slice.

Examples
--------
Initialize the store and inspect source metadata::

    python -m core.vuln_intel.cli init
    python -m core.vuln_intel.cli sources

Sync a bounded historical window (requires network access)::

    python -m core.vuln_intel.cli sync --start 2024-01-01 --end 2024-01-31

Measure what is actually stored::

    python -m core.vuln_intel.cli coverage --start 2024-01-01 --end 2024-01-31

Search and inspect::

    python -m core.vuln_intel.cli search --cwe CWE-79 --limit 20
    python -m core.vuln_intel.cli show --id CVE-2024-1234

Classify a record and triage it against a project inventory::

    python -m core.vuln_intel.cli classify-php --id CVE-2024-1234
    python -m core.vuln_intel.cli triage --project project.json --all

Query OSV.dev (which also exposes GHSA advisories)::

    python -m core.vuln_intel.cli osv-query --package symfony/http-kernel
    python -m core.vuln_intel.cli osv-get --id GHSA-xxxx-xxxx-xxxx

Rank the tools that may test an advisory (a plan, never an execution)::

    python -m core.vuln_intel.cli select-tools --vuln CVE-2024-1234 --authorized

All output is data.  Advisory text is never executed or interpreted as an
instruction.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from core.console import configure_stdio, safe_print

from .coverage import build_coverage
from .db import VulnerabilityStore
from .models import (
    ProjectProfile,
    SyncReport,
    SyncStatus,
    VulnerabilityRecord,
    record_from_stored,
)
from .php import classify_php
from .sources.base import SourceMetadata
from .sources.nvd import NVD_METADATA, NVDConnector
from .sources.osv import OSV_METADATA, OSVConnector, normalize_osv_record
from .sync import SyncEngine
from .tool_capabilities import (
    DEFAULT_CAPABILITIES,
    ToolAvailability,
    load_capability_catalog,
)
from .tool_selection import SelectionScope, select_tools
from .triage import triage_many, triage_project

DEFAULT_DB = "data/vuln_intel/vuln_intel.sqlite3"


# --------------------------------------------------------------------- parsing
def _date_start(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid date {value!r}; expected YYYY-MM-DD"
        ) from exc
    return parsed.replace(tzinfo=timezone.utc)


def _date_end(value: str) -> datetime:
    start = _date_start(value)
    return start + timedelta(days=1) - timedelta(microseconds=1)


def _search_date_start(value: str) -> datetime:
    text = value.strip()
    if len(text) == 10:
        return _date_start(text)
    parsed = _parse_iso_datetime(text)
    return parsed


def _search_date_end(value: str) -> datetime:
    text = value.strip()
    if len(text) == 10:
        return _date_end(text)
    return _parse_iso_datetime(text)


def _parse_iso_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid timestamp {value!r}; expected ISO-8601"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _today_end() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(hour=23, minute=59, second=59, microsecond=999999)


def _resolve_range(args: argparse.Namespace) -> None:
    end = getattr(args, "end", None) or _today_end()
    start = getattr(args, "start", None)
    if start is None:
        start = end - timedelta(days=7)
    if start > end:
        raise SystemExit("error: --start must be <= --end")
    args.start = start
    args.end = end


# --------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m core.vuln_intel.cli",
        description="Evidence-first vulnerability intelligence (read-only).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create/migrate the SQLite store")
    init.add_argument("--db", default=DEFAULT_DB)
    init.add_argument("--json", action="store_true")

    sources = sub.add_parser("sources", help="list registered source metadata")
    sources.add_argument("--json", action="store_true")

    sync = sub.add_parser("sync", help="sync a bounded date range from a source")
    sync.add_argument("--source", default="nvd", choices=["nvd"])
    sync.add_argument("--start", type=_date_start, default=None)
    sync.add_argument("--end", type=_date_end, default=None)
    sync.add_argument("--db", default=DEFAULT_DB)
    sync.add_argument("--page-size", type=int, default=2000)
    sync.add_argument("--max-pages", type=int, default=None)
    sync.add_argument("--no-resume", action="store_true")
    sync.add_argument("--api-key", default=None)
    sync.add_argument("--store-raw", action="store_true")
    sync.add_argument("--json", action="store_true")

    coverage = sub.add_parser("coverage", help="measure stored coverage")
    coverage.add_argument("--source", default="nvd", choices=["nvd"])
    coverage.add_argument("--start", type=_date_start, required=True)
    coverage.add_argument("--end", type=_date_end, default=None)
    coverage.add_argument("--db", default=DEFAULT_DB)
    coverage.add_argument("--expected-total", type=int, default=None)
    coverage.add_argument("--json", action="store_true")

    search = sub.add_parser("search", help="search stored advisories")
    search.add_argument("--db", default=DEFAULT_DB)
    search.add_argument("--text", default=None)
    search.add_argument("--from", dest="published_from", type=_search_date_start, default=None)
    search.add_argument("--to", dest="published_to", type=_search_date_end, default=None)
    search.add_argument("--vendor", default=None)
    search.add_argument("--product", default=None)
    search.add_argument("--package", default=None)
    search.add_argument("--ecosystem", default=None)
    search.add_argument("--cwe", default=None)
    search.add_argument("--severity", default=None)
    search.add_argument("--source", dest="source_id", default=None)
    search.add_argument("--limit", type=int, default=20)
    search.add_argument("--offset", type=int, default=0)
    search.add_argument("--json", action="store_true")

    show = sub.add_parser("show", help="show one advisory")
    show.add_argument("--db", default=DEFAULT_DB)
    show.add_argument("--id", required=True)
    show.add_argument("--json", action="store_true")

    php = sub.add_parser("classify-php", help="classify the PHP component of an advisory")
    php.add_argument("--db", default=DEFAULT_DB)
    php.add_argument("--id", required=True)
    php.add_argument("--json", action="store_true")

    triage = sub.add_parser("triage", help="triage advisories against a project inventory")
    triage.add_argument("--db", default=DEFAULT_DB)
    triage.add_argument("--project", required=True)
    triage.add_argument("--vuln", action="append", default=None)
    triage.add_argument("--all", action="store_true")
    triage.add_argument("--limit", type=int, default=1000)
    triage.add_argument("--json", action="store_true")

    export = sub.add_parser("export", help="export stored advisories")
    export.add_argument("--db", default=DEFAULT_DB)
    export.add_argument("--format", choices=["json", "csv"], default="json")
    export.add_argument("--out", default=None)
    export.add_argument("--json", action="store_true")

    osv_query = sub.add_parser(
        "osv-query", help="query OSV.dev for a package (network, read-only)"
    )
    osv_query.add_argument("--package", required=True)
    osv_query.add_argument("--ecosystem", default="Packagist")
    osv_query.add_argument("--version", default=None)
    osv_query.add_argument("--db", default=None, help="optional: store the results")
    osv_query.add_argument("--store-raw", action="store_true")
    osv_query.add_argument("--json", action="store_true")

    osv_get = sub.add_parser(
        "osv-get", help="fetch one OSV advisory by id (network, read-only)"
    )
    osv_get.add_argument("--id", required=True)
    osv_get.add_argument("--db", default=None, help="optional: store the result")
    osv_get.add_argument("--store-raw", action="store_true")
    osv_get.add_argument("--json", action="store_true")

    select = sub.add_parser(
        "select-tools", help="rank tools for an advisory (plan only, never executes)"
    )
    select.add_argument("--db", default=DEFAULT_DB)
    select.add_argument("--vuln", required=True)
    select.add_argument("--project", default=None)
    select.add_argument("--authorized", action="store_true")
    select.add_argument(
        "--max-risk",
        default="low",
        choices=["low", "medium", "high", "critical"],
    )
    select.add_argument(
        "--allow-unavailable",
        action="store_true",
        help="do not require the tool to be verified as installed",
    )
    select.add_argument(
        "--assume-available",
        action="append",
        default=None,
        help="mark a tool as installed for this run (repeatable)",
    )
    select.add_argument("--capabilities", default=None, help="JSON capability catalog")
    select.add_argument("--json", action="store_true")

    return parser


# ------------------------------------------------------------------ commands
def _cmd_init(args: argparse.Namespace) -> int:
    store = VulnerabilityStore(args.db)
    payload = {"db": str(store.db_path), "schema_version": store.schema_version, **store.stats()}
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        safe_print(f"db={payload['db']} schema={payload['schema_version']}")
        safe_print(
            "vulnerabilities={vulnerabilities} aliases={aliases} "
            "affected_packages={affected_packages} references={references} "
            "sync_runs={sync_runs}".format(**payload)
        )
    return 0


def _cmd_sources(args: argparse.Namespace) -> int:
    payload = [asdict(NVD_METADATA), asdict(OSV_METADATA)]
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for item in payload:
            window = (
                f"window={item['max_window_days']}d"
                if item["max_window_days"]
                else "query-based"
            )
            safe_print(
                f"{item['source_id']}: {item['name']} "
                f"(start={item['historical_start']}, {window}, "
                f"rate={item['rate_limit_requests']}/{item['rate_limit_period_seconds']}s)"
            )
    return 0


async def _sync_async(
    args: argparse.Namespace, store: VulnerabilityStore, connector: Any
) -> SyncReport:
    engine = SyncEngine(
        store,
        connector,
        page_size=args.page_size,
        max_pages=args.max_pages,
        resume=not args.no_resume,
    )
    try:
        return await engine.run(args.start, args.end)
    finally:
        aclose = getattr(connector, "aclose", None)
        if aclose is not None:
            await aclose()


def run_sync(args: argparse.Namespace, connector: Any = None) -> SyncReport:
    """Run a sync and return the report (injectable connector for tests)."""
    _resolve_range(args)
    store = VulnerabilityStore(args.db, store_raw=bool(getattr(args, "store_raw", False)))
    active = connector or NVDConnector(api_key=getattr(args, "api_key", None))
    return asyncio.run(_sync_async(args, store, active))


def _cmd_sync(args: argparse.Namespace, connector: Any = None) -> int:
    report = run_sync(args, connector=connector)
    payload = report.to_dict()
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        safe_print(
            "source={source_id} status={status} pages={pages_fetched} "
            "records={records_retrieved} inserted={inserted} updated={updated} "
            "unchanged={unchanged} duplicates={duplicates} rejected={rejected} "
            "errors={errors}".format(**payload)
        )
        if report.missing_intervals:
            safe_print("empty windows: " + ", ".join(report.missing_intervals))
        if report.notes:
            safe_print("notes: " + " | ".join(report.notes))
    return 0 if report.status != SyncStatus.FAILED else 1


def _cmd_coverage(args: argparse.Namespace) -> int:
    _resolve_range(args)
    store = VulnerabilityStore(args.db)
    metadata: Optional[SourceMetadata] = NVD_METADATA if args.source == "nvd" else None
    report = build_coverage(
        store,
        args.source,
        args.start,
        args.end,
        source_metadata=metadata,
        expected_total=args.expected_total,
    )
    payload = report.to_dict()
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        safe_print(
            "source={source_id} records={records_total} "
            "months={months_covered}/{months_requested} complete={complete}".format(
                **payload
            )
        )
        if report.missing_months:
            safe_print("missing months: " + ", ".join(report.missing_months))
        for limitation in report.source_limitations:
            safe_print("limitation: " + limitation)
        for note in report.notes:
            safe_print("note: " + note)
    return 0


def _record_summary(data: Dict[str, Any]) -> str:
    identifier = (
        data.get("record_id")
        or data.get("canonical_id")
        or data.get("source_record_id")
        or "unknown"
    )
    title = (
        data.get("title") or data.get("summary") or data.get("description") or ""
    ).strip().replace("\n", " ")
    if len(title) > 100:
        title = title[:97] + "..."
    return (
        f"{identifier} | {data.get('published_at') or 'unknown'} | "
        f"{data.get('severity') or 'unknown'} | {title}"
    )


def _cmd_search(args: argparse.Namespace) -> int:
    store = VulnerabilityStore(args.db)
    rows = store.search(
        text=args.text,
        published_from=args.published_from,
        published_to=args.published_to,
        vendor=args.vendor,
        product=args.product,
        package=args.package,
        ecosystem=args.ecosystem,
        cwe=args.cwe,
        severity=args.severity,
        source_id=args.source_id,
        limit=args.limit,
        offset=args.offset,
    )
    if args.json:
        safe_print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
    else:
        safe_print(f"results={len(rows)}")
        for row in rows:
            safe_print(_record_summary(row))
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    store = VulnerabilityStore(args.db)
    data = store.get(args.id)
    if data is None:
        safe_print(f"not found: {args.id}", file=sys.stderr)
        return 1
    if args.json:
        safe_print(json.dumps(data, ensure_ascii=False, indent=2, default=str))
        return 0
    safe_print(f"id: {data.get('record_id')}")
    safe_print(f"canonical: {data.get('canonical_id')}")
    safe_print(f"source: {data.get('source_id')} / {data.get('source_record_id')}")
    safe_print(f"published: {data.get('published_at')}")
    safe_print(f"severity: {data.get('severity')}")
    safe_print(f"status: {data.get('vuln_status')}")
    safe_print(f"cwes: {', '.join(data.get('cwes') or []) or 'unknown'}")
    safe_print(f"description: {data.get('description') or ''}")
    for pkg in data.get("affected") or []:
        safe_print(
            "affected: "
            f"{pkg.get('ecosystem')} {pkg.get('vendor') or ''} {pkg.get('product') or ''} "
            f"{pkg.get('package_name') or ''} {pkg.get('cpe') or ''} "
            f"range={pkg.get('version_start_including') or ''}..{pkg.get('version_end_including') or ''} "
            f"fixed={pkg.get('fixed_version') or ''}"
        )
    for ref in data.get("references") or []:
        safe_print(f"reference: {ref.get('ref_type')} {ref.get('url')}")
    return 0


def _cmd_classify_php(args: argparse.Namespace) -> int:
    store = VulnerabilityStore(args.db)
    record = store.get_record(args.id)
    if record is None:
        safe_print(f"not found: {args.id}", file=sys.stderr)
        return 1
    analysis = classify_php(record)
    payload = analysis.to_dict()
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        safe_print(f"involves_php={analysis.involves_php}")
        safe_print(f"component={analysis.component_type.value}")
        safe_print(f"confidence={analysis.confidence.value}")
        safe_print(f"names={', '.join(analysis.component_names) or 'none'}")
        for item in analysis.evidence:
            safe_print("evidence: " + item)
        for note in analysis.notes:
            safe_print("note: " + note)
    return 0


def _load_project(path: str) -> ProjectProfile:
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("project file must contain a JSON object")
    return ProjectProfile.model_validate(data)


def _cmd_triage(args: argparse.Namespace) -> int:
    store = VulnerabilityStore(args.db)
    project = _load_project(args.project)

    records: List[VulnerabilityRecord] = []
    if args.vuln:
        for identifier in args.vuln:
            record = store.get_record(identifier)
            if record is None:
                safe_print(f"not found: {identifier}", file=sys.stderr)
                return 1
            records.append(record)
    elif args.all:
        rows = store.search(limit=args.limit)
        records = [record_from_stored(row) for row in rows]
    else:
        safe_print("error: provide --vuln ID (repeatable) or --all", file=sys.stderr)
        return 2

    results = triage_many(project, records)
    payload = [result.to_dict() for result in results]
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        safe_print(f"project={project.project_id} results={len(results)}")
        for result in results:
            safe_print(
                f"{result.vuln_id} | {result.classification.value} | "
                f"{result.confidence.value} | {result.recommended_action}"
            )
            for reason in result.reasons:
                safe_print("  reason: " + reason)
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    store = VulnerabilityStore(args.db)
    if args.format == "csv":
        text = store.export_csv(args.out)
        if args.out:
            safe_print(f"wrote {args.out} ({len(text.splitlines()) - 1} rows)")
        else:
            safe_print(text)
        return 0
    rows = store.export_json(args.out)
    if args.out:
        safe_print(f"wrote {args.out} ({len(rows)} records)")
    elif args.json:
        safe_print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
    else:
        for row in rows:
            safe_print(_record_summary(row))
    return 0


async def _osv_query_async(args: argparse.Namespace, connector: Any) -> List[Dict[str, Any]]:
    if connector is not None:
        return await connector.query_package(args.package, args.ecosystem, args.version)
    active = OSVConnector()
    try:
        return await active.query_package(args.package, args.ecosystem, args.version)
    finally:
        await active.aclose()


async def _osv_get_async(args: argparse.Namespace, connector: Any) -> Dict[str, Any]:
    if connector is not None:
        return await connector.get_vuln(args.id)
    active = OSVConnector()
    try:
        return await active.get_vuln(args.id)
    finally:
        await active.aclose()


def _store_osv_records(
    records: Sequence[VulnerabilityRecord],
    raws: Sequence[Dict[str, Any]],
    db: Optional[str],
    store_raw: bool,
) -> List[Dict[str, Any]]:
    stored: List[Dict[str, Any]] = []
    if not db:
        return stored
    store = VulnerabilityStore(db, store_raw=bool(store_raw))
    for raw, record in zip(raws, records):
        result = store.upsert_vulnerability(
            record,
            raw_payload=raw if store_raw else None,
            source_url=f"https://osv.dev/vulnerability/{record.source_record_id}",
        )
        stored.append(result.model_dump(mode="json"))
    return stored


def _print_osv_payload(payload: Dict[str, Any]) -> None:
    safe_print(
        f"source={payload['source_id']} count={payload['count']} "
        f"stored={len(payload.get('stored') or [])}"
    )
    for record in payload.get("records") or []:
        safe_print(_record_summary(record))
    for item in payload.get("stored") or []:
        safe_print(f"stored {item['record_id']} status={item['status']}")


def _cmd_osv_query(args: argparse.Namespace, connector: Any = None) -> int:
    raws = asyncio.run(_osv_query_async(args, connector))
    if connector is not None:
        records = [connector.normalize(raw) for raw in raws]
    else:
        records = [normalize_osv_record(raw) for raw in raws]
    stored = _store_osv_records(
        records, raws, getattr(args, "db", None), bool(getattr(args, "store_raw", False))
    )
    payload = {
        "source_id": "osv",
        "query": {
            "package": args.package,
            "ecosystem": args.ecosystem,
            "version": args.version,
        },
        "count": len(records),
        "records": [record.model_dump(mode="json") for record in records],
        "stored": stored,
    }
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        _print_osv_payload(payload)
    return 0


def _cmd_osv_get(args: argparse.Namespace, connector: Any = None) -> int:
    raw = asyncio.run(_osv_get_async(args, connector))
    record = connector.normalize(raw) if connector is not None else normalize_osv_record(raw)
    stored = _store_osv_records(
        [record], [raw], getattr(args, "db", None), bool(getattr(args, "store_raw", False))
    )
    payload = {
        "source_id": "osv",
        "query": {"id": args.id},
        "count": 1,
        "records": [record.model_dump(mode="json")],
        "stored": stored,
    }
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        _print_osv_payload(payload)
    return 0


def _cmd_select_tools(args: argparse.Namespace) -> int:
    store = VulnerabilityStore(args.db)
    record = store.get_record(args.vuln)
    if record is None:
        safe_print(f"not found: {args.vuln}", file=sys.stderr)
        return 1

    project = _load_project(args.project) if args.project else None
    if args.capabilities:
        capabilities = load_capability_catalog(args.capabilities)
    else:
        capabilities = [item.model_copy(deep=True) for item in DEFAULT_CAPABILITIES]

    assumed = {
        str(item).strip()
        for item in (getattr(args, "assume_available", None) or [])
        if str(item).strip()
    }
    if assumed:
        capabilities = [
            item.model_copy(update={"availability": ToolAvailability.INSTALLED})
            if item.tool_id in assumed
            else item
            for item in capabilities
        ]

    scope = SelectionScope(
        authorized=bool(getattr(args, "authorized", False)),
        max_risk=getattr(args, "max_risk", "low"),
        require_installed=not bool(getattr(args, "allow_unavailable", False)),
    )
    result = select_tools(record, project, scope, capabilities)
    payload = result.to_dict()
    if args.json:
        safe_print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        safe_print(
            f"vuln={result.vuln_id} status={result.status} "
            f"classes={', '.join(result.vuln_classes) or 'none'} "
            f"authorized={result.authorized}"
        )
        for item in result.selected:
            safe_print(
                f"selected {item.tool_id} score={item.score} "
                f"risk={item.risk_level} availability={item.availability}"
            )
            for reason in item.reasons:
                safe_print("  reason: " + reason)
        for item in result.rejected:
            safe_print(f"rejected {item.tool_id}: {item.reason}")
        for note in result.notes:
            safe_print("note: " + note)
    return 0


def main(argv: Optional[Sequence[str]] = None, connector: Any = None) -> int:
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "sources":
        return _cmd_sources(args)
    if args.command == "sync":
        return _cmd_sync(args, connector=connector)
    if args.command == "coverage":
        return _cmd_coverage(args)
    if args.command == "search":
        return _cmd_search(args)
    if args.command == "show":
        return _cmd_show(args)
    if args.command == "classify-php":
        return _cmd_classify_php(args)
    if args.command == "triage":
        return _cmd_triage(args)
    if args.command == "export":
        return _cmd_export(args)
    if args.command == "osv-query":
        return _cmd_osv_query(args, connector=connector)
    if args.command == "osv-get":
        return _cmd_osv_get(args, connector=connector)
    if args.command == "select-tools":
        return _cmd_select_tools(args)
    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
