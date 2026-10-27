"""OSV.dev connector and normalizer (query-based source).

Source: https://api.osv.dev

What OSV is
-----------
OSV.dev is an **aggregator**.  A single OSV record usually mirrors one
upstream advisory database entry (GitHub Advisory Database / GHSA, PyPA,
Debian/Ubuntu, Go vulnerability database, ...).  Querying OSV therefore also
gives access to GHSA advisories, including their CVE aliases.

What this module does **not** do
--------------------------------
* It does not claim a package is vulnerability-free when OSV returns nothing.
  OSV only knows the advisories it has mirrored.
* It does not invent version ranges: an OSV record without a usable
  ``ranges``/``versions`` entry produces an affected component without a
  version range (triage then answers ``INSUFFICIENT_EVIDENCE``).
* It does not treat a Git commit range as a version range.
* It does not store the raw payload unless the store is explicitly configured
  to do so.

OSV has no date-range pagination API, so this connector is intentionally
**not** part of the ``SyncEngine`` date-window flow.  It is queried on demand
(package/version lookup or a single advisory id).
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from ..cvss import cvss3_base_score, severity_from_label, severity_from_score
from ..models import (
    AffectedPackage,
    Confidence,
    CvssData,
    Ecosystem,
    Provenance,
    Reference,
    Severity,
    VulnStatus,
    VulnerabilityRecord,
    ensure_utc,
    utc_now,
)
from .base import (
    Cursor,
    HttpClient,
    Page,
    SourceConnector,
    SourceError,
    SourceMetadata,
    SourceParseError,
)

logger = logging.getLogger("core.vuln_intel.sources.osv")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)

OSV_METADATA = SourceMetadata(
    source_id="osv",
    name="OSV.dev (aggregates GHSA and ecosystem advisories)",
    base_url="https://api.osv.dev",
    license="per-record upstream license (verify before redistribution)",
    terms_url="https://osv.dev/about/",
    historical_start="unknown",
    max_window_days=0,
    rate_limit_requests=5,
    rate_limit_period_seconds=30.0,
    allowed_hosts=("api.osv.dev",),
    supports_incremental=False,
    notes=(
        "Query-based source: no date-range pagination and no bulk history "
        "endpoint. Results depend on the upstream databases OSV has mirrored; "
        "an empty result is not proof that no advisory exists."
    ),
)

_ECOSYSTEMS: Dict[str, Ecosystem] = {
    "packagist": Ecosystem.PACKAGIST,
    "composer": Ecosystem.COMPOSER,
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "go": Ecosystem.GO,
    "maven": Ecosystem.MAVEN,
    "nuget": Ecosystem.NUGET,
    "rubygems": Ecosystem.RUBYGEMS,
    "crates.io": Ecosystem.CRATES,
    "hex": Ecosystem.OTHER,
    "wordpress": Ecosystem.WORDPRESS,
    "drupal": Ecosystem.DRUPAL,
    "magento": Ecosystem.MAGENTO,
    "php": Ecosystem.PHP,
}

_REFERENCE_TYPES = {
    "ADVISORY": "advisory",
    "FIX": "patch",
    "PATCH": "patch",
    "REPORT": "report",
    "WEB": "web",
    "EMAIL": "email",
}


def _map_ecosystem(value: object) -> Ecosystem:
    return _ECOSYSTEMS.get(str(value or "").strip().lower(), Ecosystem.OTHER)


def _split_package_name(name: str) -> Tuple[Optional[str], str]:
    if "/" in name:
        vendor, _, product = name.partition("/")
        return vendor or None, product or name
    return None, name


def _parse_timestamp(value: object) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return ensure_utc(parsed)  # type: ignore[return-value]


def _event_value(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(event_name, value)`` for a single OSV range event."""
    for name in ("introduced", "fixed", "last_affected", "limit"):
        if name in event:
            return name, str(event.get(name) or "").strip()
    return None, None


def _ranges_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, Optional[str]]]:
    """Convert an OSV event list into affected version ranges.

    OSV semantics used here:
    * ``introduced``  -> inclusive lower bound (``"0"`` means "all versions").
    * ``fixed``       -> exclusive upper bound and the documented fix.
    * ``last_affected`` -> inclusive upper bound.
    * ``limit``       -> exclusive upper bound.
    """
    ranges: List[Dict[str, Optional[str]]] = []
    start: Optional[str] = None

    def normalized_start(value: Optional[str]) -> Optional[str]:
        if value is None or value in {"", "0"}:
            return None
        return value

    for event in events:
        name, value = _event_value(event)
        if name == "introduced":
            start = normalized_start(value)
        elif name == "fixed":
            ranges.append(
                {
                    "start": start,
                    "end_excluding": value or None,
                    "end_including": None,
                    "fixed": value or None,
                }
            )
            start = None
        elif name == "last_affected":
            ranges.append(
                {
                    "start": start,
                    "end_excluding": None,
                    "end_including": value or None,
                    "fixed": None,
                }
            )
            start = None
        elif name == "limit":
            ranges.append(
                {
                    "start": start,
                    "end_excluding": value or None,
                    "end_including": None,
                    "fixed": None,
                }
            )
            start = None

    if start is not None:
        # Open-ended range: everything from the introduced version onwards.
        ranges.append(
            {
                "start": start,
                "end_excluding": None,
                "end_including": None,
                "fixed": None,
            }
        )
    return ranges


def _cwes_from(raw: Dict[str, Any]) -> List[str]:
    found: List[str] = []

    def add(value: object) -> None:
        text = str(value or "").strip().upper()
        if text and _CWE_RE.match(text) and text not in found:
            found.append(text)

    def add_from(mapping: object) -> None:
        if not isinstance(mapping, dict):
            return
        for item in mapping.get("cwe_ids") or []:
            add(item)

    # OSV/GHSA keep CWEs in ``database_specific``; some upstream feeds use
    # ``ecosystem_specific``.  Both are machine-readable, so both are read.
    add_from(raw.get("database_specific"))
    add_from(raw.get("ecosystem_specific"))
    for entry in raw.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        add_from(entry.get("database_specific"))
        add_from(entry.get("ecosystem_specific"))
    return sorted(found)


def _severity_payload(raw: Dict[str, Any]) -> Tuple[Optional[CvssData], Severity]:
    """Return the CVSS data and severity for an OSV record."""
    database_specific = raw.get("database_specific")
    label = None
    if isinstance(database_specific, dict):
        label = database_specific.get("severity")

    vector: Optional[str] = None
    version: Optional[str] = None
    for entry in raw.get("severity") or []:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("type") or "").strip().upper()
        score = str(entry.get("score") or "").strip()
        if not score:
            continue
        if kind in {"CVSS_V3", "CVSS_V2"} and vector is None:
            vector = score
            version = "3.1" if score.upper().startswith("CVSS:3.") else "2.0"
        elif kind == "CVSS_V4" and vector is None:
            vector = score
            version = "4.0"

    score_value: Optional[float] = None
    if vector and version and version.startswith("3."):
        score_value = cvss3_base_score(vector)

    severity = severity_from_score(score_value)
    if severity == Severity.UNKNOWN and label is not None:
        severity = severity_from_label(label)

    cvss: Optional[CvssData] = None
    if vector:
        cvss = CvssData(
            version=version,
            score=score_value,
            vector=vector,
            severity=severity,
        )
    return cvss, severity


def _affected_from_osv(
    raw: Dict[str, Any],
) -> Tuple[List[AffectedPackage], List[str], List[Dict[str, Any]]]:
    packages: List[AffectedPackage] = []
    fixed_versions: List[str] = []
    git_ranges: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for entry in raw.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package_info = entry.get("package")
        if not isinstance(package_info, dict):
            continue
        name = str(package_info.get("name") or "").strip()
        if not name:
            continue
        ecosystem = _map_ecosystem(package_info.get("ecosystem"))
        vendor, product = _split_package_name(name)

        usable_ranges: List[Tuple[str, Dict[str, Optional[str]]]] = []
        for raw_range in entry.get("ranges") or []:
            if not isinstance(raw_range, dict):
                continue
            range_type = str(raw_range.get("type") or "").strip().upper()
            events = [e for e in (raw_range.get("events") or []) if isinstance(e, dict)]
            if range_type == "GIT":
                git_ranges.append({"package": name, "events": events})
                continue
            if range_type not in {"SEMVER", "ECOSYSTEM"}:
                continue
            for parsed in _ranges_from_events(events):
                usable_ranges.append((range_type, parsed))

        if usable_ranges:
            for range_type, parsed in usable_ranges:
                pkg = AffectedPackage(
                    ecosystem=ecosystem,
                    vendor=vendor,
                    product=product,
                    package_name=name,
                    version_start_including=parsed.get("start"),
                    version_end_excluding=parsed.get("end_excluding"),
                    version_end_including=parsed.get("end_including"),
                    fixed_version=parsed.get("fixed"),
                    configuration={"range_type": range_type, "source": "osv"},
                )
                key = pkg.dedupe_key
                if key in seen:
                    continue
                seen.add(key)
                packages.append(pkg)
                if pkg.fixed_version:
                    fixed_versions.append(pkg.fixed_version)
            continue

        versions = [
            str(item).strip()
            for item in (entry.get("versions") or [])
            if str(item or "").strip()
        ]
        for version in versions:
            pkg = AffectedPackage(
                ecosystem=ecosystem,
                vendor=vendor,
                product=product,
                package_name=name,
                cpe_version=version,
                configuration={"source": "osv_exact_version"},
            )
            key = pkg.dedupe_key
            if key in seen:
                continue
            seen.add(key)
            packages.append(pkg)

    return packages, sorted(set(fixed_versions)), git_ranges


def _references_from(raw: Dict[str, Any]) -> List[Reference]:
    out: List[Reference] = []
    seen: set[str] = set()
    for ref in raw.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        ref_type = _REFERENCE_TYPES.get(str(ref.get("type") or "").strip().upper(), "web")
        out.append(Reference(url=url, ref_type=ref_type, tags=[]))
    return out


def normalize_osv_record(
    raw: Dict[str, Any],
    *,
    retrieved_at: Optional[datetime] = None,
) -> VulnerabilityRecord:
    """Normalize one OSV record into a :class:`VulnerabilityRecord`.

    The canonical identifier is the CVE alias when OSV provides one, so an
    OSV/GHSA record merges with the same CVE from NVD instead of duplicating
    it.  The OSV identifier itself is kept as an alias.
    """
    if not isinstance(raw, dict):
        raise SourceParseError("osv: record must be a JSON object")

    osv_id = str(raw.get("id") or "").strip()
    if not osv_id:
        raise SourceParseError("osv: record has no id")

    aliases = [
        str(item).strip().upper()
        for item in (raw.get("aliases") or [])
        if str(item or "").strip()
    ]
    cve_alias = next((item for item in aliases if _CVE_RE.match(item)), None)
    canonical_id = cve_alias or osv_id.upper()

    alias_set = {osv_id.upper()}
    alias_set.update(aliases)

    affected, fixed_versions, git_ranges = _affected_from_osv(raw)
    cvss, severity = _severity_payload(raw)

    withdrawn = _parse_timestamp(raw.get("withdrawn"))
    status = VulnStatus.WITHDRAWN if withdrawn else VulnStatus.UNKNOWN

    database_specific = raw.get("database_specific")
    upstream_source = None
    if isinstance(database_specific, dict):
        upstream_source = database_specific.get("source")

    blob = json.dumps(raw, sort_keys=True, default=str).encode("utf-8")
    now = retrieved_at or utc_now()

    return VulnerabilityRecord(
        source_id="osv",
        source_record_id=osv_id,
        canonical_id=canonical_id,
        title=None,
        summary=str(raw.get("summary") or "").strip() or None,
        description=str(raw.get("details") or "").strip() or None,
        published_at=_parse_timestamp(raw.get("published")),
        last_modified_at=_parse_timestamp(raw.get("modified")),
        vuln_status=status,
        severity=severity,
        cvss=cvss,
        cwes=_cwes_from(raw),
        affected=affected,
        references=_references_from(raw),
        aliases=sorted(alias_set),
        fixed_versions=fixed_versions,
        confidence=Confidence.STRONGLY_SUPPORTED,
        provenance=[
            Provenance(
                source_id="osv",
                source_record_id=osv_id,
                url=f"https://osv.dev/vulnerability/{quote(osv_id, safe='')}",
                retrieved_at=now,
                raw_sha256=hashlib.sha256(blob).hexdigest(),
                license="OSV terms (per-record upstream license)",
            )
        ],
        metadata={
            "osv_id": osv_id,
            "osv_source": upstream_source,
            "osv_schema_version": raw.get("schema_version"),
            "osv_git_ranges": git_ranges,
            "osv_withdrawn_at": withdrawn.isoformat() if withdrawn else None,
        },
    )


class OSVConnector(SourceConnector):
    """Query-based OSV.dev connector (package lookup and single advisories)."""

    metadata = OSV_METADATA

    def __init__(
        self,
        *,
        http_client: Optional[HttpClient] = None,
        timeout: float = 30.0,
    ):
        self._http = http_client
        self._timeout = timeout

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.__aexit__(None, None, None)
            self._http = None

    def _http_client(self) -> HttpClient:
        if self._http is None:
            self._http = HttpClient(self.metadata, timeout=self._timeout)
        return self._http

    async def fetch_page(
        self,
        *,
        start: Any,
        end: Any,
        cursor: Cursor,
        page_size: int = 2000,
    ) -> Page:
        """Not supported: OSV has no date-range pagination."""
        raise SourceError(
            "osv: OSV has no date-range pagination; use query_package() or get_vuln()"
        )

    async def query_package(
        self,
        name: str,
        ecosystem: str = "Packagist",
        version: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the raw OSV advisories known for a package (and optional version)."""
        package_name = str(name or "").strip()
        if not package_name:
            raise ValueError("package name is required")
        payload: Dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": str(ecosystem or "").strip() or "Packagist",
            }
        }
        if version:
            payload["package"]["version"] = str(version).strip()

        url = f"{self.metadata.base_url}/v1/query"
        data = await self._http_client().post_json(url, payload)
        if isinstance(data, dict):
            data = data.get("vulns") or []
        if not isinstance(data, list):
            raise SourceParseError("osv: unexpected response shape for package query")
        return [item for item in data if isinstance(item, dict)]

    async def get_vuln(self, vuln_id: str) -> Dict[str, Any]:
        """Return one raw OSV advisory by id (e.g. ``GHSA-...`` or ``OSV-...``)."""
        identifier = str(vuln_id or "").strip()
        if not identifier:
            raise ValueError("vuln id is required")
        url = f"{self.metadata.base_url}/v1/vulns/{quote(identifier, safe='')}"
        data = await self._http_client().get_json(url)
        if not isinstance(data, dict):
            raise SourceParseError("osv: unexpected response shape for advisory lookup")
        return data

    def normalize(self, raw: Dict[str, Any]) -> VulnerabilityRecord:
        return normalize_osv_record(raw)


__all__ = ["OSVConnector", "OSV_METADATA", "normalize_osv_record"]
