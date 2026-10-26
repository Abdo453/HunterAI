"""NVD 2.0 connector and normalizer.

Source: https://services.nvd.nist.gov/rest/json/cves/2.0

What this module does **not** do
-------------------------------
* It does not invent a title, CVSS score, version range, fixed version, or
  exploitation status that NVD did not provide.
* It does not treat a CPE product match as proof that a specific install is
  vulnerable; that is the triage layer's job, with version evidence.
* It does not store the raw payload unless the store is explicitly configured
  to do so.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

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
    RateLimiter,
    SourceConnector,
    SourceMetadata,
    SourceParseError,
)

logger = logging.getLogger("core.vuln_intel.sources.nvd")

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)
_CPE_SPLIT_RE = re.compile(r"(?<!\\):")

NVD_METADATA = SourceMetadata(
    source_id="nvd",
    name="NIST National Vulnerability Database",
    base_url="https://services.nvd.nist.gov",
    license="NVD terms (verify before redistribution)",
    terms_url="https://nvd.nist.gov/general/legal",
    historical_start="2002-01-01",
    max_window_days=120,
    rate_limit_requests=5,
    rate_limit_period_seconds=30.0,
    allowed_hosts=("services.nvd.nist.gov",),
    supports_incremental=True,
    notes=(
        "Anonymous rate limit is 5 requests/30s; an API key raises it to "
        "50/30s. Date windows are capped at 120 days. Pre-2002 coverage is "
        "sparse and 2026 is still in progress."
    ),
)


class NVDConnector(SourceConnector):
    metadata = NVD_METADATA

    def __init__(
        self,
        *,
        api_key: Optional[str] = None,
        fetch_json: Optional[
            Callable[[str, Dict[str, Any], Dict[str, str]], Awaitable[Dict[str, Any]]]
        ] = None,
        http_client: Optional[HttpClient] = None,
        clock: Callable[[], datetime] = utc_now,
    ):
        self.api_key = api_key or os.getenv("NVD_API_KEY") or ""
        self._fetch_json = fetch_json
        self._http = http_client
        self._clock = clock

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.__aexit__(None, None, None)
            self._http = None

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    async def fetch_page(
        self,
        *,
        start: datetime,
        end: datetime,
        cursor: Cursor,
        page_size: int = 2000,
    ) -> Page:
        start = ensure_utc(start)  # type: ignore[assignment]
        end = ensure_utc(end)  # type: ignore[assignment]
        if start is None or end is None:
            raise ValueError("start and end are required")
        if start > end:
            raise ValueError("start must be <= end")
        if not 1 <= int(page_size) <= 2000:
            raise ValueError("page_size must be between 1 and 2000")

        params: Dict[str, Any] = {
            "pubStartDate": _nvd_timestamp(start),
            "pubEndDate": _nvd_timestamp(end),
            "startIndex": max(0, int(cursor.start_index)),
            "resultsPerPage": int(page_size),
        }
        url = f"{self.metadata.base_url}/rest/json/cves/2.0"
        headers = self._headers()

        if self._fetch_json is not None:
            data = await self._fetch_json(url, params, headers)
        else:
            if self._http is None:
                requests = 50 if self.api_key else 5
                self._http = HttpClient(
                    self.metadata,
                    rate_limiter=RateLimiter(requests, 30.0),
                    headers=headers,
                )
                await self._http.__aenter__()
            data = await self._http.get_json(url, params=params, headers=headers)

        if not isinstance(data, dict):
            raise SourceParseError("NVD response is not a JSON object")
        records = data.get("vulnerabilities")
        if records is None:
            records = []
        if not isinstance(records, list):
            raise SourceParseError("NVD 'vulnerabilities' is not a list")

        total: Optional[int]
        try:
            total = int(data.get("totalResults")) if data.get("totalResults") is not None else None
        except (TypeError, ValueError):
            total = None

        next_cursor: Optional[Cursor] = None
        next_index = int(cursor.start_index) + len(records)
        if records and (total is None or next_index < total):
            next_cursor = Cursor(
                start_index=next_index,
                page=int(cursor.page) + 1,
                token=None,
            )

        return Page(
            records=records,
            next_cursor=next_cursor,
            total_results=total,
            raw_count=len(records),
        )

    # ------------------------------------------------------------- normalize
    def normalize(self, raw: Dict[str, Any]) -> VulnerabilityRecord:
        if not isinstance(raw, dict):
            raise SourceParseError("NVD record is not an object")
        cve = raw.get("cve", raw)
        if not isinstance(cve, dict):
            raise SourceParseError("NVD 'cve' field is not an object")

        cve_id = str(cve.get("id") or "").strip().upper()
        if not cve_id:
            raise SourceParseError("NVD record has no CVE id")
        if not _CVE_RE.match(cve_id):
            # Do not reject non-CVE identifiers silently; keep the source id.
            logger.debug("NVD returned non-CVE identifier %r", cve_id)

        description = _pick_description(cve.get("descriptions"))
        status = _map_status(cve.get("vulnStatus"))
        cvss = _extract_cvss(cve.get("metrics") or {})
        severity = cvss.severity if cvss and cvss.severity else Severity.UNKNOWN
        cwes = _extract_cwes(cve.get("weaknesses") or [])
        references = _extract_references(cve.get("references") or [])
        affected = _extract_affected(cve.get("configurations") or [])

        published = _parse_nvd_datetime(cve.get("published"))
        last_modified = _parse_nvd_datetime(cve.get("lastModified"))

        raw_blob = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
        raw_hash = hashlib.sha256(raw_blob.encode("utf-8")).hexdigest()

        return VulnerabilityRecord(
            source_id=self.metadata.source_id,
            source_record_id=cve_id,
            canonical_id=cve_id,
            title=None,
            description=description,
            summary=None,
            published_at=published,
            last_modified_at=last_modified,
            discovery_at=None,
            disclosed_at=None,
            imported_at=self._clock(),
            vuln_status=status,
            severity=severity,
            cvss=cvss,
            cwes=cwes,
            affected=affected,
            references=references,
            aliases=[],
            known_exploited=None,
            remediation=None,
            workarounds=[],
            fixed_versions=[],
            confidence=Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE,
            provenance=[
                Provenance(
                    source_id=self.metadata.source_id,
                    source_record_id=cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    retrieved_at=self._clock(),
                    raw_sha256=raw_hash,
                    license=self.metadata.license,
                )
            ],
            metadata={
                "nvd_source_identifier": cve.get("sourceIdentifier"),
                "nvd_vuln_status": cve.get("vulnStatus"),
                "nvd_configurations_present": bool(cve.get("configurations")),
            },
        )


def _nvd_timestamp(value: datetime) -> str:
    value = ensure_utc(value)  # type: ignore[assignment]
    return value.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse_nvd_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return ensure_utc(datetime.fromisoformat(text))
    except ValueError:
        # NVD sometimes omits the timezone; treat it as UTC.
        try:
            return ensure_utc(datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%f"))
        except ValueError:
            return None


def _pick_description(descriptions: Any) -> Optional[str]:
    if not isinstance(descriptions, list):
        return None
    english: Optional[str] = None
    first: Optional[str] = None
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        if not isinstance(value, str) or not value.strip():
            continue
        if first is None:
            first = value.strip()
        if str(item.get("lang", "")).lower().startswith("en"):
            english = value.strip()
            break
    return english or first


def _map_status(value: Any) -> VulnStatus:
    text = str(value or "").strip().lower()
    if text == "analyzed":
        return VulnStatus.ANALYZED
    if text in {"modified", "undergoing analysis", "awaiting analysis", "received"}:
        return VulnStatus.MODIFIED
    if text == "rejected":
        return VulnStatus.REJECTED
    if text == "withdrawn":
        return VulnStatus.WITHDRAWN
    return VulnStatus.UNKNOWN


def _extract_cvss(metrics: Dict[str, Any]) -> Optional[CvssData]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        entry = _prefer_primary(entries)
        if not isinstance(entry, dict):
            continue
        data = entry.get("cvssData")
        if not isinstance(data, dict):
            continue
        fallback_versions = {
            "cvssMetricV40": "4.0",
            "cvssMetricV31": "3.1",
            "cvssMetricV30": "3.0",
            "cvssMetricV2": "2.0",
        }
        version = str(data.get("version") or fallback_versions.get(key, ""))
        score = data.get("baseScore")
        try:
            score = float(score) if score is not None else None
        except (TypeError, ValueError):
            score = None
        raw_severity = data.get("baseSeverity") or entry.get("baseSeverity")
        severity = _map_severity(raw_severity)
        return CvssData(
            version=version,
            score=score,
            vector=data.get("vectorString"),
            severity=severity,
            attack_vector=data.get("attackVector") or data.get("accessVector"),
            attack_complexity=data.get("attackComplexity") or data.get("accessComplexity"),
            privileges_required=data.get("privilegesRequired") or data.get("authentication"),
            user_interaction=data.get("userInteraction"),
            confidentiality_impact=data.get("confidentialityImpact"),
            integrity_impact=data.get("integrityImpact"),
            availability_impact=data.get("availabilityImpact"),
        )
    return None


def _prefer_primary(entries: List[Any]) -> Optional[Dict[str, Any]]:
    dicts = [entry for entry in entries if isinstance(entry, dict)]
    for entry in dicts:
        if str(entry.get("type", "")).lower() == "primary":
            return entry
    return dicts[0] if dicts else None


def _map_severity(value: Any) -> Severity:
    text = str(value or "").strip().lower()
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "none": Severity.NONE,
    }
    return mapping.get(text, Severity.UNKNOWN)


def _extract_cwes(weaknesses: Any) -> List[str]:
    out: List[str] = []
    if not isinstance(weaknesses, list):
        return out
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description") or []:
            if not isinstance(desc, dict):
                continue
            value = str(desc.get("value") or "").strip().upper()
            if _CWE_RE.match(value) and value not in out:
                out.append(value)
    return out


def _extract_references(references: Any) -> List[Reference]:
    out: List[Reference] = []
    seen: set[str] = set()
    if not isinstance(references, list):
        return out
    for ref in references:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        tags = [str(tag) for tag in (ref.get("tags") or []) if str(tag).strip()]
        lowered = {tag.lower() for tag in tags}
        if "patch" in lowered:
            ref_type = "patch"
        elif "exploit" in lowered:
            ref_type = "exploit"
        elif any("advisory" in tag for tag in lowered):
            ref_type = "advisory"
        else:
            ref_type = "web"
        out.append(
            Reference(
                url=url,
                ref_type=ref_type,
                source=str(ref.get("source") or "") or None,
                tags=tags,
            )
        )
    return out


def _extract_affected(configurations: Any) -> List[AffectedPackage]:
    out: List[AffectedPackage] = []
    seen: set[str] = set()
    if not isinstance(configurations, list):
        return out
    for config in configurations:
        if not isinstance(config, dict):
            continue
        for node in config.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            for match in node.get("cpeMatch") or []:
                if not isinstance(match, dict):
                    continue
                if match.get("vulnerable") is False:
                    continue
                criteria = str(match.get("criteria") or "").strip()
                if not criteria:
                    continue
                parts = _parse_cpe(criteria)
                cpe_version = parts.get("version")
                if cpe_version in {"*", "-", ""}:
                    cpe_version = None
                pkg = AffectedPackage(
                    ecosystem=Ecosystem.CPE,
                    vendor=parts.get("vendor"),
                    product=parts.get("product"),
                    package_name=parts.get("product"),
                    cpe=criteria,
                    cpe_version=cpe_version,
                    version_start_including=match.get("versionStartIncluding"),
                    version_start_excluding=match.get("versionStartExcluding"),
                    version_end_including=match.get("versionEndIncluding"),
                    version_end_excluding=match.get("versionEndExcluding"),
                    fixed_version=None,
                    configuration={
                        "match_criteria_id": match.get("matchCriteriaId"),
                        "node_operator": node.get("operator"),
                        "negate": node.get("negate"),
                        "source": config.get("source"),
                    },
                )
                key = pkg.dedupe_key
                if key not in seen:
                    seen.add(key)
                    out.append(pkg)
    return out


def _parse_cpe(criteria: str) -> Dict[str, Optional[str]]:
    """Parse a CPE 2.3 string into named components.

    Escaped colons are preserved.  If the string is not CPE 2.3, only the raw
    criteria is useful and the caller keeps it as ``cpe``.
    """
    if not criteria.startswith("cpe:2.3:"):
        return {}
    parts = _CPE_SPLIT_RE.split(criteria)
    # cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
    if len(parts) < 6:
        return {}
    names = [
        "prefix",
        "version_scheme",
        "part",
        "vendor",
        "product",
        "version",
        "update",
        "edition",
        "language",
        "sw_edition",
        "target_sw",
        "target_hw",
        "other",
    ]
    out: Dict[str, Optional[str]] = {}
    for index, name in enumerate(names):
        if index >= len(parts):
            break
        value = parts[index]
        if name in {"prefix", "version_scheme"}:
            continue
        out[name] = _unescape_cpe(value)
    return out


def _unescape_cpe(value: str) -> str:
    return value.replace("\\:", ":").replace("\\\\", "\\")


__all__ = ["NVDConnector", "NVD_METADATA"]
