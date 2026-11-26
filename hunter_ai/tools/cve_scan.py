"""
HunterAI CVE Scan — Evidence-First Vulnerability Intelligence Lookup
====================================================================
Replaces legacy simulated CVE stubs with real ``core/vuln_intel/`` SQLite
advisory queries, deterministic applicability triage, and explainable tool
selection. Never invents or hardcodes CVEs when the local store has no matches.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from core.vuln_intel.cli import DEFAULT_DB
from core.vuln_intel.db import VulnerabilityStore
from core.vuln_intel.models import (
    Ecosystem,
    ProjectPackage,
    ProjectProfile,
    VulnerabilityRecord,
    record_from_stored,
)
from core.vuln_intel.tool_capabilities import DEFAULT_CAPABILITIES, ToolAvailability
from core.vuln_intel.tool_selection import SelectionScope, select_tools
from core.vuln_intel.triage import triage_project

logger = logging.getLogger("hunter_ai.tools.cve_scan")

# Canonical alias matching the architecture specification
VulnDB = VulnerabilityStore

_TECH_VER_RE = re.compile(r"^\s*([A-Za-z0-9_.\-@/]+?)(?:[:/\s@]+v?(\d+(?:\.\d+){0,3}[A-Za-z0-9._\-]*))?\s*$")

_ECOSYSTEM_HINTS: Dict[str, Ecosystem] = {
    "composer": Ecosystem.COMPOSER,
    "packagist": Ecosystem.PACKAGIST,
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "pip": Ecosystem.PYPI,
    "go": Ecosystem.GO,
    "maven": Ecosystem.MAVEN,
    "nuget": Ecosystem.NUGET,
    "rubygems": Ecosystem.RUBYGEMS,
    "crates": Ecosystem.CRATES,
    "wordpress": Ecosystem.WORDPRESS,
    "drupal": Ecosystem.DRUPAL,
    "magento": Ecosystem.MAGENTO,
    "php": Ecosystem.PHP,
    "cpe": Ecosystem.CPE,
}


def _resolve_db_path(db_path: Optional[Union[str, Path]] = None) -> Path:
    if db_path is not None:
        return Path(db_path)
    env_path = (os.environ.get("HUNTER_VULN_INTEL_DB") or "").strip()
    return Path(env_path) if env_path else Path(DEFAULT_DB)


def _infer_ecosystem(name: str, explicit: Optional[str] = None) -> Ecosystem:
    if explicit:
        key = explicit.strip().lower()
        if key in _ECOSYSTEM_HINTS:
            return _ECOSYSTEM_HINTS[key]
    low = name.strip().lower()
    if low == "php" or low.startswith("php-"):
        return Ecosystem.PHP
    if "wordpress" in low:
        return Ecosystem.WORDPRESS
    if "drupal" in low:
        return Ecosystem.DRUPAL
    if "magento" in low:
        return Ecosystem.MAGENTO
    if "/" in low:
        return Ecosystem.COMPOSER
    return Ecosystem.CPE


def _parse_tech_entry(entry: Any) -> Optional[Tuple[str, Optional[str], Ecosystem]]:
    if isinstance(entry, ProjectPackage):
        return entry.name, entry.version, entry.ecosystem
    if isinstance(entry, dict):
        name = str(entry.get("name") or entry.get("package") or entry.get("product") or "").strip()
        if not name:
            return None
        version = str(entry.get("version")).strip() if entry.get("version") else None
        eco = _infer_ecosystem(name, entry.get("ecosystem"))
        return name, version, eco
    if isinstance(entry, str):
        raw = entry.strip()
        if not raw:
            return None
        m = _TECH_VER_RE.match(raw)
        if not m:
            return raw, None, _infer_ecosystem(raw)
        name = m.group(1).strip()
        version = m.group(2).strip() if m.group(2) else None
        return name, version, _infer_ecosystem(name)
    return None


def _build_project_profile(
    host: str,
    technologies: Optional[Sequence[Any]] = None,
    packages: Optional[Sequence[Any]] = None,
    php_version: Optional[str] = None,
) -> ProjectProfile:
    pkg_list: List[ProjectPackage] = []
    frameworks: Dict[str, str] = {}
    detected_php = php_version

    seen: set[Tuple[str, str, str]] = set()
    for raw_item in list(technologies or []) + list(packages or []):
        parsed = _parse_tech_entry(raw_item)
        if not parsed:
            continue
        name, version, eco = parsed
        low = name.lower()
        if low == "php" and version and not detected_php:
            detected_php = version
        if low in {"laravel", "symfony", "wordpress", "drupal", "magento", "django", "rails", "spring", "next.js", "express"}:
            frameworks[low] = version or "unknown"
        key = (low, version or "", eco.value)
        if key in seen:
            continue
        seen.add(key)
        pkg_list.append(ProjectPackage(name=name, version=version, ecosystem=eco, source="cve_scan"))

    return ProjectProfile(
        project_id=host or "unknown",
        name=host or "unknown",
        ecosystem=pkg_list[0].ecosystem if pkg_list else Ecosystem.CPE,
        packages=pkg_list,
        php_version=detected_php,
        frameworks=frameworks,
        inventory_complete=False,
    )


def _search_store_for_project(
    store: VulnerabilityStore,
    host: str,
    project: ProjectProfile,
    limit: int,
) -> List[Dict[str, Any]]:
    by_id: Dict[str, Dict[str, Any]] = {}

    def _collect(rows: List[Dict[str, Any]]) -> None:
        for row in rows:
            rid = str(row.get("record_id") or row.get("canonical_id") or "")
            if rid and rid not in by_id:
                by_id[rid] = row

    for pkg in project.packages:
        name = pkg.name.strip()
        basename = name.split("/")[-1]
        _collect(store.search(package=name, limit=limit))
        _collect(store.search(product=basename, limit=limit))
        if len(by_id) < limit:
            _collect(store.search(text=name, limit=limit))
            if basename != name:
                _collect(store.search(text=basename, limit=limit))

    if project.php_version and len(by_id) < limit:
        _collect(store.search(product="php", limit=limit))

    if not project.packages and not project.php_version and host:
        _collect(store.search(text=host, limit=limit))

    return list(by_id.values())[:limit]


async def _query_osv_for_packages(
    packages: Sequence[ProjectPackage],
    store: Optional[VulnerabilityStore] = None,
) -> List[VulnerabilityRecord]:
    """Optional read-only OSV.dev enrichment when caller explicitly enables network access."""
    from core.vuln_intel.sources.osv import OSVConnector, normalize_osv_record

    eco_map = {
        Ecosystem.COMPOSER: "Packagist",
        Ecosystem.PACKAGIST: "Packagist",
        Ecosystem.NPM: "npm",
        Ecosystem.PYPI: "PyPI",
        Ecosystem.GO: "Go",
        Ecosystem.MAVEN: "Maven",
        Ecosystem.NUGET: "NuGet",
        Ecosystem.RUBYGEMS: "RubyGems",
        Ecosystem.CRATES: "crates.io",
    }
    connector = OSVConnector()
    records: List[VulnerabilityRecord] = []
    try:
        for pkg in packages[:10]:
            osv_eco = eco_map.get(pkg.ecosystem)
            if not osv_eco:
                continue
            try:
                raws = await connector.query_package(pkg.name, osv_eco, pkg.version)
            except Exception as exc:
                logger.debug("OSV lookup failed for %s: %s", pkg.name, exc)
                continue
            for raw in raws:
                try:
                    rec = normalize_osv_record(raw)
                    records.append(rec)
                    if store is not None:
                        store.upsert_vulnerability(rec)
                except Exception:
                    continue
    finally:
        await connector.aclose()
    return records


def scan_cves(
    host: str,
    *,
    technologies: Optional[Sequence[Any]] = None,
    packages: Optional[Sequence[Any]] = None,
    php_version: Optional[str] = None,
    db_path: Optional[Union[str, Path]] = None,
    authorized: bool = False,
    max_risk: str = "low",
    allow_osv_network: bool = False,
    limit: int = 50,
) -> Dict[str, Any]:
    """Query ``core/vuln_intel/`` SQLite store + deterministic triage & tool selection.

    Never fabricates CVEs. Returns explicit ``status="UNAVAILABLE"`` and empty
    provenance whenever the local vulnerability store has no matching advisories.
    """
    resolved_db = _resolve_db_path(db_path)
    store = VulnerabilityStore(resolved_db)
    db_total = store.count()

    project = _build_project_profile(
        host=host,
        technologies=technologies,
        packages=packages,
        php_version=php_version,
    )

    matched_rows = _search_store_for_project(store, host, project, limit=max(1, int(limit)))
    records: List[VulnerabilityRecord] = [record_from_stored(row) for row in matched_rows]

    osv_queried = False
    if allow_osv_network and project.packages:
        osv_queried = True
        try:
            try:
                asyncio.get_running_loop()
                # Avoid nested asyncio.run inside an active loop; keep hermetic/non-blocking.
                osv_records: List[VulnerabilityRecord] = []
            except RuntimeError:
                osv_records = asyncio.run(_query_osv_for_packages(project.packages, store=store))
            existing_ids = {r.record_id for r in records}
            for rec in osv_records:
                if rec.record_id not in existing_ids:
                    records.append(rec)
                    existing_ids.add(rec.record_id)
            db_total = store.count()
        except Exception as exc:
            logger.debug("OSV live query skipped: %s", exc)

    if not records:
        reason = (
            "Local vuln_intel SQLite store is empty (0 records); run vuln_intel sync before scanning."
            if db_total == 0
            else "No advisories matched the target inventory in local vuln_intel SQLite store."
        )
        return {
            "host": host,
            "status": "UNAVAILABLE",
            "available": db_total > 0,
            "reason": reason,
            "cves": [],
            "total": 0,
            "provenance": {
                "source": "core.vuln_intel",
                "db_path": str(store.db_path),
                "db_records_total": db_total,
                "matched_records": 0,
                "advisory_sources": [],
                "osv_queried": osv_queried,
            },
        }

    scope = SelectionScope(
        authorized=bool(authorized),
        max_risk=max_risk,
        require_installed=False,
    )
    capabilities = [cap.model_copy(deep=True) for cap in DEFAULT_CAPABILITIES]

    cves_out: List[Dict[str, Any]] = []
    advisory_sources: set[str] = set()
    for rec in records[: max(1, int(limit))]:
        advisory_sources.add(rec.source_id)
        triage_res = triage_project(project, rec)
        selection_res = select_tools(rec, project, scope, capabilities)
        cves_out.append({
            "cve": rec.canonical_id,
            "record_id": rec.record_id,
            "title": rec.title or rec.summary or rec.canonical_id,
            "severity": rec.severity.value,
            "cvss_score": rec.cvss.score if rec.cvss else None,
            "cwes": list(rec.cwes),
            "source_id": rec.source_id,
            "published_at": rec.published_at.isoformat() if rec.published_at else None,
            "applicability": triage_res.classification.value,
            "confidence": triage_res.confidence.value,
            "matched_packages": list(triage_res.matched_packages),
            "fixed_versions": list(triage_res.fixed_versions),
            "reasons": list(triage_res.reasons),
            "recommended_action": triage_res.recommended_action,
            "tool_selection": {
                "status": selection_res.status,
                "vuln_classes": list(selection_res.vuln_classes),
                "selected_tools": [s.tool_id for s in selection_res.selected],
            },
            "provenance": [p.model_dump(mode="json") for p in rec.provenance],
        })

    return {
        "host": host,
        "status": "OK",
        "available": True,
        "cves": cves_out,
        "total": len(cves_out),
        "provenance": {
            "source": "core.vuln_intel",
            "db_path": str(store.db_path),
            "db_records_total": db_total,
            "matched_records": len(cves_out),
            "advisory_sources": sorted(advisory_sources),
            "osv_queried": osv_queried,
        },
    }


__all__ = ["scan_cves", "VulnDB"]
