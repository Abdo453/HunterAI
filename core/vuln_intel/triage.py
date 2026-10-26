"""Project-aware applicability triage.

The matcher is deterministic and conservative:

* package/framework names must match (no substring guessing);
* the installed version must be present and parseable to confirm applicability;
* a fixed version at or below the installed version means NOT_APPLICABLE;
* unknown versions yield INSUFFICIENT_EVIDENCE, never a false confirmation;
* if the project inventory is incomplete, an absent package yields
  INSUFFICIENT_EVIDENCE rather than NOT_APPLICABLE.

It does not perform any active testing.  Active validation belongs to the
existing pipeline and must pass through the authorization layer.
"""
from __future__ import annotations

from typing import Iterable, List, Optional, Sequence, Tuple

from .models import (
    AffectedPackage,
    Applicability,
    Confidence,
    Ecosystem,
    PhpComponent,
    ProjectPackage,
    ProjectProfile,
    TriageResult,
    VulnerabilityRecord,
    normalize_package_name,
    utc_now,
)
from .php import classify_php
from .versions import compare_versions

_RANK = {
    Applicability.CONFIRMED_APPLICABLE: 5,
    Applicability.LIKELY_APPLICABLE: 4,
    Applicability.POSSIBLY_APPLICABLE: 3,
    Applicability.INSUFFICIENT_EVIDENCE: 2,
    Applicability.NOT_APPLICABLE: 1,
}

_COMPOSER_ECOSYSTEMS = {Ecosystem.COMPOSER, Ecosystem.PACKAGIST}
_CMS_ECOSYSTEMS = {Ecosystem.WORDPRESS, Ecosystem.DRUPAL, Ecosystem.MAGENTO}


def _has_range(pkg: AffectedPackage) -> bool:
    return any(
        [
            pkg.version_start_including,
            pkg.version_start_excluding,
            pkg.version_end_including,
            pkg.version_end_excluding,
        ]
    )


def _name_matches(affected: AffectedPackage, project_pkg: ProjectPackage) -> bool:
    eco = affected.ecosystem
    name = normalize_package_name(project_pkg.name)
    basename = name.split("/")[-1]
    product = normalize_package_name(affected.product)
    package_name = normalize_package_name(affected.package_name)
    vendor = normalize_package_name(affected.vendor)

    if eco in _COMPOSER_ECOSYSTEMS:
        if project_pkg.ecosystem not in _COMPOSER_ECOSYSTEMS:
            return False
        return bool(package_name) and name == package_name

    if eco in _CMS_ECOSYSTEMS:
        candidates = {name, basename}
        return bool(product) and (
            product in candidates
            or (bool(package_name) and package_name in candidates)
        )

    if eco == Ecosystem.CPE:
        if not product:
            return False
        if "/" in name and vendor:
            prefix = name.split("/")[0]
            if prefix != vendor:
                return False
        if basename == product or name == product:
            return True
        if vendor == product and "/" in name and name.split("/")[0] == vendor:
            return True
        return False

    if eco == Ecosystem.PHP:
        return product == "php" or package_name == "php" or basename == "php"

    return False


def _evaluate_affected(
    *,
    project: ProjectProfile,
    project_pkg: ProjectPackage,
    affected: AffectedPackage,
) -> Tuple[Applicability, Confidence, List[str], List[str]]:
    reasons: List[str] = []
    component = (
        affected.package_name
        or affected.product
        or affected.cpe
        or affected.ecosystem.value
    )
    evidence: List[str] = [
        f"project package {project_pkg.name!r} matched advisory component {component!r}"
    ]
    if not project_pkg.version:
        reasons.append(
            "installed version is unknown; applicability cannot be confirmed"
        )
        classification = (
            Applicability.POSSIBLY_APPLICABLE
            if project.inventory_complete
            else Applicability.INSUFFICIENT_EVIDENCE
        )
        return classification, Confidence.PROVISIONAL, reasons, evidence

    match = affected.matches_version(project_pkg.version)
    if match is True:
        if _has_range(affected):
            classification = Applicability.CONFIRMED_APPLICABLE
            confidence = Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
            reasons.append(
                f"installed version {project_pkg.version} falls inside the advisory range"
            )
        else:
            classification = Applicability.LIKELY_APPLICABLE
            confidence = Confidence.STRONGLY_SUPPORTED
            reasons.append(
                f"installed version {project_pkg.version} equals the advisory's exact CPE version; "
                "configuration may still differ"
            )
        if affected.fixed_version:
            evidence.append(f"advisory fixed version: {affected.fixed_version}")
    elif match is False:
        classification = Applicability.NOT_APPLICABLE
        confidence = Confidence.STRONGLY_SUPPORTED
        at_or_above_fixed = False
        if affected.fixed_version:
            fixed_cmp = compare_versions(project_pkg.version, affected.fixed_version)
            at_or_above_fixed = fixed_cmp is not None and fixed_cmp >= 0
        if at_or_above_fixed:
            reasons.append(
                f"installed version {project_pkg.version} is at or above the fixed version "
                f"{affected.fixed_version}"
            )
        else:
            reasons.append(
                f"installed version {project_pkg.version} is outside the advisory range"
            )
    else:
        classification = Applicability.INSUFFICIENT_EVIDENCE
        confidence = Confidence.PROVISIONAL
        reasons.append(
            "the advisory has no usable version range, or the version could not be compared"
        )
    return classification, confidence, reasons, evidence


def _evaluate_php_runtime(
    *,
    record: VulnerabilityRecord,
    project: ProjectProfile,
) -> Optional[Tuple[Applicability, Confidence, List[str], List[str]]]:
    analysis = classify_php(record)
    if analysis.component_type != PhpComponent.RUNTIME:
        return None
    if not project.php_version:
        return (
            Applicability.INSUFFICIENT_EVIDENCE,
            Confidence.PROVISIONAL,
            ["the project PHP version is unknown"],
            ["advisory is classified as a PHP runtime issue"],
        )

    runtime_packages = [
        pkg
        for pkg in record.affected
        if (pkg.vendor or "").lower() in {"php", "php_group"}
        and (
            (pkg.product or "").lower() in {"php", "php-fpm"}
            or (pkg.package_name or "").lower() == "php"
        )
    ]
    if not runtime_packages:
        return (
            Applicability.INSUFFICIENT_EVIDENCE,
            Confidence.PROVISIONAL,
            ["the advisory does not contain a machine-readable PHP version range"],
            ["advisory is classified as a PHP runtime issue"],
        )

    results: List[Tuple[Applicability, Confidence, List[str], List[str]]] = []
    for pkg in runtime_packages:
        match = pkg.matches_version(project.php_version)
        if match is True:
            has_range = _has_range(pkg)
            results.append(
                (
                    Applicability.CONFIRMED_APPLICABLE if has_range else Applicability.LIKELY_APPLICABLE,
                    Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
                    if has_range
                    else Confidence.STRONGLY_SUPPORTED,
                    [
                        f"project PHP version {project.php_version} is affected by the advisory range"
                        if has_range
                        else f"project PHP version {project.php_version} matches the advisory's exact PHP version"
                    ],
                    [f"PHP runtime range: {pkg.cpe or pkg.package_name or 'php'}"],
                )
            )
        elif match is False:
            results.append(
                (
                    Applicability.NOT_APPLICABLE,
                    Confidence.STRONGLY_SUPPORTED,
                    [f"project PHP version {project.php_version} is outside the advisory range"],
                    [f"PHP runtime range: {pkg.cpe or pkg.package_name or 'php'}"],
                )
            )
        else:
            results.append(
                (
                    Applicability.INSUFFICIENT_EVIDENCE,
                    Confidence.PROVISIONAL,
                    ["PHP version comparison was not possible"],
                    [f"PHP runtime range: {pkg.cpe or pkg.package_name or 'php'}"],
                )
            )
    return _best(results)


def _best(
    results: Sequence[Tuple[Applicability, Confidence, List[str], List[str]]]
) -> Tuple[Applicability, Confidence, List[str], List[str]]:
    best = max(results, key=lambda item: _RANK[item[0]])
    reasons: List[str] = []
    evidence: List[str] = []
    for classification, _confidence, item_reasons, item_evidence in results:
        if classification == best[0]:
            for reason in item_reasons:
                if reason not in reasons:
                    reasons.append(reason)
            for item in item_evidence:
                if item not in evidence:
                    evidence.append(item)
    return best[0], best[1], reasons, evidence


def triage_project(project: ProjectProfile, record: VulnerabilityRecord) -> TriageResult:
    results: List[Tuple[Applicability, Confidence, List[str], List[str]]] = []
    matched_packages: List[str] = []
    fixed_versions: List[str] = list(record.fixed_versions)

    for project_pkg in project.packages:
        for affected in record.affected:
            if not _name_matches(affected, project_pkg):
                continue
            matched_packages.append(
                f"{project_pkg.name}@{project_pkg.version or 'unknown'}"
            )
            results.append(
                _evaluate_affected(
                    project=project,
                    project_pkg=project_pkg,
                    affected=affected,
                )
            )
            if affected.fixed_version:
                fixed_versions.append(affected.fixed_version)

    runtime = _evaluate_php_runtime(record=record, project=project)
    if runtime is not None:
        results.append(runtime)

    if results:
        classification, confidence, reasons, evidence = _best(results)
    else:
        if not record.affected:
            classification = Applicability.INSUFFICIENT_EVIDENCE
            confidence = Confidence.PROVISIONAL
            reasons = ["the advisory has no machine-readable affected package data"]
            evidence = ["no affected package/version range in the stored record"]
        elif not project.packages and not project.php_version:
            classification = Applicability.INSUFFICIENT_EVIDENCE
            confidence = Confidence.PROVISIONAL
            reasons = ["the project inventory is empty"]
            evidence = ["no packages or PHP version were supplied"]
        elif project.inventory_complete:
            classification = Applicability.NOT_APPLICABLE
            confidence = Confidence.STRONGLY_SUPPORTED
            reasons = ["no project package matches the advisory's affected components"]
            evidence = [
                "compared "
                + ", ".join(sorted({pkg.package_name or pkg.product or "unknown" for pkg in record.affected}))
            ]
        else:
            classification = Applicability.INSUFFICIENT_EVIDENCE
            confidence = Confidence.PROVISIONAL
            reasons = [
                "no match was found, but the project inventory is marked incomplete"
            ]
            evidence = ["inventory_complete=False"]

    fixed_versions = sorted({value for value in fixed_versions if value})
    if classification in {
        Applicability.CONFIRMED_APPLICABLE,
        Applicability.LIKELY_APPLICABLE,
    }:
        action = (
            "Upgrade to a documented fixed version or apply the vendor mitigation; "
            "validate the fix in an authorized environment."
        )
        if fixed_versions:
            action += " Known fixed version(s): " + ", ".join(fixed_versions) + "."
    elif classification == Applicability.POSSIBLY_APPLICABLE:
        action = "Determine the installed version and configuration before deciding."
    elif classification == Applicability.INSUFFICIENT_EVIDENCE:
        action = "Collect version/configuration evidence; do not treat this as confirmed."
    else:
        action = "No action required based on the available evidence."

    return TriageResult(
        vuln_id=record.record_id,
        project_id=project.project_id,
        classification=classification,
        confidence=confidence,
        reasons=reasons,
        evidence=evidence,
        matched_packages=sorted(set(matched_packages)),
        fixed_versions=fixed_versions,
        recommended_action=action,
        evaluated_at=utc_now(),
    )


def triage_many(
    project: ProjectProfile, records: Iterable[VulnerabilityRecord]
) -> List[TriageResult]:
    return [triage_project(project, record) for record in records]


__all__ = ["triage_project", "triage_many"]
