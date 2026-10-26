"""Project-aware triage: deterministic and conservative."""
from __future__ import annotations

from core.vuln_intel.models import Applicability, Confidence
from core.vuln_intel.triage import triage_many, triage_project


def _laravel_record(make_record, composer_package):
    return make_record(
        description="Laravel before 10.2.1 is vulnerable.",
        affected=[
            composer_package(
                "laravel/framework",
                start_including="10.0.0",
                end_excluding="10.2.1",
                fixed_version="10.2.1",
            )
        ],
    )


def test_composer_package_in_range_is_confirmed(
    make_record, make_project, composer_package
):
    record = _laravel_record(make_record, composer_package)
    project = make_project([{"name": "laravel/framework", "version": "10.1.0"}])
    result = triage_project(project, record)
    assert result.classification == Applicability.CONFIRMED_APPLICABLE
    assert result.confidence == Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
    assert result.matched_packages == ["laravel/framework@10.1.0"]
    assert result.fixed_versions == ["10.2.1"]
    assert "Upgrade" in result.recommended_action


def test_at_fixed_version_is_not_applicable(
    make_record, make_project, composer_package
):
    record = _laravel_record(make_record, composer_package)
    project = make_project([{"name": "laravel/framework", "version": "10.2.1"}])
    result = triage_project(project, record)
    assert result.classification == Applicability.NOT_APPLICABLE
    assert "fixed version" in " ".join(result.reasons)
    assert result.recommended_action.startswith("No action")


def test_below_range_is_not_applicable(make_record, make_project, composer_package):
    record = _laravel_record(make_record, composer_package)
    project = make_project([{"name": "laravel/framework", "version": "9.9.9"}])
    assert triage_project(project, record).classification == Applicability.NOT_APPLICABLE


def test_above_range_is_not_applicable(make_record, make_project, composer_package):
    record = _laravel_record(make_record, composer_package)
    project = make_project([{"name": "laravel/framework", "version": "10.3.0"}])
    assert triage_project(project, record).classification == Applicability.NOT_APPLICABLE


def test_unknown_version_is_possibly_applicable(
    make_record, make_project, composer_package
):
    record = _laravel_record(make_record, composer_package)
    project = make_project(
        [{"name": "laravel/framework", "version": None}], inventory_complete=True
    )
    result = triage_project(project, record)
    assert result.classification == Applicability.POSSIBLY_APPLICABLE
    assert result.confidence == Confidence.PROVISIONAL


def test_unknown_version_with_incomplete_inventory_is_insufficient(
    make_record, make_project, composer_package
):
    record = _laravel_record(make_record, composer_package)
    project = make_project(
        [{"name": "laravel/framework", "version": None}], inventory_complete=False
    )
    result = triage_project(project, record)
    assert result.classification == Applicability.INSUFFICIENT_EVIDENCE


def test_no_matching_package_with_complete_inventory_is_not_applicable(
    make_record, make_project, composer_package
):
    record = _laravel_record(make_record, composer_package)
    project = make_project(
        [{"name": "symfony/http-kernel", "version": "6.0.0"}],
        inventory_complete=True,
    )
    result = triage_project(project, record)
    assert result.classification == Applicability.NOT_APPLICABLE
    assert result.confidence == Confidence.STRONGLY_SUPPORTED


def test_no_matching_package_with_incomplete_inventory_is_insufficient(
    make_record, make_project, composer_package
):
    record = _laravel_record(make_record, composer_package)
    project = make_project(
        [{"name": "symfony/http-kernel", "version": "6.0.0"}],
        inventory_complete=False,
    )
    result = triage_project(project, record)
    assert result.classification == Applicability.INSUFFICIENT_EVIDENCE


def test_empty_project_is_insufficient(make_record, make_project, composer_package):
    record = _laravel_record(make_record, composer_package)
    result = triage_project(make_project([]), record)
    assert result.classification == Applicability.INSUFFICIENT_EVIDENCE


def test_advisory_without_affected_data_is_insufficient(make_record, make_project):
    record = make_record(affected=[])
    result = triage_project(make_project([]), record)
    assert result.classification == Applicability.INSUFFICIENT_EVIDENCE
    assert any("no machine-readable" in reason for reason in result.reasons)


def test_php_runtime_range_is_confirmed(make_record, make_project, cpe_package):
    record = make_record(
        description="PHP before 8.1.27 is vulnerable.",
        affected=[
            cpe_package(
                "php",
                "php",
                start_including="8.0.0",
                end_excluding="8.1.27",
            )
        ],
    )
    project = make_project([], php_version="8.1.10")
    result = triage_project(project, record)
    assert result.classification == Applicability.CONFIRMED_APPLICABLE
    assert result.confidence == Confidence.CONFIRMED_BY_AUTHORITATIVE_SOURCE
    assert any("PHP version" in reason for reason in result.reasons)


def test_php_runtime_unknown_version_is_insufficient(
    make_record, make_project, cpe_package
):
    record = make_record(
        description="PHP before 8.1.27 is vulnerable.",
        affected=[cpe_package("php", "php", end_excluding="8.1.27")],
    )
    result = triage_project(make_project([], php_version=None), record)
    assert result.classification == Applicability.INSUFFICIENT_EVIDENCE


def test_php_runtime_outside_range_is_not_applicable(
    make_record, make_project, cpe_package
):
    record = make_record(
        description="PHP before 8.1.27 is vulnerable.",
        affected=[cpe_package("php", "php", end_excluding="8.1.27")],
    )
    result = triage_project(make_project([], php_version="8.2.0"), record)
    assert result.classification == Applicability.NOT_APPLICABLE


def test_cpe_wordpress_core_matches_project_package(
    make_record, make_project, cpe_package
):
    record = make_record(
        description="WordPress before 6.4.2 is vulnerable.",
        affected=[
            cpe_package(
                "wordpress",
                "wordpress",
                start_including="6.0.0",
                end_excluding="6.4.2",
            )
        ],
    )
    project = make_project(
        [{"name": "wordpress/wordpress", "version": "6.3.0"}]
    )
    result = triage_project(project, record)
    assert result.classification == Applicability.CONFIRMED_APPLICABLE


def test_cpe_vendor_prefix_mismatch_does_not_match(
    make_record, make_project, cpe_package
):
    record = make_record(
        description="Laravel before 10.2.1 is vulnerable.",
        affected=[
            cpe_package(
                "laravel",
                "framework",
                start_including="10.0.0",
                end_excluding="10.2.1",
            )
        ],
    )
    project = make_project(
        [{"name": "symfony/framework", "version": "10.1.0"}],
        inventory_complete=True,
    )
    assert triage_project(project, record).classification == Applicability.NOT_APPLICABLE


def test_multiple_packages_choose_the_best_result(
    make_record, make_project, composer_package
):
    record = _laravel_record(make_record, composer_package)
    project = make_project(
        [
            {"name": "symfony/http-kernel", "version": "6.0.0"},
            {"name": "laravel/framework", "version": "10.1.0"},
        ]
    )
    result = triage_project(project, record)
    assert result.classification == Applicability.CONFIRMED_APPLICABLE
    assert result.matched_packages == ["laravel/framework@10.1.0"]


def test_exact_cpe_version_is_likely_not_confirmed(
    make_record, make_project, cpe_package
):
    record = make_record(
        description="A PHP runtime issue.",
        affected=[cpe_package("php", "php", version="8.1.0")],
    )
    project = make_project(
        [{"name": "php/php", "version": "8.1.0"}],
        inventory_complete=True,
    )
    result = triage_project(project, record)
    assert result.classification == Applicability.LIKELY_APPLICABLE
    assert result.confidence == Confidence.STRONGLY_SUPPORTED


def test_below_range_with_fixed_version_does_not_claim_at_or_above_fixed(
    make_record, make_project, composer_package
):
    record = make_record(
        description='A package issue.',
        affected=[
            composer_package(
                'example/package',
                start_including='1.0.0',
                fixed_version='2.0.0',
            )
        ],
    )
    project = make_project([{'name': 'example/package', 'version': '0.5.0'}])
    result = triage_project(project, record)
    assert result.classification == Applicability.NOT_APPLICABLE
    assert any('outside the advisory range' in reason for reason in result.reasons)
    assert not any('at or above the fixed version' in reason for reason in result.reasons)


def test_fixed_versions_from_record_and_package_are_merged(
    make_record, make_project, composer_package
):
    record = make_record(
        fixed_versions=["10.2.1"],
        affected=[
            composer_package(
                "laravel/framework",
                start_including="10.0.0",
                fixed_version="10.2.1",
            )
        ],
    )
    project = make_project([{"name": "laravel/framework", "version": "10.1.0"}])
    result = triage_project(project, record)
    assert result.fixed_versions == ["10.2.1"]


def test_triage_many_returns_one_result_per_record(
    make_record, make_project, composer_package
):
    first = _laravel_record(make_record, composer_package)
    second = make_record(
        source_record_id="CVE-2024-0002",
        description="A kernel issue.",
        affected=[],
    )
    project = make_project([{"name": "laravel/framework", "version": "10.1.0"}])
    results = triage_many(project, [first, second])
    assert len(results) == 2
    assert results[0].classification == Applicability.CONFIRMED_APPLICABLE
    assert results[1].classification == Applicability.INSUFFICIENT_EVIDENCE

def test_php_runtime_triage_ignores_non_php_vendor_product_php(
    make_record, make_project, cpe_package
):
    record = make_record(
        description="A PHP runtime issue.",
        affected=[
            cpe_package("php", "php", start_including="9.0.0"),
            cpe_package("acme", "php", end_excluding="9.0.0"),
        ],
    )
    project = make_project([], php_version="8.1.0")
    result = triage_project(project, record)
    assert result.classification == Applicability.NOT_APPLICABLE
    assert "outside the advisory range" in " ".join(result.reasons)
