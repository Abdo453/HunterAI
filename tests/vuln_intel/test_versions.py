"""Deterministic version parsing and range comparison."""
from __future__ import annotations

import pytest

from core.vuln_intel.versions import (
    compare_versions,
    normalize_package_name,
    parse_version,
    version_in_range,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("8.1.2", "8.1.2"),
        ("v2.4.1", "2.4.1"),
        ("1.0.0-beta1", "1.0.0b1"),
        ("8.1.2-1ubuntu2.14", "8.1.2"),
        (" 10.2.1 ", "10.2.1"),
    ],
)
def test_parse_version_accepts_common_forms(value, expected):
    parsed = parse_version(value)
    assert parsed is not None
    assert str(parsed) == expected


@pytest.mark.parametrize("value", [None, "", "*", "-", "unknown", "not-a-version"])
def test_parse_version_returns_none_for_unknown(value):
    assert parse_version(value) is None


def test_compare_versions_is_deterministic():
    assert compare_versions("1.2.3", "1.2.3") == 0
    assert compare_versions("1.2.3", "1.2.4") == -1
    assert compare_versions("2.0", "1.9.9") == 1
    assert compare_versions("unknown", "1.0") is None


def test_version_in_range_inclusive_and_exclusive_bounds():
    assert version_in_range(
        "1.5", start_including="1.0", end_excluding="2.0"
    ) is True
    assert version_in_range(
        "2.0", start_including="1.0", end_excluding="2.0"
    ) is False
    assert version_in_range(
        "2.0", start_including="1.0", end_including="2.0"
    ) is True
    assert version_in_range(
        "1.0", start_excluding="1.0", end_including="2.0"
    ) is False
    assert version_in_range(
        "0.9", start_including="1.0", end_including="2.0"
    ) is False


def test_version_in_range_returns_none_for_unparseable_input():
    assert version_in_range("not-a-version", start_including="1.0") is None
    assert version_in_range("1.5", start_including="not-a-version") is None


def test_normalize_package_name_is_case_and_whitespace_only():
    assert normalize_package_name("  Laravel/Framework ") == "laravel/framework"
    assert normalize_package_name(None) == ""
