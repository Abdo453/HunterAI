"""CVSS v3 base score calculation (deterministic, spec-based)."""
from __future__ import annotations

import pytest

from core.vuln_intel.cvss import (
    cvss3_base_score,
    parse_cvss3_vector,
    severity_from_label,
    severity_from_score,
)
from core.vuln_intel.models import Severity


@pytest.mark.parametrize(
    "vector,expected",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ],
)
def test_known_vectors_score_correctly(vector, expected):
    assert cvss3_base_score(vector) == expected


def test_parse_returns_base_metrics_only():
    metrics = parse_cvss3_vector(
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C"
    )
    assert metrics is not None
    assert metrics["AV"] == "N"
    assert metrics["S"] == "U"
    assert "E" not in metrics


def test_cvss4_vector_is_not_calculated():
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert parse_cvss3_vector(vector) is None
    assert cvss3_base_score(vector) is None


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "not a vector",
        "CVSS:3.1/AV:N/AC:L",  # missing metrics
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # unknown metric value
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:X/C:H/I:H/A:H",  # unknown scope
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",  # missing A
    ],
)
def test_malformed_vectors_return_none(vector):
    assert cvss3_base_score(vector) is None


def test_severity_bands():
    assert severity_from_score(9.8) == Severity.CRITICAL
    assert severity_from_score(7.5) == Severity.HIGH
    assert severity_from_score(4.0) == Severity.MEDIUM
    assert severity_from_score(0.1) == Severity.LOW
    assert severity_from_score(0.0) == Severity.NONE
    assert severity_from_score(None) == Severity.UNKNOWN


def test_severity_labels():
    assert severity_from_label("CRITICAL") == Severity.CRITICAL
    assert severity_from_label("MODERATE") == Severity.MEDIUM
    assert severity_from_label("low") == Severity.LOW
    assert severity_from_label("weird") == Severity.UNKNOWN
    assert severity_from_label(None) == Severity.UNKNOWN
