"""Minimal CVSS v3.x base-score calculation.

Why this exists
---------------
OSV records usually ship a CVSS *vector* (``CVSS:3.1/AV:N/...``) and a
human-readable severity label.  To store a score we need to compute it
ourselves instead of trusting a free-text label.

Rules
-----
* Only the **base score** of CVSS v3.0/v3.1 is computed (spec section 8.1).
* Temporal and environmental metrics are ignored: this is the base score only.
* CVSS v4.0 vectors use a different metric set and are **not** calculated here.
  The vector is still stored as data, but the score stays ``None``.
* An unknown metric, an unknown prefix, or a malformed vector returns ``None``.
  The function never guesses.

The implementation follows the published CVSS v3.1 specification (Appendix A
"Roundup" and the base-score equations).
"""
from __future__ import annotations

import math
from typing import Dict, Optional

from .models import Severity

__all__ = [
    "cvss3_base_score",
    "parse_cvss3_vector",
    "severity_from_score",
    "severity_from_label",
]


_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}

_REQUIRED_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_cvss3_vector(vector: str) -> Optional[Dict[str, str]]:
    """Return the base metrics of a CVSS v3.x vector, or ``None``.

    Only the base metrics are returned; temporal/environmental metrics are
    ignored.  ``None`` means "not a usable CVSS v3 base vector".
    """
    text = (vector or "").strip()
    if not text.upper().startswith("CVSS:3."):
        return None

    metrics: Dict[str, str] = {}
    for part in text.split("/")[1:]:
        if ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip().upper()
        value = value.strip().upper()
        # Temporal and environmental metrics are ignored: only the base
        # metrics are returned.
        if key in _REQUIRED_METRICS and value:
            metrics[key] = value

    if any(key not in metrics for key in _REQUIRED_METRICS):
        return None
    if metrics["S"] not in {"U", "C"}:
        return None
    return metrics


def _roundup(value: float) -> float:
    """CVSS v3.1 "Roundup": smallest one-decimal value not below ``value``."""
    scaled = int(round(value * 100000))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> Optional[float]:
    """Compute the CVSS v3.x base score of ``vector`` (``None`` if unknown)."""
    metrics = parse_cvss3_vector(vector)
    if metrics is None:
        return None

    av = _AV.get(metrics["AV"])
    ac = _AC.get(metrics["AC"])
    ui = _UI.get(metrics["UI"])
    c = _CIA.get(metrics["C"])
    i = _CIA.get(metrics["I"])
    a = _CIA.get(metrics["A"])
    scope_changed = metrics["S"] == "C"
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED).get(metrics["PR"])

    if None in (av, ac, pr, ui, c, i, a):
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    raw = impact + exploitability
    if scope_changed:
        raw *= 1.08
    return _roundup(min(raw, 10.0))


def severity_from_score(score: Optional[float]) -> Severity:
    """Map a CVSS score to the severity band used by this project."""
    if score is None:
        return Severity.UNKNOWN
    value = float(score)
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0.0:
        return Severity.LOW
    return Severity.NONE


def severity_from_label(label: object) -> Severity:
    """Map a vendor severity label (e.g. GHSA ``MODERATE``) to a severity band."""
    text = str(label or "").strip().lower()
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "moderate": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "none": Severity.NONE,
    }
    return mapping.get(text, Severity.UNKNOWN)
