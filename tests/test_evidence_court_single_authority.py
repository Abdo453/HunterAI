"""Guard: ``core.evidence_court`` must stay the single authoritative MODULE.

A stray ``core/evidence_court/`` package silently shadows ``core/evidence_court.py``
and breaks every ``from core.evidence_court import EvidenceCourt`` import in the
project (this happened twice during development). This test fails fast with a
clear message so the shadowing is caught immediately instead of surfacing as
dozens of unrelated collection errors.
"""
from __future__ import annotations

import core.evidence_court as ec


def test_evidence_court_resolves_to_the_module_not_a_package():
    assert not hasattr(ec, "__path__"), (
        "core.evidence_court resolved to a PACKAGE; it must be the module "
        "core/evidence_court.py. A package here shadows the authoritative court "
        "and breaks every 'from core.evidence_court import ...' in the project."
    )


def test_evidence_court_exposes_authoritative_api():
    for name in (
        "EvidenceCourt",
        "CourtVerdict",
        "CourtJudgment",
        "ProofPayload",
        "CausalEvidence",
        "ExecutionEvidence",
    ):
        assert hasattr(ec, name), f"core.evidence_court is missing the {name!r} API"
    assert hasattr(ec.EvidenceCourt, "adjudicate"), "EvidenceCourt.adjudicate is the authoritative entry point"
