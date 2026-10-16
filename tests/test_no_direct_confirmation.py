"""LEDGER-016 (M1a): no evidence-grade CONFIRMED outside the Evidence Court.

These guards fail if a live code path can declare CONFIRMED from a bare caller
flag, an LLM vote, or a dangerous default — i.e. without re-evaluable proof.

The single authoritative gate is ``core.evidence_court.EvidenceCourt`` (and the
pipeline gates that call it). Anything else that names
``LifecycleStage.CONFIRMED`` or emits an evidence-grade ``CONFIRMED`` is a
regression.
"""
from __future__ import annotations

import importlib
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Modules that legitimately own the lifecycle enum / state machine.
_LIFECYCLE_OWNERS = {
    "core/evidence_contract.py",
    "core/lifecycle/finding_lifecycle.py",
    "core/lifecycle/finding_lifecycle_engine.py",
}


def test_dead_arbitration_engine_is_removed():
    """core/arbitration_engine.py was dead code writing CONFIRMED from a flag.

    It duplicated the Evidence Court, had zero importers, and its
    ``is_verified = tool_output.get("verified")`` shortcut could promote an
    unproven claim. It is deleted rather than wired up.
    """
    assert not (REPO_ROOT / "core" / "arbitration_engine.py").exists()
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("core.arbitration_engine")


def test_no_direct_lifecycle_confirmed_writes_outside_owners():
    """No core module may name LifecycleStage.CONFIRMED except its owners."""
    offenders = []
    for path in (REPO_ROOT / "core").rglob("*.py"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in _LIFECYCLE_OWNERS:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"LifecycleStage\.CONFIRMED", text):
            offenders.append(rel)
    assert offenders == [], f"Direct LifecycleStage.CONFIRMED writes: {offenders}"


def test_verdict_default_is_fail_closed():
    """A Verdict built without an explicit decision must not default to CONFIRMED."""
    from core.evidence_os.unified_model import Verdict

    assert Verdict().decision != "CONFIRMED"


def test_confidence_consensus_is_advisory_not_confirmed():
    """Unanimous LLM votes are advisory consensus, never evidence-grade CONFIRMED."""
    from core.confidence_checker import ConfidenceChecker, ModelVerdict

    checker = ConfidenceChecker()
    verdicts = [
        ModelVerdict("m", "sec", "CONFIRMED", 0.99, "e", "r", 0.1)
        for _ in range(5)
    ]
    res = checker._calculate_consensus("claim", "http://target", verdicts, "", "", 0.0)
    assert res.final_verdict != "CONFIRMED"
    assert res.final_verdict in {"CORROBORATED", "UNCERTAIN", "FALSE_POSITIVE"}


def test_court_confirms_only_with_derived_proof_not_declared_flag():
    """The sanctioned gate confirms derived proof and refuses a bare caller flag."""
    from core.evidence_court import (
        CausalEvidence,
        CourtVerdict,
        EvidenceCourt,
    )

    # Derived proof (a typed causal invariant) -> CONFIRMED.
    derived = EvidenceCourt.adjudicate(
        target_url="http://t/",
        parameter="id",
        vuln_class="cmd_injection",
        verifier_result={"reproduced": True},
        causal_evidence=CausalEvidence(invariant_passed=True, rationale="invariant held"),
    )
    assert derived.verdict is CourtVerdict.CONFIRMED
    assert derived.reportable is True

    # Bare declared flag with no re-evaluable payload -> NOT confirmed.
    declared = EvidenceCourt.adjudicate(
        target_url="http://t/",
        parameter="id",
        vuln_class="cmd_injection",
        verifier_result={"reproduced": True, "arithmetic_proof_confirmed": True},
    )
    assert declared.verdict is not CourtVerdict.CONFIRMED
    assert declared.reportable is False
