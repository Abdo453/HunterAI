"""HunterAI Adversarial Evidence Court (tribunal) — standalone package.

The five-role adversarial tribunal (Finder → Advocate → Prosecutor → Verifier →
Justice) implemented in :mod:`core.adversarial_court.tribunal`.

This package was previously named ``core/evidence_court/``, which shadowed the
authoritative ``core/evidence_court.py`` module and broke every
``from core.evidence_court import EvidenceCourt`` import in the project. It was
renamed to ``core.adversarial_court`` so the single authoritative Evidence Court
(``core.evidence_court``) and this independent tribunal can coexist.

Note: this tribunal's ``EvidenceCourt`` is a *different* class from the
authoritative :class:`core.evidence_court.EvidenceCourt`. Prefer the
authoritative court for proof adjudication; use this package only when a
five-role narrative tribunal is explicitly required.
"""
from core.adversarial_court.tribunal import (
    EvidenceCourt,
    CourtCase,
    CourtEvidence,
    CourtArgument,
    Verdict,
    evidence_court,
)

__all__ = [
    "EvidenceCourt",
    "CourtCase",
    "CourtEvidence",
    "CourtArgument",
    "Verdict",
    "evidence_court",
]
__version__ = "1.0.0"
