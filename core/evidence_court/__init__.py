"""HunterAI Adversarial Evidence Court Package"""
from core.evidence_court.tribunal import (
    EvidenceCourt, CourtCase, CourtEvidence, CourtArgument, Verdict, evidence_court,
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
