"""
Evidence Processing Package
"""
from core.evidence.collector import EvidenceCollector
from core.evidence.correlator import EvidenceCorrelator
from core.evidence.validator import EvidenceValidator

__all__ = [
    "EvidenceCollector",
    "EvidenceCorrelator",
    "EvidenceValidator"
]
