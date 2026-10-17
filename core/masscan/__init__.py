"""Masscan Port Discovery Package — Core components (L1→L5 data models + analyzers)"""
from core.masscan.schemas import (
    MasscanPortRecord, PortScanProfile,
    MasscanEvidenceLevel, PortConfidence,
)
from core.masscan.analyzer import MasscanNormalizer, DuplicateDetector, EvidenceReviewer
from core.masscan.context import (
    ContextEnricher, AdaptiveTestAdvisor,
    WELL_KNOWN_PORTS, HIGH_VALUE_PORTS,
)

__all__ = [
    "MasscanPortRecord",
    "PortScanProfile",
    "MasscanEvidenceLevel",
    "PortConfidence",
    "MasscanNormalizer",
    "DuplicateDetector",
    "EvidenceReviewer",
    "ContextEnricher",
    "AdaptiveTestAdvisor",
    "WELL_KNOWN_PORTS",
    "HIGH_VALUE_PORTS",
]
__version__ = "1.0.0-pilot"
