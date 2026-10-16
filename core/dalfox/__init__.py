"""Dalfox XSS Context Analyzer Package"""
from core.dalfox.schemas import DalfoxFindingRecord, DalfoxEvidenceLevel
from core.dalfox.analyzer import DalfoxNormalizer, DuplicateDetector, EvidenceReviewer
from core.dalfox.context import ContextEnricher, AdaptiveAdvisor

__all__ = [
    "DalfoxFindingRecord",
    "DalfoxEvidenceLevel",
    "DalfoxNormalizer",
    "DuplicateDetector",
    "EvidenceReviewer",
    "ContextEnricher",
    "AdaptiveAdvisor",
]
__version__ = "1.0.0-pilot"
