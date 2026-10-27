"""Burp Suite Traffic Intelligence Package"""
from core.burp.schemas import BurpTrafficRecord, BurpEvidenceLevel
from core.burp.analyzer import BurpNormalizer, DuplicateDetector, EvidenceReviewer
from core.burp.context import ContextEnricher, AdaptiveAdvisor

__all__ = [
    "BurpTrafficRecord",
    "BurpEvidenceLevel",
    "BurpNormalizer",
    "DuplicateDetector",
    "EvidenceReviewer",
    "ContextEnricher",
    "AdaptiveAdvisor",
]
__version__ = "1.0.0-pilot"
