"""Subjack Subdomain Takeover Package"""
from core.subjack.schemas import (
    SubdomainTakeoverRecord, TakeoverProfile,
    SubjackEvidenceLevel,
)
from core.subjack.analyzer import (
    SubjackNormalizer, DuplicateDetector, EvidenceReviewer,
)
from core.subjack.context import ContextEnricher, AdaptiveTestAdvisor

__all__ = [
    "SubdomainTakeoverRecord",
    "TakeoverProfile",
    "SubjackEvidenceLevel",
    "SubjackNormalizer",
    "DuplicateDetector",
    "EvidenceReviewer",
    "ContextEnricher",
    "AdaptiveTestAdvisor",
]
__version__ = "1.0.0-pilot"
