"""ffuf Response Intelligence Package — Core components (L1→L5 data models + analyzers)"""
from core.ffuf.schemas import (
    FfufResultRecord, ResponseCluster,
    FfufEvidenceLevel, ResponseCategory,
)
from core.ffuf.analyzer import FfufNormalizer, DuplicateDetector, Soft404Detector, EvidenceReviewer
from core.ffuf.context import ContextEnricher, AdaptiveWordlistAdvisor

__all__ = [
    "FfufResultRecord",
    "ResponseCluster",
    "FfufEvidenceLevel",
    "ResponseCategory",
    "FfufNormalizer",
    "DuplicateDetector",
    "Soft404Detector",
    "EvidenceReviewer",
    "ContextEnricher",
    "AdaptiveWordlistAdvisor",
]
__version__ = "1.0.0-pilot"
