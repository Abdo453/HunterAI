"""Soft-404 Detector Package"""
from core.soft_404.schemas import (
    Soft404Record, Soft404Profile,
    Soft404EvidenceLevel,
)
from core.soft_404.analyzer import (
    Soft404Normalizer, DuplicateDetector, EvidenceReviewer,
)
from core.soft_404.context import ContextEnricher, AdaptiveTestAdvisor
from agents.soft_404_agent import Soft404Agent

__all__ = [
    "Soft404Record",
    "Soft404Profile",
    "Soft404EvidenceLevel",
    "Soft404Normalizer",
    "DuplicateDetector",
    "EvidenceReviewer",
    "ContextEnricher",
    "AdaptiveTestAdvisor",
    "Soft404Agent",
]
__version__ = "1.0.0-pilot"
