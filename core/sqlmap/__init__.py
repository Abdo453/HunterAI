"""SQLmap Result Interpreter Package"""
from core.sqlmap.schemas import SQLmapFindingRecord, SQLmapEvidenceLevel
from core.sqlmap.analyzer import SQLmapNormalizer, DuplicateDetector, EvidenceReviewer
from core.sqlmap.context import ContextEnricher, AdaptiveAdvisor

__all__ = [
    "SQLmapFindingRecord",
    "SQLmapEvidenceLevel",
    "SQLmapNormalizer",
    "DuplicateDetector",
    "EvidenceReviewer",
    "ContextEnricher",
    "AdaptiveAdvisor",
]
__version__ = "1.0.0-pilot"
