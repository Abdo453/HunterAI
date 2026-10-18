"""OT / ICS intelligence package — Core components (L1→L5)."""
from core.ot.schemas import OTAssetRecord, OTEvidenceLevel, OTProtocol, OTSecurityProfile
from core.ot.analyzer import DuplicateDetector, EvidenceReviewer, OTNormalizer
from core.ot.context import AdaptiveTestAdvisor, ContextEnricher

__all__ = [
    "OTAssetRecord",
    "OTEvidenceLevel",
    "OTProtocol",
    "OTSecurityProfile",
    "DuplicateDetector",
    "EvidenceReviewer",
    "OTNormalizer",
    "AdaptiveTestAdvisor",
    "ContextEnricher",
]
__version__ = "1.0.0-phase4"
