"""NetExec (nxc) package — Core components (L1→L5)."""
from core.netexec.schemas import (
    NetExecEvidenceLevel,
    NetExecHostRecord,
    NetExecProfile,
)
from core.netexec.analyzer import (
    DuplicateDetector,
    EvidenceReviewer,
    NetExecNormalizer,
)
from core.netexec.context import AdaptiveTestAdvisor, ContextEnricher

__all__ = [
    "NetExecEvidenceLevel",
    "NetExecHostRecord",
    "NetExecProfile",
    "DuplicateDetector",
    "EvidenceReviewer",
    "NetExecNormalizer",
    "AdaptiveTestAdvisor",
    "ContextEnricher",
]
__version__ = "1.0.0-pilot"
