"""OSINT Identity Subsystem — Package init"""
from core.osint.schemas import (
    IdentityEvidenceRecord,
    IdentityCluster,
    OSINTVector,
    EvidenceLevel,
    ConfidenceLabel,
    DetectionMethod,
)
from core.osint.platform_registry import (
    PlatformEntry,
    GENERIC_USERNAMES,
    PLATFORMS,
    is_generic_username,
    canonicalize_platform,
    platform_entry,
    all_platforms,
    extract_urls,
)
from core.osint.evidence_normalizer import EvidenceNormalizer
from core.osint.fp_guards import FPGuards
from core.osint.confidence_model import ConfidenceModel
from core.osint.identity_correlation import IdentityCorrelationEngine
from core.osint.identity_bridge import OSINTIdentityBridge

__all__ = [
    "IdentityEvidenceRecord",
    "IdentityCluster",
    "OSINTVector",
    "EvidenceLevel",
    "ConfidenceLabel",
    "DetectionMethod",
    "PlatformEntry",
    "GENERIC_USERNAMES",
    "PLATFORMS",
    "is_generic_username",
    "canonicalize_platform",
    "platform_entry",
    "all_platforms",
    "extract_urls",
    "EvidenceNormalizer",
    "FPGuards",
    "ConfidenceModel",
    "IdentityCorrelationEngine",
    "OSINTIdentityBridge",
]

__version__ = "1.0.0"