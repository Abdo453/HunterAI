"""SSLScan TLS Cipher & Protocol Intelligence package — Core components (L1→L5)."""
from core.sslscan.schemas import (
    SSLCertRecord,
    SSLCipherRecord,
    SSLAssetRecord,
    SSLEvidenceLevel,
    SSLProtocolRecord,
    TLSConfigProfile,
)
from core.sslscan.analyzer import DuplicateDetector, EvidenceReviewer, SSLScanNormalizer
from core.sslscan.context import AdaptiveTestAdvisor, ContextEnricher

__all__ = [
    "SSLCertRecord",
    "SSLCipherRecord",
    "SSLAssetRecord",
    "SSLEvidenceLevel",
    "SSLProtocolRecord",
    "TLSConfigProfile",
    "DuplicateDetector",
    "EvidenceReviewer",
    "SSLScanNormalizer",
    "AdaptiveTestAdvisor",
    "ContextEnricher",
]
__version__ = "1.0.0-pilot"
