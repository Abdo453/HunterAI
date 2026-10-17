"""Wireless / WiFi intelligence package — Core components (L1→L5)."""
from core.wireless.schemas import (
    EncryptionStrength,
    WiFiNetworkRecord,
    WiFiSecurityProfile,
    WirelessEvidenceLevel,
)
from core.wireless.analyzer import DuplicateDetector, EvidenceReviewer, WirelessNormalizer
from core.wireless.context import AdaptiveTestAdvisor, ContextEnricher

__all__ = [
    "EncryptionStrength",
    "WiFiNetworkRecord",
    "WiFiSecurityProfile",
    "WirelessEvidenceLevel",
    "DuplicateDetector",
    "EvidenceReviewer",
    "WirelessNormalizer",
    "AdaptiveTestAdvisor",
    "ContextEnricher",
]
__version__ = "1.0.0-phase4"
