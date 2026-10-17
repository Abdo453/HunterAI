"""IoT device intelligence package — Core components (L1→L5)."""
from core.iot.schemas import IoTDeviceRecord, IoTEvidenceLevel, IoTProtocol, IoTSecurityProfile
from core.iot.analyzer import DuplicateDetector, EvidenceReviewer, IoTNormalizer
from core.iot.context import AdaptiveTestAdvisor, ContextEnricher

__all__ = [
    "IoTDeviceRecord",
    "IoTEvidenceLevel",
    "IoTProtocol",
    "IoTSecurityProfile",
    "DuplicateDetector",
    "EvidenceReviewer",
    "IoTNormalizer",
    "AdaptiveTestAdvisor",
    "ContextEnricher",
]
__version__ = "1.0.0-phase4"
