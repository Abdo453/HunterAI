"""WhatWeb Technology Fingerprinting package — Core components (L1→L5)."""
from core.whatweb.schemas import (
    WhatWebAssetRecord,
    WhatWebEvidenceLevel,
    WhatWebPluginRecord,
    TechFingerprintProfile,
)
from core.whatweb.analyzer import DuplicateDetector, EvidenceReviewer, WhatWebNormalizer
from core.whatweb.context import AdaptiveTestAdvisor, ContextEnricher

__all__ = [
    "WhatWebAssetRecord",
    "WhatWebEvidenceLevel",
    "WhatWebPluginRecord",
    "TechFingerprintProfile",
    "DuplicateDetector",
    "EvidenceReviewer",
    "WhatWebNormalizer",
    "AdaptiveTestAdvisor",
    "ContextEnricher",
]
__version__ = "1.0.0-pilot"
