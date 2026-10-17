"""Network data model package — Host/Service/ProtocolTrace/NetworkFinding + HostGraph."""
from core.network_model.schemas import (
    HostRecord,
    NetworkFinding,
    NetworkEvidenceLevel,
    ProtocolTrace,
    ServiceConfidence,
    ServiceRecord,
    ServiceState,
)
from core.network_model.graph import HostGraph

__all__ = [
    "HostRecord",
    "ServiceRecord",
    "ProtocolTrace",
    "NetworkFinding",
    "NetworkEvidenceLevel",
    "ServiceConfidence",
    "ServiceState",
    "HostGraph",
]
__version__ = "0.1.0-phase0"
