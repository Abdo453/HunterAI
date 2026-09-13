"""
HunterAI 'Unknown Unknowns' Epistemic Visibility Matrix
======================================================
Prevents false assumptions of safety by categorizing target attack surface into
5 explicit epistemic sectors:
- KNOWN_TESTED: Thoroughly probed with definitive evidence.
- KNOWN_UNTESTED: Discovered endpoints pending testing in queue.
- BLOCKED: Restricted by WAF challenge, auth boundary, or rate limiting.
- UNSUPPORTED: Technologies/protocols detected but lacking analyzer modules (e.g. gRPC, WebSockets).
- UNKNOWN_POTENTIAL: Dynamically referenced routes (JS chunks) whose reachability is unverified.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class SurfaceSector(str, Enum):
    KNOWN_TESTED = "KNOWN_TESTED"
    KNOWN_UNTESTED = "KNOWN_UNTESTED"
    BLOCKED = "BLOCKED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN_POTENTIAL = "UNKNOWN_POTENTIAL"


@dataclass
class SurfaceAssetRecord:
    endpoint: str
    method: str
    sector: SurfaceSector
    rationale: str


class UnknownsMatrix:
    """Manages surface epistemic breakdown and transparency scoring"""

    def __init__(self, target_host: str):
        self.target_host = target_host
        self._assets: Dict[str, SurfaceAssetRecord] = {}

    def record_asset(self, endpoint: str, method: str, sector: SurfaceSector, rationale: str):
        key = f"{method.upper()}:{endpoint}"
        self._assets[key] = SurfaceAssetRecord(endpoint, method.upper(), sector, rationale)

    def get_summary(self) -> Dict[str, Any]:
        sectors_count = {s.value: 0 for s in SurfaceSector}
        for a in self._assets.values():
            sectors_count[a.sector.value] += 1

        total = len(self._assets)
        tested = sectors_count[SurfaceSector.KNOWN_TESTED.value]
        visibility_pct = round((tested / total) * 100, 1) if total > 0 else 0.0

        return {
            "target": self.target_host,
            "total_surface_points": total,
            "visibility_percentage": visibility_pct,
            "sectors": sectors_count,
            "warning": (
                "Epistemic Warning: Attack surface contains unassessed or unsupported endpoints. "
                "Absence of findings in these sectors DOES NOT imply security."
                if (sectors_count[SurfaceSector.UNSUPPORTED.value] + sectors_count[SurfaceSector.UNKNOWN_POTENTIAL.value]) > 0
                else "All identified surface points evaluated."
            )
        }
