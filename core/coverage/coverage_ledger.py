"""
HunterAI Coverage Map & Negative Space Ledger
==============================================
Provides transparent tracking of what was tested and what was NOT tested.
Eliminates false assurances of security by logging unprobed attack surface
along with explicit causal reasons:
- PROBED_AND_VERIFIED
- PROBED_AND_SAFE
- SKIPPED_OUT_OF_SCOPE
- SKIPPED_AUTH_MISSING
- SKIPPED_RATE_LIMITED
- SKIPPED_WAF_BLOCKED
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class CoverageStatus(str, Enum):
    PROBED_AND_VERIFIED = "PROBED_AND_VERIFIED"
    PROBED_AND_SAFE = "PROBED_AND_SAFE"
    SKIPPED_OUT_OF_SCOPE = "SKIPPED_OUT_OF_SCOPE"
    SKIPPED_AUTH_MISSING = "SKIPPED_AUTH_MISSING"
    SKIPPED_RATE_LIMITED = "SKIPPED_RATE_LIMITED"
    SKIPPED_WAF_BLOCKED = "SKIPPED_WAF_BLOCKED"
    SKIPPED_USER_RESTRICTION = "SKIPPED_USER_RESTRICTION"


@dataclass
class SurfaceItem:
    target: str
    endpoint: str
    method: str
    parameter: Optional[str] = None
    status: CoverageStatus = CoverageStatus.PROBED_AND_SAFE
    reason: str = ""
    probe_count: int = 0
    timestamp: float = field(default_factory=time.time)


class CoverageLedger:
    """Tracks coverage metrics and negative space (untested surface)"""

    def __init__(self, target_scope: str):
        self.target_scope = target_scope
        self.items: Dict[str, SurfaceItem] = {}

    def _make_key(self, endpoint: str, method: str, parameter: Optional[str] = None) -> str:
        param_part = f"?{parameter}" if parameter else ""
        return f"{method.upper()}:{endpoint}{param_part}"

    def record_probed(self, endpoint: str, method: str, parameter: Optional[str] = None, verified_finding: bool = False) -> SurfaceItem:
        key = self._make_key(endpoint, method, parameter)
        status = CoverageStatus.PROBED_AND_VERIFIED if verified_finding else CoverageStatus.PROBED_AND_SAFE
        item = SurfaceItem(
            target=self.target_scope,
            endpoint=endpoint,
            method=method.upper(),
            parameter=parameter,
            status=status,
            reason="Tested with differential verification probes.",
            probe_count=self.items.get(key, SurfaceItem(self.target_scope, endpoint, method)).probe_count + 1
        )
        self.items[key] = item
        return item

    def record_skipped(self, endpoint: str, method: str, status: CoverageStatus, reason: str, parameter: Optional[str] = None) -> SurfaceItem:
        key = self._make_key(endpoint, method, parameter)
        item = SurfaceItem(
            target=self.target_scope,
            endpoint=endpoint,
            method=method.upper(),
            parameter=parameter,
            status=status,
            reason=reason,
            probe_count=0
        )
        self.items[key] = item
        return item

    def get_summary(self) -> Dict[str, Any]:
        total = len(self.items)
        probed_verified = sum(1 for i in self.items.values() if i.status == CoverageStatus.PROBED_AND_VERIFIED)
        probed_safe = sum(1 for i in self.items.values() if i.status == CoverageStatus.PROBED_AND_SAFE)
        skipped = total - (probed_verified + probed_safe)

        coverage_pct = round(((probed_verified + probed_safe) / max(1, total)) * 100.0, 1)

        skipped_breakdown = {}
        for i in self.items.values():
            if "SKIPPED" in i.status.value:
                skipped_breakdown[i.status.value] = skipped_breakdown.get(i.status.value, 0) + 1

        return {
            "target_scope": self.target_scope,
            "total_surface_items": total,
            "probed_items": probed_verified + probed_safe,
            "probed_and_verified": probed_verified,
            "probed_and_safe": probed_safe,
            "skipped_items": skipped,
            "coverage_percentage": coverage_pct,
            "skipped_breakdown": skipped_breakdown
        }

    def format_terminal_coverage_map(self) -> str:
        summary = self.get_summary()
        sep = "═" * 68
        sub = "─" * 68
        lines = [
            sep,
            f" 🗺️ HunterAI Attack Surface Coverage Map — {self.target_scope}",
            sep,
            f" Total Identified Surface:  {summary['total_surface_items']:>6} endpoints & parameters",
            f" Fully Probed & Verified:   {summary['probed_items']:>6} ({summary['coverage_percentage']}%)",
            f" Untested / Negative Space: {summary['skipped_items']:>6}",
            sub,
            " Negative Space Breakdown (What was NOT tested and why):"
        ]
        if summary["skipped_breakdown"]:
            for k, count in summary["skipped_breakdown"].items():
                lines.append(f"   • {k:<28} : {count:>4} items")
        else:
            lines.append("   • All discovered in-scope endpoints were fully probed.")
        lines.append(sep)
        return "\n".join(lines)
