"""
HunterAI Security Posture Timeline Tracker
==========================================
Tracks longitudinal security trends across recurring scans:
- New findings introduced
- Confirmed remediated findings
- Regressions (previously fixed findings that reappeared)
- Surface expansion rate
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class PostureTrend(str, Enum):
    IMPROVING = "IMPROVING (Risk Reduced)"
    DEGRADING = "DEGRADING (New Flaws or Regressions)"
    STABLE = "STABLE"


@dataclass
class AssessmentSnapshot:
    scan_id: str
    month_label: str
    timestamp: float
    open_findings: int
    fixed_findings: int
    regressions: int
    coverage_percentage: float


class PostureTimelineTracker:
    """Tracks continuous target health across temporal audit intervals"""

    def __init__(self, target: str):
        self.target = target
        self.snapshots: List[AssessmentSnapshot] = []

    def record_snapshot(
        self,
        scan_id: str,
        month_label: str,
        open_findings: int,
        fixed_findings: int,
        regressions: int,
        coverage_pct: float
    ) -> AssessmentSnapshot:
        snap = AssessmentSnapshot(
            scan_id=scan_id,
            month_label=month_label,
            timestamp=time.time(),
            open_findings=open_findings,
            fixed_findings=fixed_findings,
            regressions=regressions,
            coverage_percentage=coverage_pct
        )
        self.snapshots.append(snap)
        return snap

    def compute_trend(self) -> PostureTrend:
        if len(self.snapshots) < 2:
            return PostureTrend.STABLE

        prev = self.snapshots[-2]
        curr = self.snapshots[-1]

        if curr.regressions > 0 or curr.open_findings > prev.open_findings:
            return PostureTrend.DEGRADING
        elif curr.fixed_findings > prev.fixed_findings or curr.open_findings < prev.open_findings:
            return PostureTrend.IMPROVING
        return PostureTrend.STABLE

    def get_timeline_ascii(self) -> str:
        lines = [
            f"=== Security Posture Timeline: {self.target} ===",
            f"Overall Trend: {self.compute_trend().value}",
            "-" * 60,
            f"{'Month':<12} {'Open':<8} {'Fixed':<8} {'Regressions':<14} {'Coverage'}"
        ]
        for s in self.snapshots:
            lines.append(f"{s.month_label:<12} {s.open_findings:<8} {s.fixed_findings:<8} {s.regressions:<14} {s.coverage_percentage}%")
        return "\n".join(lines)
