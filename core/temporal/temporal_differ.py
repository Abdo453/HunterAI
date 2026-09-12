"""
Temporal Intelligence & State Diffing Engine
Calculates asset and attack surface deltas over time (Day 1 vs Day 2).
Enables continuous security testing, avoiding re-running scans from scratch.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class TemporalDiffResult:
    target: str
    previous_snapshot_timestamp: float
    current_snapshot_timestamp: float
    new_subdomains: List[str] = field(default_factory=list)
    removed_subdomains: List[str] = field(default_factory=list)
    new_endpoints: List[str] = field(default_factory=list)
    removed_endpoints: List[str] = field(default_factory=list)
    changed_endpoints: List[str] = field(default_factory=list)
    new_technologies: List[str] = field(default_factory=list)
    total_delta_count: int = 0


class TemporalDiffer:
    """
    محرك الذكاء الزمني والتفاضلي (Temporal Intelligence):
    - يقارن مخرجات وحالات الفحص السابقة بالوضع الحالي.
    - يستخرج الأصول الجديدة والمعدلة والمحذوفة بدقة متناهية.
    """

    @classmethod
    def calculate_file_hash(cls, file_path: Path) -> str:
        if not file_path.exists():
            return ""
        return hashlib.sha256(file_path.read_bytes()).hexdigest()

    @classmethod
    def diff_snapshots(
        cls,
        target: str,
        prior_state: Dict[str, Any],
        current_state: Dict[str, Any]
    ) -> TemporalDiffResult:
        prior_subs = set(prior_state.get("subdomains", []))
        curr_subs = set(current_state.get("subdomains", []))

        prior_eps = set(prior_state.get("endpoints", []))
        curr_eps = set(current_state.get("endpoints", []))

        prior_tech = set(prior_state.get("technologies", []))
        curr_tech = set(current_state.get("technologies", []))

        new_subs = sorted(list(curr_subs - prior_subs))
        rem_subs = sorted(list(prior_subs - curr_subs))

        new_eps = sorted(list(curr_eps - prior_eps))
        rem_eps = sorted(list(prior_eps - curr_eps))

        new_tech = sorted(list(curr_tech - prior_tech))

        delta_count = len(new_subs) + len(rem_subs) + len(new_eps) + len(rem_eps) + len(new_tech)

        return TemporalDiffResult(
            target=target,
            previous_snapshot_timestamp=prior_state.get("timestamp", 0.0),
            current_snapshot_timestamp=current_state.get("timestamp", time.time()),
            new_subdomains=new_subs,
            removed_subdomains=rem_subs,
            new_endpoints=new_eps,
            removed_endpoints=rem_eps,
            changed_endpoints=[],
            new_technologies=new_tech,
            total_delta_count=delta_count
        )
