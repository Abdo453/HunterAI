"""
HunterAI Checkpoint & Mission Resume Manager
============================================
Provides fault-tolerant persistence for long-running security assessments:
- Periodic atomic snapshotting of mission state to JSON
- Seamless resumption after sudden shutdown, timeout, or network reboot
- Eliminates duplicated scanning of already-verified endpoints
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


@dataclass
class MissionCheckpoint:
    mission_id: str
    target: str
    started_at: float
    last_checkpoint_at: float
    completed_endpoints: Set[str] = field(default_factory=set)
    pending_queue: List[str] = field(default_factory=list)
    findings_count: int = 0
    coverage_percentage: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["completed_endpoints"] = sorted(list(self.completed_endpoints))
        return d


class CheckpointManager:
    """Atomic snapshot and recovery engine for HunterAI missions"""

    def __init__(self, checkpoints_dir: Optional[Path] = None):
        self.checkpoints_dir = checkpoints_dir or (Path(__file__).resolve().parent.parent.parent / "data" / "checkpoints")
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)

    def _file_path(self, mission_id: str) -> Path:
        return self.checkpoints_dir / f"checkpoint_{mission_id}.json"

    def save_checkpoint(
        self,
        mission_id: str,
        target: str,
        started_at: float,
        completed_endpoints: Set[str],
        pending_queue: List[str],
        findings_count: int = 0,
        coverage_pct: float = 0.0
    ) -> Path:
        """Atomically saves mission snapshot"""
        cp = MissionCheckpoint(
            mission_id=mission_id,
            target=target,
            started_at=started_at,
            last_checkpoint_at=time.time(),
            completed_endpoints=completed_endpoints,
            pending_queue=pending_queue,
            findings_count=findings_count,
            coverage_percentage=coverage_pct
        )
        file_path = self._file_path(mission_id)
        # Write to temporary file first, then atomic rename
        temp_file = file_path.with_suffix(".tmp")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(cp.to_dict(), f, indent=2)
        temp_file.replace(file_path)
        return file_path

    def load_checkpoint(self, mission_id: str) -> Optional[MissionCheckpoint]:
        """Loads mission state from previous checkpoint"""
        file_path = self._file_path(mission_id)
        if not file_path.exists():
            return None
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return MissionCheckpoint(
                    mission_id=data["mission_id"],
                    target=data["target"],
                    started_at=data["started_at"],
                    last_checkpoint_at=data["last_checkpoint_at"],
                    completed_endpoints=set(data.get("completed_endpoints", [])),
                    pending_queue=data.get("pending_queue", []),
                    findings_count=data.get("findings_count", 0),
                    coverage_percentage=data.get("coverage_percentage", 0.0)
                )
        except Exception:
            return None
