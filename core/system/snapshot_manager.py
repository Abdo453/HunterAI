"""
HunterAI Snapshots & Time Travel State Persistence (Phase 10)
=============================================================
Enables full point-in-time state capture and deterministic rollback:
  1. Captures full system state via snapshot() with SHA-256 integrity checksums
  2. Deterministic restoration via rollback(snapshot_id)
  3. Change audit trail logged to snapshot_history.json
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.snapshot_manager")


@dataclass
class SnapshotRecord:
    snapshot_id: str
    label: str
    timestamp: float
    checksum: str
    state_file: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SnapshotManager:
    """
    Manages persistent state snapshots, rollbacks, and historical audit logs.
    """
    def __init__(self, snapshots_dir: str | Path = "snapshots", history_file: Optional[str | Path] = None):
        self.snapshots_dir = Path(snapshots_dir)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = Path(history_file) if history_file else (self.snapshots_dir / "snapshot_history.json")
        self._history: List[Dict[str, Any]] = []
        self._load_history()

    def _load_history(self) -> None:
        if self.history_file.exists():
            try:
                self._history = json.loads(self.history_file.read_text(encoding="utf-8"))
            except Exception as e:
                logger.warning("Failed loading snapshot history: %s", e)
                self._history = []

    def _save_history(self) -> None:
        self.history_file.write_text(json.dumps(self._history, indent=2, default=str), encoding="utf-8")

    def _calculate_checksum(self, data_str: str) -> str:
        return hashlib.sha256(data_str.encode("utf-8")).hexdigest()

    def snapshot(self, state_data: Dict[str, Any], label: str = "checkpoint", metadata: Optional[Dict[str, Any]] = None) -> SnapshotRecord:
        """
        Captures full system state into a persistent snapshot with SHA-256 integrity verification.
        """
        snapshot_id = f"SNAP-{uuid.uuid4().hex[:8].upper()}"
        serialized = json.dumps(state_data, indent=2, sort_keys=True, default=str)
        checksum = self._calculate_checksum(serialized)
        
        target_file = self.snapshots_dir / f"{snapshot_id}.json"
        target_file.write_text(serialized, encoding="utf-8")

        record = SnapshotRecord(
            snapshot_id=snapshot_id,
            label=label,
            timestamp=time.time(),
            checksum=checksum,
            state_file=str(target_file),
            metadata=metadata or {},
        )

        history_entry = {
            "action": "CREATE_SNAPSHOT",
            "snapshot_id": snapshot_id,
            "label": label,
            "timestamp": record.timestamp,
            "checksum": checksum,
            "file": str(target_file),
            "metadata": record.metadata,
        }
        self._history.append(history_entry)
        self._save_history()

        logger.info("Snapshot captured: id=%s label='%s' file=%s", snapshot_id, label, target_file)
        return record

    def rollback(self, snapshot_id: str) -> Dict[str, Any]:
        """
        Restores state from a snapshot after verifying checksum integrity.
        """
        target_file = self.snapshots_dir / f"{snapshot_id}.json"
        if not target_file.exists():
            raise FileNotFoundError(f"Snapshot not found: {snapshot_id}")

        content = target_file.read_text(encoding="utf-8")
        current_checksum = self._calculate_checksum(content)

        # Verify against history
        matching = [h for h in self._history if h.get("snapshot_id") == snapshot_id and h.get("action") == "CREATE_SNAPSHOT"]
        if matching:
            expected = matching[0]["checksum"]
            if current_checksum != expected:
                raise ValueError(f"Integrity check failed for snapshot {snapshot_id}: expected {expected}, got {current_checksum}")

        state = json.loads(content)

        rollback_entry = {
            "action": "ROLLBACK",
            "snapshot_id": snapshot_id,
            "timestamp": time.time(),
            "status": "RESTORED",
        }
        self._history.append(rollback_entry)
        self._save_history()

        logger.info("Rollback executed: restored state from snapshot %s", snapshot_id)
        return state

    def list_snapshots(self) -> List[Dict[str, Any]]:
        return [h for h in self._history if h.get("action") == "CREATE_SNAPSHOT"]

    def get_history(self) -> List[Dict[str, Any]]:
        return list(self._history)
