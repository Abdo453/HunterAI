"""
HunterAI Failure Memory & Anti-Loop Prevention Engine
====================================================
Prevents the agent and AI models from repeating identical failed actions,
fuzzing attempts, or rejected hypotheses in a futile loop.

Rule: "do_not_repeat_without_new_evidence"
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.failure_memory")


@dataclass
class FailureRecord:
    action: str
    target: str
    result: str
    reason: str
    timestamp: float = field(default_factory=lambda: time.time())
    evidence_fingerprint: str = ""
    retry_policy: str = "do_not_repeat_without_new_evidence"
    attempts_count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FailureMemory:
    """
    Tracks failed tool executions, HTTP probes, and rejected AI hypotheses.
    Blocks re-execution unless new differential evidence is introduced.
    """

    def __init__(self, storage_file: Optional[str] = None):
        self.storage_file = Path(storage_file) if storage_file else None
        if self.storage_file:
            self.storage_file.parent.mkdir(parents=True, exist_ok=True)

        self._failures: Dict[str, FailureRecord] = {}
        self._rejected_hypotheses: Set[str] = set()
        self._load()

    def _hash_key(self, action: str, target: str) -> str:
        raw = f"{action.strip().lower()}::{target.strip().lower()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _load(self) -> None:
        if self.storage_file and self.storage_file.exists():
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k, v in data.get("failures", {}).items():
                        self._failures[k] = FailureRecord(**v)
                    self._rejected_hypotheses = set(data.get("rejected_hypotheses", []))
            except Exception as e:
                logger.debug(f"Failed to load failure memory: {e}")

    def _save(self) -> None:
        if not self.storage_file:
            return
        try:
            payload = {
                "failures": {k: v.to_dict() for k, v in self._failures.items()},
                "rejected_hypotheses": list(self._rejected_hypotheses),
            }
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to save failure memory: {e}")

    def record_failure(
        self,
        action: str,
        target: str,
        reason: str,
        evidence_fingerprint: str = "",
    ) -> None:
        """Register a failure event for an action/target pair"""
        k = self._hash_key(action, target)
        if k in self._failures:
            rec = self._failures[k]
            rec.attempts_count += 1
            rec.reason = reason
            rec.timestamp = time.time()
            rec.evidence_fingerprint = evidence_fingerprint
        else:
            self._failures[k] = FailureRecord(
                action=action,
                target=target,
                result="failed",
                reason=reason,
                evidence_fingerprint=evidence_fingerprint,
                attempts_count=1,
            )
        self._save()
        logger.info(f"FAILURE MEMORY: Recorded failed action '{action}' on '{target}' (Attempts: {self._failures[k].attempts_count})")

    def should_execute(
        self,
        action: str,
        target: str,
        current_evidence_fingerprint: str = "",
    ) -> Tuple[bool, Optional[str]]:
        """
        Determines whether the action should proceed or be suppressed.
        Returns (should_run, reason_if_blocked).
        """
        k = self._hash_key(action, target)
        if k not in self._failures:
            return True, None

        rec = self._failures[k]
        # If no new evidence has been gathered since last failure, block repeat
        if rec.evidence_fingerprint and current_evidence_fingerprint:
            if rec.evidence_fingerprint == current_evidence_fingerprint:
                return False, f"Anti-Loop: Action '{action}' on '{target}' failed previously ({rec.reason}). Suppressed until new evidence emerges."
        elif rec.attempts_count >= 2:
            return False, f"Anti-Loop: Action '{action}' failed {rec.attempts_count} times on '{target}' ({rec.reason})."

        return True, None

    def record_rejected_hypothesis(self, hypothesis_key: str, reason: str = "") -> None:
        """Records a hypothesis that was deterministically evaluated and rejected"""
        clean_key = hypothesis_key.strip().lower()
        self._rejected_hypotheses.add(clean_key)
        self._save()
        logger.info(f"FAILURE MEMORY: Registered rejected hypothesis: '{clean_key}' ({reason})")

    def is_hypothesis_rejected(self, hypothesis_key: str) -> bool:
        return hypothesis_key.strip().lower() in self._rejected_hypotheses
