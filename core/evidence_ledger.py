"""
Evidence Ledger
===============
Cryptographically chained audit trail linking:
Observation -> Evidence -> Hypothesis -> Test -> Result -> Verifier -> Court Decision
Provides complete traceability for answering "Why was this marked Critical?"
"""
import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class LedgerEntry:
    entry_id: str = field(default_factory=lambda: f"ledg_{uuid.uuid4().hex[:8]}")
    step_type: str = "observation"  # observation, hypothesis, test, verifier, court_decision
    summary: str = ""
    payload_hash: str = ""
    evidence_ref: str = ""
    prev_entry_hash: str = ""
    entry_hash: str = ""
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)


class EvidenceLedger:
    """Immutable event ledger tracking the full lineage of every security finding"""

    def __init__(self):
        self.entries: List[LedgerEntry] = []
        self._last_hash = "0" * 64

    def record_step(
        self,
        step_type: str,
        summary: str,
        details: Dict[str, Any],
        evidence_ref: str = ""
    ) -> LedgerEntry:
        det_str = json.dumps(details, sort_keys=True, default=str)
        p_hash = hashlib.sha256(det_str.encode("utf-8")).hexdigest()

        # Chain hash
        combined = f"{self._last_hash}:{step_type}:{p_hash}:{time.time()}"
        entry_h = hashlib.sha256(combined.encode("utf-8")).hexdigest()

        entry = LedgerEntry(
            step_type=step_type,
            summary=summary,
            payload_hash=p_hash,
            evidence_ref=evidence_ref,
            prev_entry_hash=self._last_hash,
            entry_hash=entry_h,
            details=details
        )
        self.entries.append(entry)
        self._last_hash = entry_h
        return entry

    def get_lineage(self, entry_id: str) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self.entries]

    def to_dict(self) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self.entries]