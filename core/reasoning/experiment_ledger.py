"""
HunterAI V27.0 - Tamper-Evident Experiment Ledger
=================================================
Append-only, cryptographically chained experiment record ledger.
Preserves the complete forensic lineage of every security experiment:
  - Contract specification & hash
  - Physical execution artifacts & hash
  - Triad states: B, C, E1, E2
  - Formal Invariant outcome & causal strength
  - Chained cryptographic block hashes ensuring provenance integrity
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.experiment_ledger")


@dataclass
class ExperimentRecord:
    experiment_id: str
    hypothesis_id: str
    parent_experiment_id: Optional[str] = None
    contract_hash: str = ""
    execution_hash: str = ""
    evidence_hash: str = ""
    parent_hash: str = "0" * 64
    block_hash: str = ""

    source_transaction: Dict[str, Any] = field(default_factory=dict)
    actor_context: str = "ANONYMOUS"
    target_state: str = "UNKNOWN"

    baseline_b: Dict[str, Any] = field(default_factory=dict)
    control_c: Dict[str, Any] = field(default_factory=dict)
    experiment_e1: Dict[str, Any] = field(default_factory=dict)
    experiment_e2: Dict[str, Any] = field(default_factory=dict)

    observations: List[str] = field(default_factory=list)
    invariant_result: Dict[str, Any] = field(default_factory=dict)
    causal_strength: float = 0.0
    negative_evidence: List[str] = field(default_factory=list)
    information_gain: float = 0.0
    execution_provenance: List[Dict[str, Any]] = field(default_factory=list)
    replay_recipe: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def compute_block_hash(self) -> str:
        """Calculates immutable SHA-256 block hash linking parent, contract, execution and evidence."""
        payload = (
            f"{self.experiment_id}:{self.hypothesis_id}:{self.contract_hash}:"
            f"{self.execution_hash}:{self.evidence_hash}:{self.parent_hash}:{self.causal_strength}:{self.timestamp}"
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TamperEvidentExperimentLedger:
    """
    Append-only cryptographic ledger maintaining verified experiment records.
    Provides verifiable forensic integrity check across the entire investigation session.
    """

    def __init__(self):
        self._records: List[ExperimentRecord] = []

    def append(self, record: ExperimentRecord) -> ExperimentRecord:
        """
        Chains and records a new ExperimentRecord.
        Computes block_hash ensuring strict linkage with previous record.
        """
        if self._records:
            record.parent_hash = self._records[-1].block_hash
        else:
            record.parent_hash = "0" * 64

        # Compute contract hash if not populated
        if not record.contract_hash:
            c_data = f"{record.experiment_id}:{record.hypothesis_id}:{record.actor_context}"
            record.contract_hash = hashlib.sha256(c_data.encode("utf-8")).hexdigest()

        # Compute evidence hash if not populated
        if not record.evidence_hash:
            ev_data = json.dumps(record.invariant_result, sort_keys=True)
            record.evidence_hash = hashlib.sha256(ev_data.encode("utf-8")).hexdigest()

        record.block_hash = record.compute_block_hash()
        self._records.append(record)

        logger.info(
            f"[EXPERIMENT LEDGER] Appended record '{record.experiment_id}' "
            f"[Block #{len(self._records)}: {record.block_hash[:12]}...]"
        )
        return record

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Cryptographically validates the entire ledger from genesis to tip.
        Returns (True, None) if valid, or (False, error_details) if corrupted/tampered.
        """
        prev_hash = "0" * 64
        for idx, rec in enumerate(self._records):
            # 1. Verify parent hash linkage
            if rec.parent_hash != prev_hash:
                return False, f"Broken parent hash link at block #{idx+1} ({rec.experiment_id})"

            # 2. Verify self block hash
            expected_hash = rec.compute_block_hash()
            if rec.block_hash != expected_hash:
                return False, f"Hash mismatch at block #{idx+1} ({rec.experiment_id})"

            prev_hash = rec.block_hash

        return True, None

    def __len__(self) -> int:
        return len(self._records)

    def export_ledger(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._records]
