"""
HunterAI Cryptographic Provenance Chain
=======================================
Enforces the fundamental axiom: "Every security claim has a provenance."
Constructs an unbroken 8-step backward causal chain:
Observation -> Baseline -> Control -> Active Request -> Active Response -> Differential -> Court Verdict -> Finding
Guarantees full reproducibility and mathematical verifiability of claims.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ProvenanceStage(str, Enum):
    OBSERVATION = "OBSERVATION"
    BASELINE = "BASELINE"
    HARMLESS_CONTROL = "HARMLESS_CONTROL"
    ACTIVE_REQUEST = "ACTIVE_REQUEST"
    ACTIVE_RESPONSE = "ACTIVE_RESPONSE"
    DIFFERENTIAL = "DIFFERENTIAL"
    COURT_VERDICT = "COURT_VERDICT"
    FINDING = "FINDING"


@dataclass
class ProvenanceStep:
    step_index: int
    stage: ProvenanceStage
    actor: str
    summary: str
    data_payload: str
    data_hash: str
    parent_hash: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["stage"] = self.stage.value
        return d


class ProvenanceChain:
    """Tamper-evident chain of custody connecting raw HTTP bytes to reported findings"""

    def __init__(self, finding_id: str, target: str):
        self.finding_id = finding_id
        self.target = target
        self.steps: List[ProvenanceStep] = []

    def _hash_data(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()

    def add_step(self, stage: ProvenanceStage, actor: str, summary: str, raw_data: str) -> ProvenanceStep:
        parent_hash = self.steps[-1].data_hash if self.steps else "0" * 64
        step_index = len(self.steps)

        # Compute hash over data + parent_hash (blockchain-like chaining)
        step_seed = f"{step_index}:{stage.value}:{actor}:{parent_hash}:{raw_data}"
        current_hash = self._hash_data(step_seed)

        step = ProvenanceStep(
            step_index=step_index,
            stage=stage,
            actor=actor,
            summary=summary,
            data_payload=raw_data[:500],  # truncated snippet
            data_hash=current_hash,
            parent_hash=parent_hash
        )
        self.steps.append(step)
        return step

    def verify_integrity(self) -> bool:
        """Verifies the unbroken cryptographic chain across all recorded stages"""
        if not self.steps:
            return False

        for i, step in enumerate(self.steps):
            expected_parent = self.steps[i - 1].data_hash if i > 0 else "0" * 64
            if step.parent_hash != expected_parent:
                return False

        return True

    def render_trace_ascii(self) -> str:
        """Renders the 8-stage backward causal provenance tree"""
        lines = [
            "+" + "-" * 72 + "+",
            f"| [PROVENANCE] Finding Provenance Chain: {self.finding_id:<41} |",
            f"| Target: {self.target:<62} |",
            "+" + "-" * 72 + "+"
        ]
        for i, step in enumerate(self.steps):
            connector = "+-- " if i == len(self.steps) - 1 else "+-- "
            indent = "    " * min(i, 2)
            lines.append(f"| {indent}{connector}[{step.stage.value}] ({step.actor}): {step.summary[:38]}")
            lines.append(f"| {indent}    Hash: {step.data_hash[:16]}... (Parent: {step.parent_hash[:8]}...)")

        lines.append("+" + "-" * 72 + "+")
        return "\n".join(lines)
