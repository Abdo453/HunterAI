"""
HunterAI Negative Knowledge Base
================================
Persistently records what was tested and proven clean, along with the forensic
rationale for why the vulnerability is absent.

Prevents redundant re-testing across subsequent scans:
"/api/search: Tested for SQLi on 2026-09-13. Result: Negative. Stable baseline (200 OK),
arithmetic payloads ((41+1)) produced zero differential changes."
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class NegativeProof:
    endpoint: str
    method: str
    vulnerability_family: str
    tested_at: float = field(default_factory=time.time)
    baseline_status: int = 200
    confidence_score: float = 0.95
    conclusive_rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "vulnerability_family": self.vulnerability_family,
            "tested_at": self.tested_at,
            "baseline_status": self.baseline_status,
            "confidence_score": round(self.confidence_score, 2),
            "conclusive_rationale": self.conclusive_rationale,
        }


class NegativeKnowledgeBase:
    """Stores verified negative outcomes to optimize future scan cycles"""

    def __init__(self):
        self._records: Dict[str, NegativeProof] = {}

    def _make_key(self, endpoint: str, method: str, vuln_family: str) -> str:
        return f"{method.upper()}:{endpoint}:{vuln_family.upper()}"

    def record_negative_proof(
        self,
        endpoint: str,
        method: str,
        vuln_family: str,
        baseline_status: int = 200,
        conclusive_rationale: str = "Tested with differential controls; zero execution detected."
    ) -> NegativeProof:
        key = self._make_key(endpoint, method, vuln_family)
        proof = NegativeProof(
            endpoint=endpoint,
            method=method.upper(),
            vulnerability_family=vuln_family.upper(),
            baseline_status=baseline_status,
            confidence_score=0.95,
            conclusive_rationale=conclusive_rationale
        )
        self._records[key] = proof
        return proof

    def is_known_negative(self, endpoint: str, method: str, vuln_family: str) -> Optional[NegativeProof]:
        key = self._make_key(endpoint, method, vuln_family)
        return self._records.get(key)

    def has_negative_proof(self, endpoint: str, method: str, vuln_family: str) -> bool:
        return self.is_known_negative(endpoint, method, vuln_family) is not None

    def count(self) -> int:
        return len(self._records)

