"""
HunterAI Standardized Analysis Result Schema
Guarantees consistent output for every Agent:
- status: success / failure / blocked
- analysis: technical summary
- confidence: 0.0 to 1.0 (High: >=0.90, Med: 0.70-0.89, Low: <0.70)
- model: model identifier used (e.g. "local/qwen", "cloud/reasoning")
- reasoning_mode: "fast", "deep", "critic_validated"
- evidence: list of verifiable observations
- critic_verdict: passed / challenged / rejected
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class HunterAIResult:
    task_id: str
    status: str  # "success", "blocked", "needs_approval", "failed"
    analysis: str
    confidence: float  # 0.0 to 1.0
    model: str  # "local/qwen", "cloud/reasoning", "deterministic"
    reasoning_mode: str = "deep"
    evidence: List[str] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    critic_verdict: str = "passed"
    critic_notes: str = ""
    latency_ms: float = 0.0
    fallback_used: bool = False
    timestamp: float = field(default_factory=time.time)

    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.90

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "analysis": self.analysis,
            "confidence": round(self.confidence, 3),
            "confidence_tier": "High" if self.confidence >= 0.90 else "Medium" if self.confidence >= 0.70 else "Low",
            "model": self.model,
            "reasoning_mode": self.reasoning_mode,
            "evidence": self.evidence,
            "critic_verdict": self.critic_verdict,
            "critic_notes": self.critic_notes,
            "latency_ms": self.latency_ms,
            "fallback_used": self.fallback_used
        }
