"""
HunterAI Replay Lab & Evidence Drift Engine
===========================================
Freezes findings into self-contained replay bundles:
data/replays/finding_<id>/
  - request.txt
  - response.txt
  - baseline.txt
  - metadata.json
  - replay.py (standalone 1-click execution)

Detects Evidence Drift:
- Original CONFIRMED vs Replay CONFIRMED -> Drift: NONE
- Original CONFIRMED vs Replay REJECTED -> Drift: DETECTED (Target patched or flaky)
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger("hunter_ai.replay_lab")


@dataclass
class ReplayDriftResult:
    finding_id: str
    original_verdict: str
    replay_verdict: str
    evidence_drift_detected: bool
    is_reproducible: bool
    drift_details: str = ""
    timestamp: float = field(default_factory=time.time)

    def format_summary(self) -> str:
        status_icon = "✅" if not self.evidence_drift_detected else "⚠️"
        return (
            f"{status_icon} [REPLAY LAB] Finding {self.finding_id}:\n"
            f"   • Original Verdict: {self.original_verdict}\n"
            f"   • Replay Verdict:   {self.replay_verdict}\n"
            f"   • Evidence Drift:   {'DETECTED' if self.evidence_drift_detected else 'NONE'}\n"
            f"   • Reproducible:     {'YES' if self.is_reproducible else 'NO'}"
        )


class ReplayLab:
    """Manages frozen bundles and standalone replay verification"""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or (Path(__file__).resolve().parent.parent.parent / "data" / "replays")
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def freeze_finding(
        self,
        finding_id: str,
        target_url: str,
        method: str,
        parameter: str,
        payload: str,
        raw_request: str,
        raw_response: str,
        raw_baseline: str,
        verdict: str = "CONFIRMED"
    ) -> Path:
        """Freezes a finding into a permanent, standalone replay bundle directory"""
        bundle_dir = self.base_dir / f"finding_{finding_id}"
        bundle_dir.mkdir(parents=True, exist_ok=True)

        (bundle_dir / "request.txt").write_text(raw_request, encoding="utf-8")
        (bundle_dir / "response.txt").write_text(raw_response, encoding="utf-8")
        (bundle_dir / "baseline.txt").write_text(raw_baseline, encoding="utf-8")

        meta = {
            "finding_id": finding_id,
            "target_url": target_url,
            "method": method,
            "parameter": parameter,
            "payload": payload,
            "original_verdict": verdict,
            "frozen_at": time.time()
        }
        with open(bundle_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        # Generate 1-click standalone replay script
        replay_py_content = f"""#!/usr/bin/env python3
# Standalone Replay Script for Finding {finding_id}
import urllib.request

url = "{target_url}"
print(f"Replaying probe against {{url}}...")
req = urllib.request.Request(url, headers={{"User-Agent": "HunterAI-Replay/2.0"}})
try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        print(f"Status: {{resp.status}}")
        if "{payload}" in body:
            print("CONFIRMED: Payload reflected successfully.")
        else:
            print("REJECTED: Payload not observed.")
except Exception as e:
    print(f"Error during replay: {{e}}")
"""
        (bundle_dir / "replay.py").write_text(replay_py_content, encoding="utf-8")
        return bundle_dir

    def evaluate_replay(
        self,
        finding_id: str,
        re_executed_response_body: str,
        expected_indicator: str
    ) -> ReplayDriftResult:
        """Evaluates replay execution against original verdict to detect evidence drift"""
        bundle_dir = self.base_dir / f"finding_{finding_id}"
        meta_file = bundle_dir / "metadata.json"
        original_verdict = "CONFIRMED"
        if meta_file.exists():
            with open(meta_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
                original_verdict = meta.get("original_verdict", "CONFIRMED")

        is_present = (expected_indicator in re_executed_response_body)
        replay_verdict = "CONFIRMED" if is_present else "REJECTED"
        drift = (original_verdict != replay_verdict)

        return ReplayDriftResult(
            finding_id=finding_id,
            original_verdict=original_verdict,
            replay_verdict=replay_verdict,
            evidence_drift_detected=drift,
            is_reproducible=(replay_verdict == "CONFIRMED"),
            drift_details="Target state matches original evidence." if not drift else "Target state changed: payload no longer reproduces."
        )
