"""
Replay Engine
=============
Packages findings into reproducible test bundles:
finding/<id>/
  - request.txt
  - response.txt
  - baseline.txt
  - evidence.json
  - reproduction.json
Enables instant, isolated re-verification of findings without re-running entire scans.
"""
import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("hunter_ai.replay_engine")


@dataclass
class ReplayBundle:
    finding_id: str
    target_url: str
    method: str
    param_name: str
    payload: str
    raw_request: str
    raw_response: str
    raw_baseline: str
    evidence_data: Dict[str, Any]

    def save_to_dir(self, base_dir: str) -> str:
        f_dir = Path(base_dir) / f"finding_{self.finding_id}"
        f_dir.mkdir(parents=True, exist_ok=True)

        (f_dir / "request.txt").write_text(self.raw_request, encoding="utf-8")
        (f_dir / "response.txt").write_text(self.raw_response, encoding="utf-8")
        (f_dir / "baseline.txt").write_text(self.raw_baseline, encoding="utf-8")

        with open(f_dir / "evidence.json", "w", encoding="utf-8") as f:
            json.dump(self.evidence_data, f, indent=2)

        with open(f_dir / "reproduction.json", "w", encoding="utf-8") as f:
            json.dump({
                "target_url": self.target_url,
                "method": self.method,
                "param_name": self.param_name,
                "payload": self.payload
            }, f, indent=2)

        return str(f_dir)