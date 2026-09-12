"""
HunterAI Real-World Benchmark Engine
====================================
Executes standardized benchmark test runs against industry-standard targets:
- OWASP Juice Shop
- DVWA (Damn Vulnerable Web App)
- WebGoat
- PortSwigger Web Security Academy

Evaluates:
- Total Cases
- Detected (True Positives)
- Missed (False Negatives)
- False Positives
- Precision & Recall
- Total Requests Dispatched
- Runtime
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class BenchmarkCase:
    case_id: str
    target_app: str
    vulnerability_type: str
    endpoint: str
    parameter: str
    expected_vulnerable: bool
    cwe: str = ""
    description: str = ""


@dataclass
class BenchmarkRunResult:
    run_id: str
    target_app: str
    total_cases: int
    detected: int
    missed: int
    false_positives: int
    precision_pct: float
    recall_pct: float
    total_requests: int
    runtime_sec: float
    timestamp: float = field(default_factory=time.time)

    def format_terminal_summary(self) -> str:
        sep = "═" * 54
        sub = "─" * 54
        return f"""{sep}
 🎯 Benchmark Run #{self.run_id} ({self.target_app})
{sep}
 Cases:              {self.total_cases:>6}
 Detected:           {self.detected:>6}
 Missed:             {self.missed:>6}
 False Positives:    {self.false_positives:>6}
{sub}
 Precision:          {self.precision_pct:>6.1f}%
 Recall:             {self.recall_pct:>6.1f}%
{sub}
 Requests:           {self.total_requests:>6}
 Runtime:            {self.runtime_sec:>6.2f}s
{sep}"""


class BenchmarkEngine:
    """Manages benchmark catalogs, test execution, and run reporting"""

    def __init__(self, benchmark_dir: Optional[Path] = None):
        self.benchmark_dir = benchmark_dir or (Path(__file__).resolve().parent)
        self.ground_truth_dir = self.benchmark_dir / "ground_truth"
        self.runs_dir = self.benchmark_dir / "runs"
        self.reports_dir = self.benchmark_dir / "reports"
        self.ground_truth_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def load_ground_truth(self, category: str) -> List[BenchmarkCase]:
        file_path = self.ground_truth_dir / f"{category}.json"
        if not file_path.exists():
            return []
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return [BenchmarkCase(**d) for d in data]

    def record_run(self, result: BenchmarkRunResult) -> None:
        run_file = self.runs_dir / f"run_{result.run_id}.json"
        with open(run_file, "w", encoding="utf-8") as f:
            json.dump(asdict(result), f, indent=2)

        report_file = self.reports_dir / f"report_{result.run_id}.md"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"# Benchmark Run #{result.run_id} - {result.target_app}\n\n")
            f.write(f"- **Cases:** {result.total_cases}\n")
            f.write(f"- **Detected:** {result.detected}\n")
            f.write(f"- **Missed:** {result.missed}\n")
            f.write(f"- **False Positives:** {result.false_positives}\n")
            f.write(f"- **Precision:** {result.precision_pct:.1f}%\n")
            f.write(f"- **Recall:** {result.recall_pct:.1f}%\n")
            f.write(f"- **Requests:** {result.total_requests}\n")
            f.write(f"- **Runtime:** {result.runtime_sec:.2f}s\n")
