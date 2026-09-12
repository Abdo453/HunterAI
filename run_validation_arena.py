#!/usr/bin/env python3
"""
HunterAI - Validation Arena CLI Runner
======================================
Executes the standardized 8-lab benchmark suite, compares blind execution
findings against ground truth, prints quantitative scorecard, and outputs
VALIDATION_ARENA_SCORECARD.md.
"""
from __future__ import annotations

import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

from core.arena.arena_evaluator import ArenaEvaluator


def main():
    print("\n" + "=" * 78)
    print(" 🚀 Launching HunterAI Validation Arena (8 Ground-Truth Benchmark Labs)")
    print("=" * 78 + "\n")

    scorecard = ArenaEvaluator.run_all()
    print(scorecard.format_terminal_report())

    report_path = PROJECT_ROOT / "VALIDATION_ARENA_SCORECARD.md"
    scorecard.generate_markdown_report(report_path)
    print(f"\n 📄 Saved detailed benchmark report: {report_path.name}\n")

    # Assert rigorous performance thresholds
    passed = (scorecard.false_positives == 0 and scorecard.detection_rate_pct >= 85.0)
    if passed:
        print(" 🎉 VALIDATION ARENA CERTIFICATION: PASSED!")
        print(" 🚀 VERDICT: 0.0% FALSE POSITIVE RATE & FULL EVIDENCE REASONING CERTIFIED!\n")
    else:
        print(f" ⚠️ BENCHMARK FAILED TO MEET ZERO-FP OR RECALL STANDARDS.\n")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
