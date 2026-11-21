#!/usr/bin/env python3
"""vuln_scorer.py — deterministic finding severity scorer (triage rubric).

From Likhithsai2580/AI-Bug-Bounty's vulnerability-scorer concept, made
deterministic (no ML randomness) so the 7-Question Gate stays reproducible.

Score domains (each 0-3):
  impact_realms  conf/data_integrity | authn_takeover | money | infra
  exploitability instant | conditional | lab-only
  breadth        all-users | privileged-users | one-tenant
  hardening      NO compensating control | partial control | plugin-level fix
  proof          end-to-end proven | replay proven | candidate only

Output: weighted score 0-100, tier P1..P4 + one-line rationale + RED flags
(what drops it a tier: report without proof, conditional-only exploit etc).

Usage:
  python scripts/vuln_scorer.py --data-scores 3 3 3 --exploit 3 --breadth 3 --control 1 --proof 3
  python scripts/vuln_scorer.py --profile examples path/to/finding.json
"""
from __future__ import annotations

import argparse
import json

WEIGHTS = {"impact": 0.40, "exploitability": 0.25, "breadth": 0.15,
           "control": 0.12, "proof": 0.08}

TIERS = [(85, "P1", "submit immediately — critical"),
         (65, "P2", "high — submit after full PoC replay"),
         (40, "P3", "medium — needs chaining to reach P1/P2"),
         (15, "P4", "low / leaderboard — check always-rejected list first"),
         (0,  "DIE", "not submittable — kill it (5-min rule)")]


def score(impact, exploitability, breadth, control, proof) -> dict:
    base = (impact * WEIGHTS["impact"] + exploitability * WEIGHTS["exploitability"]
            + breadth * WEIGHTS["breadth"] + control * WEIGHTS["control"]
            + proof * WEIGHTS["proof"]) / 3.0
    pct = round(base * 100, 1)
    tier = next(t for floor, t, _ in TIERS if pct >= floor)
    why = next(msg for floor, t, msg in TIERS if pct >= floor)
    flags = []
    if proof <= 1 and impact >= 2:
        flags.append("high impact claimed with weak proof — validate BEFORE report")
    if exploitability <= 1:
        flags.append("lab-only/conditional — needs a real-target replay")
    if control >= 2 and impact < 3:
        flags.append("compensating control likely present — expect triager downgrade")
    if breadth <= 1 and impact >= 3:
        flags.append("one-tenant money impact — still strong, but scope the blast radius")
    return {"score": pct, "tier": tier, "advice": why, "flags": flags,
            "cvss_hint": {3: "High/9+", 2: "Medium", 1: "Low"}[min(impact, 3)]}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-scores", type=int, nargs=3, metavar=("C", "T", "M"),
                   default=[2, 1, 1],
                   help="impact realms 0-3: (confidentiality, takeover, money)")
    p.add_argument("--exploit", type=int, default=2, help="0-3")
    p.add_argument("--breadth", type=int, default=2, help="0-3")
    p.add_argument("--control", type=int, default=1, help="0-3 (0 = NO control)")
    p.add_argument("--proof", type=int, default=2, help="0-3")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    res = score(max(a.data_scores), a.exploit, a.breadth, a.control, a.proof)
    print(json.dumps(res, indent=2) if a.json else
          f"score={res['score']}/100 tier={res['tier']} | {res['advice']}")
    for f in res["flags"]:
        print(f"  !! {f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
