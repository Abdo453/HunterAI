#!/usr/bin/env python3
"""rate_guard.py — file-backed shared rate budget across PARALLEL agents (OP-6).

The in-process RateLimiter/CircuitBreaker (bughunter/memory/audit_log.py) works
inside one process. When multiple subagents hit the same host from SEPARATE
processes, they must share one budget file:

    data/memory/rate_budget.json   {"host": {"ts": [...], "open_until": 0}}

Usage (each parallel worker calls before every request):
    python scripts/rate_guard.py acquire <host> [--rps 10] [-b path]   # exit 0 = go, 2 = wait
Or importable: from rate_guard import SharedBudget
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "data" / "memory" / "rate_budget.json"
WINDOW = 1.0          # per-second bucket
BREAK_THRESHOLD = 5   # consecutive floods open circuit


class SharedBudget:
    def __init__(self, path: Path = DEFAULT_PATH, rps: float = 10.0):
        self.path = path; self.rps = rps
        path.parent.mkdir(parents=True, exist_ok=True)
        self._load()

    def _load(self):
        try:
            self.state = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            self.state = {}

    def _save(self):
        self.path.write_text(json.dumps(self.state), encoding="utf-8")

    def acquire(self, host: str) -> tuple[bool, float]:
        """returns (go, wait_seconds). Circuit tripped -> wait resolves later."""
        now = time.time()
        rec = self.state.setdefault(host, {"ts": [], "open_until": 0, "floods": 0})
        if now < rec.get("open_until", 0):
            return False, rec["open_until"] - now
        rec["ts"] = [t for t in rec.get("ts", []) if now - t < WINDOW]
        go = len(rec["ts"]) < self.rps
        if go:
            rec["ts"].append(now)
        self._save()
        if not go:
            return False, WINDOW / self.rps
        return True, 0.0

    def record_failure(self, host: str) -> bool:
        """consecutive 5xx storms -> open circuit 5 min. Returns trip state."""
        rec = self.state.setdefault(host, {"ts": [], "open_until": 0, "floods": 0})
        rec["floods"] = rec.get("floods", 0) + 1
        tripped = rec["floods"] >= BREAK_THRESHOLD
        if tripped:
            rec["open_until"] = time.time() + 300
            rec["floods"] = 0
        self._save()
        return tripped

    def record_success(self, host: str):
        rec = self.state.setdefault(host, {"ts": [], "open_until": 0, "floods": 0})
        rec["floods"] = 0
        self._save()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    pa = sub.add_parser("acquire"); pa.add_argument("host")
    pa.add_argument("--rps", type=float, default=10.0)
    pf = sub.add_parser("fail"); pf.add_argument("host")
    po = sub.add_parser("ok"); po.add_argument("host")
    ps = sub.add_parser("status"); ps.add_argument("host", nargs="?", default=None)
    x = p.parse_args()
    sb = SharedBudget()
    if x.cmd == "acquire":
        sb.rps = x.rps
        go, wait = sb.acquire(x.host)
        print(json.dumps({"go": go, "wait": round(wait, 3)}))
        return 0 if go else 2
    if x.cmd == "fail":
        t = sb.record_failure(x.host)
        print(json.dumps({"circuit_tripped": t, "open_until": t and 300 or 0}))
        return 0
    if x.cmd == "ok":
        sb.record_success(x.host); print('{"ok": true}')
        return 0
    if x.cmd == "status":
        for h, rec in (sb.state if not x.host else {x.host: sb.state.get(x.host, {})}).items():
            print(f"  {h:<30} open={time.time() < rec.get('open_until', 0)} floods={rec.get('floods', 0)}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
