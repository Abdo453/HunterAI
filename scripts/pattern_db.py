#!/usr/bin/env python3
"""pattern_db.py — cross-target root-cause pattern memory (hash-chained).

From awarexone/Agentic-Bug-Hunter's `pattern_db.py` concept + this repo's OP-4:
after every VALIDATED finding, store the ROOT-CAUSE pattern (class + signature +
bypass that worked), NOT the target name. On a new engagement, replay past
patterns against the new stack fingerprint before brute exploration.

Store: data/memory/patterns.jsonl (hash-chained, tamper-evident).

Usage:
  python scripts/pattern_db.py add --class idor --stack "flask,uuid,postgres" \
      --sig "detail/{uuid} no ownership check" --bypass "second-object-id" \
      --evidence artifacts/t1/evidence/e1/
  python scripts/pattern_db.py query --stack "flask,uuid"
  python scripts/pattern_db.py list [--class idor]
  python scripts/pattern_db.py verify
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

STORE = Path(__file__).resolve().parents[1] / "data" / "memory" / "patterns.jsonl"
GENESIS = {"prev": "0" * 64}
FIELDS = ("class", "stack", "sig", "bypass", "evidence", "notes")


def _h(rec: dict) -> str:
    return hashlib.sha256(json.dumps(rec, sort_keys=True).encode()).hexdigest()


def _records() -> list[tuple[dict, dict]]:
    if not STORE.exists():
        return []
    out = []
    for raw in STORE.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        obj = json.loads(raw)
        chain = obj.get("_chain", {})
        body = {k: v for k, v in obj.items() if k != "_chain"}
        out.append((body, chain))  # chain = {"h": ..., "prev": ...}
    return out


def add(a) -> int:
    rec = {"class": a.clazz, **{f: getattr(a, f, "") or "" for f in FIELDS if f != "class"}}
    rec["ts"] = datetime.now(timezone.utc).isoformat()
    prev = "0" * 64
    if STORE.exists() and STORE.read_text(encoding="utf-8").strip():
        last = _records()[-1][1]
        prev = last.get("h", prev)
    chain = {"prev": prev, "h": None}
    body = {"_chain": dict(chain, h="PENDING"), **rec}
    chain["h"] = _h(body)
    out = {**rec, "_chain": chain}
    STORE.parent.mkdir(parents=True, exist_ok=True)
    with STORE.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(out, ensure_ascii=False) + "\n")
    print(f"[+] pattern #{len(_records())-1} stored -> {STORE}")
    return 0


def query(a) -> int:
    terms = [t.lower() for t in (a.stack.split(",") + a.classes.split(",")) if t]
    hits = []
    for body, _ in _records():
        blob = " ".join(str(v).lower() for k, v in body.items() if k != "ts")
        if all(t in blob for t in terms):
            hits.append(body)
    print(f"pattern_db: {len(hits)} match(es) for {terms}")
    for b in hits[-a.limit:]:
        print(json.dumps(b, ensure_ascii=False))
    return 0


def list_(a) -> int:
    recs = _records()
    if a.clazz:
        recs = [(b, c) for b, c in recs if b.get("class") == a.clazz]
    print(f"pattern_db: {len(recs)} record(s) @ {STORE}")
    for b, c in recs[-a.limit:]:
        print(f"  [{b.get('class','?')}] {b.get('sig','')[:60]} | bypass: {b.get('bypass','')[:40]}")
    return 0


def verify() -> int:
    prev = "0" * 64
    ok = True
    for i, (body, chain) in enumerate(_records()):
        check = body.copy(); check["_chain"] = {"prev": prev, "h": "PENDING"}
        if chain.get("prev") != prev or _h(check) != chain.get("h"):
            print(f"[!] chain BROKEN at record {i}"); ok = False
        prev = chain.get("h", prev)
    print("chain OK" if ok else "chain TAMPERED")
    return 0 if ok else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("add")
    s.add_argument("--class", dest="clazz", required=True, help="bug class (idor/ssrf/...)")
    s.add_argument("--stack", required=True, help="stack fp: 'flask,uuid,jwt'")
    s.add_argument("--sig", required=True, help="root-cause signature (no target names)")
    s.add_argument("--bypass", default="", help="the trick that made it exploitable")
    s.add_argument("--evidence", default="", help="artifacts path")
    s.add_argument("--notes", default="")
    q = sub.add_parser("query")
    q.add_argument("--stack", default="", help="stack terms to match")
    q.add_argument("--classes", dest="classes", default="", help="class terms to match")
    q.add_argument("--limit", type=int, default=20)
    l = sub.add_parser("list")
    l.add_argument("--class", dest="clazz", default=None)
    l.add_argument("--limit", type=int, default=20)
    sub.add_parser("verify")
    a = p.parse_args()
    if a.cmd == "add":
        return add(a)
    if a.cmd == "query":
        return query(a)
    if a.cmd == "list":
        return list_(a)
    return verify()


if __name__ == "__main__":
    raise SystemExit(main())
