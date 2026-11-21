#!/usr/bin/env python3
"""oss_bounty_triage.py — open-source GitHub bounty triage (OP-7, Hermes flow).

Layered search: bounty-tagged OPEN issues with NO assignee, zero-reward noise
skipped, acceptance-path check per repo (am I able to fix from outside?).

Usage:
  python scripts/oss_bounty_triage.py                       # default sweep
  python scripts/oss_bounty_triage.py --repo expensify/expensify
  python scripts/oss_bounty_triage.py --min-reward 250 --limit 15
Env: GITHUB_TOKEN optional (raised rate limits).
"""
from __future__ import annotations

import argparse
import json
import os
import time
import urllib.request

API = "https://api.github.com"
DOLLAR = "$"  # zero-reward bounty bots post "$0"/points — skipped by default
REWARD_RE = None


def _gh(path: str, timeout: int = 20) -> dict | list:
    req = urllib.request.Request(f"{API}{path}")
    req.add_header("Accept", "application/vnd.github+json")
    tok = os.environ.get("GITHUB_TOKEN", "")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def sweep(min_reward: int, limit: int, repo: str | None) -> int:
    q = 'label:"bounty" state:open no:assignee'
    if repo:
        q += f' repo:{repo}'
    try:
        res = _gh(f"/search/issues?q={urllib.request.quote(q)}&per_page=30&sort=created&order=desc")
    except Exception as e:
        print(f"[!] GitHub search failed: {e}")
        return 1
    items = res.get("items", [])
    print(f"oss-bounty: {res.get('total_count', 0)} open unconquered bounty issues"
          f" (showing {min(limit, len(items))})\n")
    rows = []
    for it in items[: limit * 2]:
        body = (it.get("body") or "")
        # skip zero-reward bot posts
        rewards = [int(s) for s in
                   [f.strip() for f in
                    body.replace(",", "").split("$")[1:20][:0]]] if False else []
        # cheap reward extraction: first $N>=min_reward mention
        import re
        found = [int(m.group(1)) for m in re.finditer(r"\$(\d{2,6})", body)
                 if int(m.group(1)) >= min_reward]
        if not found:
            continue  # noise / points-only
        repo_name = (it.get("repository_url") or "?").split("repos/")[-1]
        age_days = (time.time() - time.mktime(
            time.strptime(it.get("created_at", ""),
                          "%Y-%m-%dT%H:%M:%SZ"))) // 86400 if it.get("created_at") and (it.get("created_at").endswith("Z")) else (time.time() - time.mktime(time.strptime(it.get("created_at", "2000-01-01T00:00:00Z"), "%Y-%m-%dT%H:%M:%SZ"))) // 86400
        rows.append({"reward": max(found), "repo": repo_name,
                     "title": it.get("title", "")[:70],
                     "age_days": int(age_days), "url": it.get("html_url"),
                     "labels": [lb.get("name", "") for lb in it.get("labels", [])][:4]})
    rows.sort(key=lambda r: (r["reward"], -r["age_days"]), reverse=True)
    for r in rows[:limit]:
        print(f"  ${r['reward']:<6} {r['repo']:<40} {r['age_days']:>4}d | {r['title']}")
        print(f"         {r['url']}  labels={r['labels']}")
    # acceptance-path hint for top row
    if rows:
        top = rows[0]
        print(f"\n[hint] before sinking time on {top['repo']}: check CODEOWNERS +"
              " CONTRIBUTING + maintainer responsiveness"
              " (human-blocker handoff per OP-7).")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", default=None)
    p.add_argument("--min-reward", type=int, default=100)
    p.add_argument("--limit", type=int, default=12)
    a = p.parse_args()
    return sweep(a.min_reward, a.limit, a.repo)


if __name__ == "__main__":
    raise SystemExit(main())
