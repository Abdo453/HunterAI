#!/usr/bin/env python3
"""monitor_surface.py — continuous monitor mode for long engagements (OP-3).

Baseline once, then diff on a schedule. Detects:
  * new/retired subdomains (passive: crt.sh — no active probing)
  * new JS bundle URLs + bundle-hash changes
Store per-target state in artifacts/<target>/monitor/.
Alerts append to alerts.jsonl (delta prints to stdout).

Usage:
  python scripts/monitor_surface.py baseline examples-hunt.example.com
  python scripts/monitor_surface.py check examples-hunt.example.com
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import ssl
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOMAIN_RE = re.compile(r"[a-z0-9._-]+\.[a-z]{2,}", re.IGNORECASE)


def _crtsh(domain: str, timeout: int = 25) -> list[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:  # offline-friendly
        print(f"[!] crt.sh unavailable: {e}")
        return []
    names = set()
    for cert in data:
        for n in cert.get("name_value", "").split("\n"):
            n = n.strip().remove_prefix("*.").lower()
            if n.endswith("." + domain) or n == domain:
                names.add(n)
    return sorted(names)


def _bundle_hashes(lines: list[str]) -> dict[str, str]:
    """hash every src/href ending in .js found in the homepage html"""
    out = {}
    for m in re.finditer(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']',
                         "\n".join(lines)):
        url = m.group(1)
        out[url] = hashlib.sha256(url.encode()).hexdigest()[:12]
    return out


def _state(target: str) -> Path:
    safe = re.sub(r"[^a-z0-9.-]", "_", target.lower())
    d = ROOT / "artifacts" / safe / "monitor"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{safe}.json"


def baseline(target: str) -> int:
    subs = _crtsh(target)
    state = {"ts": datetime.now(timezone.utc).isoformat(),
             "subdomains": subs, "bundles": {}}
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(f"https://{target}", timeout=15, context=ctx) as r:
            state["bundles"] = _bundle_hashes([r.read(200_000).decode(errors="replace")])
    except Exception as e:
        print(f"[!] homepage fetch failed: {e}")
    _state(target).write_text(json.dumps(state, indent=2), encoding="utf-8")
    print(f"[+] baseline: {len(subs)} subs, {len(state['bundles'])} js bundles"
          f" -> {_state(target)}")
    return 0


def check(target: str) -> int:
    sp = _state(target)
    if not sp.exists():
        print("[!] no baseline — run: python scripts/monitor_surface.py baseline", target)
        return 1
    old = json.loads(sp.read_text(encoding="utf-8"))
    new_subs = _crtsh(target)
    new_set, old_set = set(new_subs), set(old.get("subdomains", []))
    added, gone = sorted(new_set - old_set), sorted(old_set - new_set)
    alerts = []
    if added:
        alerts.append({"type": "subdomain-new", "hosts": added})
    if gone:
        alerts.append({"type": "subdomain-gone", "hosts": gone})
    # bundle diff
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(f"https://{target}", timeout=15, context=ctx) as r:
            bundles = _bundle_hashes([r.read(200_000).decode(errors="replace")])
    except Exception:
        bundles = old.get("bundles", {})
    old_b = old.get("bundles", {})
    changed = [u for u, h in bundles.items() if old_b.get(u) and old_b[u] != h]
    added_b = [u for u in bundles if u not in old_b]
    if changed or added_b:
        alerts.append({"type": "js-bundle", "changed": changed, "new": added_b})
    ts = {"ts": datetime.now(timezone.utc).isoformat(), "alerts": alerts}
    alerts_path = sp.parent / "alerts.jsonl"
    with alerts_path.open("a", encoding="utf-8") as fp:
        for al in alerts:
            fp.write(json.dumps({**al, "checked_at": ts["ts"]}, ensure_ascii=False) + "\n")
    sp.write_text(json.dumps({"ts": ts["ts"], "subdomains": new_subs,
                              "bundles": bundles}, indent=2), encoding="utf-8")
    print(f"[=] check {ts['ts']} — {len(alerts)} alert group(s),"
          f" +{len(added)}/-{len(gone)} subs, {len(changed)+len(added_b)} js")
    for al in alerts:
        print(json.dumps(al, ensure_ascii=False))
    print(f"    alerts -> {alerts_path}")
    return 0


def watch(target: str, interval: int) -> int:
    print(f"[+] watching {target} every {interval}s — Ctrl-C to stop")
    while True:
        check(target)
        time.sleep(interval)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline"); b.add_argument("target")
    c = sub.add_parser("check"); c.add_argument("target")
    w = sub.add_parser("watch"); w.add_argument("target")
    w.add_argument("--interval", type=int, default=3600)
    a = p.parse_args()
    if a.cmd == "baseline":
        return baseline(a.target)
    if a.cmd == "check":
        return check(a.target)
    if a.cmd == "watch":
        return watch(a.target, a.interval)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
