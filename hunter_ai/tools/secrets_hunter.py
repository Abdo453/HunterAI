"""
HunterAI Secrets Hunter — Leaked Credentials Scan
=================================================
Scans JS bundles, source, and GitHub orgs for leaked credentials.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List


SECRET_PATTERNS = [
    (r"sk-[A-Za-z0-9]{20,}", "Stripe key"),
    (r"ghp_[A-Za-z0-9]{36,}", "GitHub token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"xoxb-[0-9A-Za-z-]+", "Slack token"),
]


def hunt_secrets(js_bundle: str) -> List[Dict[str, Any]]:
    """Hunt for leaked credentials in JS bundle or source directory."""
    p = Path(js_bundle)
    results: List[Dict[str, Any]] = []
    files = [p] if p.is_file() else list(p.rglob("*.js")) + list(p.rglob("*.ts"))
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for pat, name in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                results.append({
                    "file": str(f),
                    "type": name,
                    "match": m.group()[:20] + "...",
                    "line": text[: m.start()].count("\n") + 1,
                })
    print(f"[Secrets Hunter] Found {len(results)} potential secrets in {js_bundle}")
    for r in results:
        print(f"  {r['file']}:{r['line']} — {r['type']}")
    return results


__all__ = ["hunt_secrets", "SECRET_PATTERNS"]
