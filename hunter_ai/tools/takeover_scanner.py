"""
HunterAI Takeover Scanner — Real Fingerprint-Backed Subdomain Takeover Audit
============================================================================
Loads verified takeover provider fingerprints from
``wordlists/pentesterflow/takeover/fingerprints.json`` and inspects recon
artifacts in ``recon_dir`` (never fabricating synthetic candidates).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List

_FINGERPRINTS_PATH = (
    Path(__file__).resolve().parents[2]
    / "wordlists"
    / "pentesterflow"
    / "takeover"
    / "fingerprints.json"
)


def _load_fingerprints() -> List[Dict[str, Any]]:
    if not _FINGERPRINTS_PATH.is_file():
        return []
    try:
        data = json.loads(_FINGERPRINTS_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("fingerprints"), list):
            return [f for f in data["fingerprints"] if isinstance(f, dict)]
        if isinstance(data, list):
            return [f for f in data if isinstance(f, dict)]
    except Exception:
        return []
    return []


def scan_takeover(recon_dir: str) -> List[Dict[str, Any]]:
    """Scan recon output directory for subdomain takeover candidates against verified CNAME patterns."""
    p = Path(recon_dir)
    if not p.exists():
        print(f"[Takeover Scanner] UNAVAILABLE: recon path not found: {recon_dir}")
        return []

    fingerprints = _load_fingerprints()
    cname_patterns: List[tuple[str, str]] = []
    for fp in fingerprints:
        svc = str(fp.get("service") or fp.get("provider") or "unknown")
        for pat in fp.get("cname") or []:
            if isinstance(pat, str) and pat.strip():
                cname_patterns.append((svc, pat.strip().lower()))

    files = [p] if p.is_file() else [f for f in p.rglob("*") if f.is_file() and f.suffix in (".txt", ".json", ".csv", ".log")]
    results: List[Dict[str, Any]] = []
    seen = set()

    for f in files[:200]:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for line in text.splitlines():
            low = line.lower()
            for svc, pat in cname_patterns:
                if pat in low:
                    host_m = re.search(r"([a-z0-9][a-z0-9.-]+\.[a-z]{2,})", low)
                    sub = host_m.group(1) if host_m else str(f.name)
                    key = (sub, pat)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append({
                        "subdomain": sub,
                        "service": svc,
                        "cname_pattern": pat,
                        "source_file": str(f),
                        "verified": False,
                        "status": "CANDIDATE",
                    })
                    break

    print(f"[Takeover Scanner] Found {len(results)} candidate(s) in {recon_dir}")
    for r in results[:20]:
        print(f"  {r['subdomain']} -> {r['service']} ({r['cname_pattern']}) [CANDIDATE]")
    return results


__all__ = ["scan_takeover"]
