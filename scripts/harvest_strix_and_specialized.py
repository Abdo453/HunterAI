#!/usr/bin/env python3
"""Index specialized community documents without activating them as skills."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMUNITY = REPO_ROOT / "skills_library" / "community_packs"
OUTPUT = REPO_ROOT / "skills_library" / "specialized-intake-index.json"
PACKS = {
    "strix": COMMUNITY / "usestrix_strix",
    "shannon": COMMUNITY / "KeygraphHQ_shannon",
    "owasp-wstg": COMMUNITY / "OWASP_WSTG",
    "bounty-atlas": COMMUNITY / "FiredMosquito831_bugbounty-cybersec-ai-agent-resources",
}


def main() -> int:
    items: list[dict] = []
    for pack, root in PACKS.items():
        if not root.is_dir():
            continue
        for source in sorted(root.rglob("*.md")):
            if ".git" in source.parts or source.name.lower() in {"license.md", "contributing.md"}:
                continue
            raw = source.read_bytes()
            if len(raw) < 200:
                continue
            items.append({
                "pack": pack,
                "path": source.relative_to(REPO_ROOT).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "status": "review_required",
                "active": False,
            })
    payload = {
        "schema": "hunterai-specialized-intake/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "active": False,
        "count": len(items),
        "items": items,
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Indexed {len(items)} specialized documents for review; active skill roots were not changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
