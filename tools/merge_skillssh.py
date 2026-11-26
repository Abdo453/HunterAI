#!/usr/bin/env python3
"""Create a review-only index of skills.sh intake without activating it."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = BASE_DIR / ".skills"
DEFAULT_OUTPUT = BASE_DIR / "skills_library" / "skills-sh-intake-index.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", default=str(DEFAULT_SOURCE))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--skills-dir", help="deprecated compatibility option; never used as an activation target")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    source = Path(args.source_dir).resolve(strict=False)
    items = []
    if source.is_dir():
        for entrypoint in sorted(source.rglob("SKILL.md")):
            raw = entrypoint.read_bytes()
            items.append({
                "path": entrypoint.relative_to(source).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "status": "review_required",
                "active": False,
            })
    payload = {
        "schema": "hunterai-skills-sh-intake/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": str(source),
        "active": False,
        "count": len(items),
        "items": items,
    }
    output = Path(args.output)
    print(json.dumps({"source": str(source), "count": len(items), "active": False}, indent=2))
    if not args.dry_run:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote review-only index: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
