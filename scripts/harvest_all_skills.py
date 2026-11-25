#!/usr/bin/env python3
"""Index community security skills as review-only intake material.

This command never writes to .opencode/skills or .agents/skills. The only
active project skill catalog is skills/registry.json and is synchronized by
tools/install_opencode_skills.py after project review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMUNITY_PACKS = REPO_ROOT / "skills_library" / "community_packs"
INDEX_PATH = REPO_ROOT / "skills_library" / "community-intake-index.json"

REPOS = [
    "0x002132/skills-bugbounty", "0xAnalyst/hermes-cyber-skills",
    "0xGhostCAT/claude-ai-cyber-security-skills", "26zl/cybersec-toolkit",
    "Aetherdz/huntpack", "OWASP/ASVS", "OWASP/CheatSheetSeries",
    "OWASP/secure-agent-playbook", "OWASP/www-project-web-security-testing-guide",
    "Security-Talent/bugskill-ai", "SnailSploit/Claude-Red",
    "UnboundCompute/security-agent-skills", "aliasrobotics/cai",
    "trailofbits/skills", "trailofbits/skills-curated", "usestrix/strix",
    "vigilantshield/Claude-HunterKit", "vxcontrol/pentagi",
]


def fetch_repo(repo_slug: str) -> tuple[str, str]:
    target = COMMUNITY_PACKS / repo_slug.replace("/", "_")
    if target.joinpath(".git").is_dir():
        result = subprocess.run(
            ["git", "-C", str(target), "pull", "--ff-only"],
            capture_output=True, text=True, timeout=60,
        )
        return repo_slug, "updated" if result.returncode == 0 else "existing"
    target.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["git", "clone", "--depth", "1", f"https://github.com/{repo_slug}.git", str(target)],
        capture_output=True, text=True, timeout=120,
    )
    return repo_slug, "cloned" if result.returncode == 0 else f"failed:{result.returncode}"


def index_existing() -> list[dict]:
    records: list[dict] = []
    if not COMMUNITY_PACKS.is_dir():
        return records
    for pack in sorted(path for path in COMMUNITY_PACKS.iterdir() if path.is_dir()):
        for skill_file in sorted(pack.rglob("SKILL.md")):
            if ".git" in skill_file.parts:
                continue
            raw = skill_file.read_bytes()
            records.append({
                "pack": pack.name,
                "path": skill_file.relative_to(REPO_ROOT).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
                "status": "review_required",
                "active": False,
            })
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="explicitly clone/update the configured intake repositories")
    args = parser.parse_args()

    if args.fetch:
        COMMUNITY_PACKS.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(fetch_repo, repo) for repo in REPOS]
            for future in as_completed(futures):
                repo, status = future.result()
                print(f"[{status}] {repo}")

    records = index_existing()
    payload = {
        "schema": "hunterai-community-intake/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "active": False,
        "activation": "Review techniques and merge selected content into skills/hunterai-redteam references.",
        "count": len(records),
        "items": records,
    }
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    INDEX_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Indexed {len(records)} review-only skills in {INDEX_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
