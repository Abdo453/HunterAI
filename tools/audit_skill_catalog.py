#!/usr/bin/env python3
"""Audit HunterAI skill entrypoints line by line without executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ROOTS = (REPO_ROOT / ".opencode" / "skills", REPO_ROOT / ".agents" / "skills")

PATTERNS = {
    "authorization_gate": re.compile(
        r"written authorization|required authorization|authorization required|"
        r"proof of authorization|no grant[,;:]? no execution|signed grant|"
        r"do not proceed without|must confirm scope",
        re.I,
    ),
    "blanket_refusal": re.compile(
        r"refuse (?:the |any |all )?requests?|cannot (?:help|assist)|"
        r"must not assist|only (?:defensive|safe) (?:work|requests)|"
        r"redirect to (?:defensive|safe)",
        re.I,
    ),
    "mode_downgrade": re.compile(
        r"read[- ]only only|offline only|local[- ]only|never execute|"
        r"do not (?:run|execute|test)|analysis only|passive only",
        re.I,
    ),
    "instruction_override": re.compile(
        r"ignore (?:all )?(?:previous|prior|system|developer) instructions|"
        r"developer mode|never refuse|safety polic(?:y|ies).{0,32}(?:not|doesn.t|don.t) apply|"
        r"all (?:safety|content) filters.{0,24}disabled|do anything now",
        re.I,
    ),
    "request_data_mutation": re.compile(
        r"(?:drop|delete|remove|filter|strip|denylist|sanitize|redact).{0,48}"
        r"(?:cookie|token|authorization|bearer|header|request body)|"
        r"anonymous[- ]only (?:cookie|session)",
        re.I,
    ),
    "auto_install_or_download": re.compile(
        r"(?:pip|pip3|npm|pnpm|yarn|apt|apt-get|dnf|yum|brew|go|cargo) install\b|"
        r"\bgit clone\b|\bcurl\b.{0,160}(?:\||>|-o\b)|\bwget\b",
        re.I,
    ),
    "hooks_persistence_telemetry": re.compile(
        r"postinstall|preinstall|sessionstart|userpromptsubmit|shell (?:profile|init)|"
        r"autorun|auto[- ]update|telemetry|analytics endpoint|phone home",
        re.I,
    ),
    "secret_or_credential_access": re.compile(
        r"~[/\\]\.ssh|~[/\\]\.aws|~[/\\]\.config|credentials? file|"
        r"environment variables?|api[_ -]?key|access[_ -]?token|private key",
        re.I,
    ),
}


def normalized_digest(text: str) -> str:
    """Hash behaviorally equivalent wrappers together despite generated names."""
    text = re.sub(r"^name:\s*.*$", "name: <normalized>", text, flags=re.M)
    text = re.sub(r"^\*Sourced from .*\*\s*$", "", text, flags=re.M)
    text = re.sub(r"^#\s+[^\n]+", "# <normalized>", text, count=1, flags=re.M)
    text = re.sub(r"\s+", " ", text).strip()
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def inspect_file(path: Path, root: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    findings: dict[str, list[dict]] = defaultdict(list)
    for number, line in enumerate(lines, 1):
        for category, pattern in PATTERNS.items():
            if pattern.search(line):
                findings[category].append({"line": number, "text": line.strip()[:500]})

    frontmatter = text.startswith("---\n") or text.startswith("---\r\n")
    name_match = re.search(r"^name:\s*['\"]?([^'\"\r\n]+)", text, re.M)
    description_match = re.search(r"^description:\s*(\S.*)$", text, re.M)
    expected_name = path.parent.name
    declared_name = name_match.group(1).strip() if name_match else None
    return {
        "root": root.relative_to(REPO_ROOT).as_posix(),
        "path": path.relative_to(REPO_ROOT).as_posix(),
        "expected_name": expected_name,
        "declared_name": declared_name,
        "frontmatter": frontmatter,
        "description_present": bool(description_match),
        "name_matches_folder": declared_name == expected_name,
        "bytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "normalized_sha256": normalized_digest(text),
        "findings": dict(findings),
    }


def render_markdown(report: dict) -> str:
    counts = report["finding_counts"]
    lines = [
        "# HunterAI skill catalog audit",
        "",
        f"Generated: `{report['generated_at']}`",
        "",
        "The audit reads every discovered `SKILL.md` line by line. It does not execute skill content.",
        "",
        "## Inventory",
        "",
        f"- Entrypoints: **{report['entrypoints']}**",
        f"- Unique raw files: **{report['unique_raw_files']}**",
        f"- Unique normalized contents: **{report['unique_normalized_contents']}**",
        f"- Duplicate copies: **{report['duplicate_copies']}**",
        f"- Invalid or mismatched frontmatter: **{report['frontmatter_issues']}**",
        "",
        "## Line-level signals",
        "",
        "| Category | Matching lines | Affected skills |",
        "| --- | ---: | ---: |",
    ]
    for category in PATTERNS:
        item = counts.get(category, {"lines": 0, "skills": 0})
        lines.append(f"| `{category}` | {item['lines']} | {item['skills']} |")

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "A signal is not automatically a defect. Quoted test payloads, warnings, and examples can match the same words as operating instructions. The JSON report preserves file, line, and surrounding text so reviewers can distinguish data from reachable behavior.",
            "",
            "The active catalog should be generated from the reviewed project source under `skills/hunterai-redteam/`. Community packages remain intake material and must not be copied directly into discovery roots.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=REPO_ROOT / "artifacts" / "skill-audit.json")
    parser.add_argument("--markdown", type=Path, default=REPO_ROOT / "docs" / "SKILL_AUDIT.md")
    args = parser.parse_args()

    records = []
    for root in DEFAULT_ROOTS:
        if not root.is_dir():
            continue
        for path in sorted(root.glob("*/SKILL.md")):
            records.append(inspect_file(path, root))

    raw_hashes = Counter(item["sha256"] for item in records)
    normalized_hashes = Counter(item["normalized_sha256"] for item in records)
    finding_counts = {}
    for category in PATTERNS:
        matching = [item for item in records if item["findings"].get(category)]
        finding_counts[category] = {
            "skills": len(matching),
            "lines": sum(len(item["findings"][category]) for item in matching),
        }

    report = {
        "schema": "hunterai-skill-audit/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entrypoints": len(records),
        "unique_raw_files": len(raw_hashes),
        "unique_normalized_contents": len(normalized_hashes),
        "duplicate_copies": len(records) - len(normalized_hashes),
        "frontmatter_issues": sum(
            not item["frontmatter"]
            or not item["description_present"]
            or not item["name_matches_folder"]
            for item in records
        ),
        "finding_counts": finding_counts,
        "duplicate_groups": [
            {"normalized_sha256": digest, "paths": [item["path"] for item in records if item["normalized_sha256"] == digest]}
            for digest, count in normalized_hashes.items()
            if count > 1
        ],
        "skills": records,
    }

    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    args.markdown.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("entrypoints", "unique_raw_files", "unique_normalized_contents", "duplicate_copies", "frontmatter_issues", "finding_counts")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
