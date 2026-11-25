#!/usr/bin/env python3
"""Synchronize HunterAI's reviewed project skill registry into discovery roots."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "skills" / "registry.json"
TARGETS = (REPO_ROOT / ".opencode" / "skills", REPO_ROOT / ".agents" / "skills")
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


class RegistryError(RuntimeError):
    pass


def snapshot(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def parse_entrypoint(path: Path, expected_name: str) -> tuple[str, str]:
    if not path.is_file():
        raise RegistryError(f"missing entrypoint: {path}")
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        raise RegistryError(f"missing YAML frontmatter: {path}")
    name_match = re.search(r"^name:\s*['\"]?([^'\"\r\n]+)", text, re.M)
    description_match = re.search(r"^description:\s*['\"]?([^\r\n]+)", text, re.M)
    if not name_match or name_match.group(1).strip() != expected_name:
        raise RegistryError(f"frontmatter name does not match {expected_name}: {path}")
    if not description_match or not description_match.group(1).strip().strip("'\""):
        raise RegistryError(f"missing description: {path}")
    return name_match.group(1).strip(), description_match.group(1).strip().strip("'\"")


def load_registry() -> list[dict]:
    data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    if data.get("schema") != "hunterai-project-skills/1":
        raise RegistryError("unsupported registry schema")
    entries = data.get("skills")
    if not isinstance(entries, list) or not entries:
        raise RegistryError("registry must contain at least one skill")
    names = [entry.get("name") for entry in entries]
    if len(names) != len(set(names)):
        raise RegistryError("duplicate skill name in registry")
    for entry in entries:
        name = entry.get("name", "")
        if not NAME_RE.fullmatch(name):
            raise RegistryError(f"invalid skill name: {name}")
        source = (REPO_ROOT / entry["source"]).resolve(strict=False)
        if not source.is_relative_to((REPO_ROOT / "skills").resolve()):
            raise RegistryError(f"skill source escapes canonical skills root: {source}")
        parse_entrypoint(source / "SKILL.md", name)
        for route in entry.get("routes", []):
            reference = (source / route.get("path", "")).resolve(strict=False)
            if not reference.is_relative_to(source) or not reference.is_file():
                raise RegistryError(f"invalid routed reference for {name}: {reference}")
    return entries


def sources(entries: list[dict]) -> dict[str, Path]:
    return {entry["name"]: REPO_ROOT / entry["source"] for entry in entries}


def stale_skill_dirs(target: Path, expected: set[str]) -> list[Path]:
    if not target.is_dir():
        return []
    return sorted(
        child
        for child in target.iterdir()
        if child.is_dir() and (child / "SKILL.md").is_file() and child.name not in expected
    )


def validate_removal_target(path: Path, parent: Path) -> None:
    resolved_parent = parent.resolve()
    resolved_path = path.resolve(strict=False)
    if resolved_path == resolved_parent or not resolved_path.is_relative_to(resolved_parent):
        raise RegistryError(f"unsafe removal target outside {parent}: {path}")
    if path.is_symlink():
        raise RegistryError(f"refusing to remove linked skill directory: {path}")


def sync(entries: list[dict], *, clean: bool, dry_run: bool) -> list[dict]:
    source_map = sources(entries)
    for target in TARGETS:
        target.mkdir(parents=True, exist_ok=True)
        stale = stale_skill_dirs(target, set(source_map))
        if stale and not clean:
            raise RegistryError(f"{target} contains {len(stale)} unmanaged skills; rerun with --clean")
        for path in stale:
            validate_removal_target(path, target)
            print(f"[-] remove stale {path.relative_to(REPO_ROOT)}")
            if not dry_run:
                shutil.rmtree(path)
        for name, source in source_map.items():
            destination = target / name
            print(f"[+] sync {source.relative_to(REPO_ROOT)} -> {destination.relative_to(REPO_ROOT)}")
            if not dry_run:
                if destination.exists():
                    validate_removal_target(destination, target)
                    shutil.rmtree(destination)
                shutil.copytree(source, destination)

    installed = []
    for entry in entries:
        source = REPO_ROOT / entry["source"]
        _, description = parse_entrypoint(source / "SKILL.md", entry["name"])
        installed.append({
            "name": entry["name"],
            "description": description,
            "source": entry["source"],
            "sha256": snapshot(source),
            "kind": "project_primary" if entry["name"] == "hunterai-redteam" else "project_skill",
            "routes": entry.get("routes", []),
        })

    if not dry_run:
        manifest = {
            "schema": "hunterai-active-skills/1",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "count": len(installed),
            "primary": "hunterai-redteam",
            "skills": installed,
        }
        (TARGETS[0] / "MANIFEST.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    return installed


def check(entries: list[dict]) -> None:
    source_map = sources(entries)
    expected = set(source_map)
    for target in TARGETS:
        stale = stale_skill_dirs(target, expected)
        if stale:
            raise RegistryError(f"unmanaged skills in {target}: {len(stale)}")
        for name, source in source_map.items():
            destination = target / name
            if not destination.is_dir():
                raise RegistryError(f"missing mirror: {destination}")
            if snapshot(destination) != snapshot(source):
                raise RegistryError(f"stale mirror: {destination}")
            parse_entrypoint(destination / "SKILL.md", name)
    manifest = json.loads((TARGETS[0] / "MANIFEST.json").read_text(encoding="utf-8"))
    if manifest.get("count") != len(entries):
        raise RegistryError("manifest count does not match registry")
    if [item["name"] for item in manifest.get("skills", [])] != [item["name"] for item in entries]:
        raise RegistryError("manifest catalog does not match registry")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clean", action="store_true", help="remove unmanaged discovered skills")
    parser.add_argument("--check", action="store_true", help="verify mirrors without changes")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--profiles", help="compatibility flag; centralized catalog ignores profiles")
    parser.add_argument("--full", action="store_true", help="compatibility flag; catalog stays centralized")
    parser.add_argument("--cap", type=int, help="compatibility flag; registry defines active count")
    args = parser.parse_args()

    try:
        entries = load_registry()
        if args.check:
            check(entries)
            print(f"[+] Project skill registry valid: {len(entries)} active skill(s)")
            return 0
        installed = sync(entries, clean=args.clean, dry_run=args.dry_run)
        suffix = " (dry run)" if args.dry_run else ""
        print(f"[+] Synchronized {len(installed)} project skill(s){suffix}")
        return 0
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, RegistryError) as error:
        print(f"[-] Skill registry error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
