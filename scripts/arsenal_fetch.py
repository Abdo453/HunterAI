#!/usr/bin/env python3
"""
arsenal_fetch.py — curated, on-demand pentest-resource fetcher for the kill-chain
=================================================================================
The philosophy is NOT "download 3GB of everything" (indiscriminate archives waste
space, contain abandoned/exposed PoCs, and break license hygiene). Instead each
category below is a CURATED dual-use resource the agent pulls when a mission
needs it, into data/arsenal/, tracked + manifest-written.

Catalog
-------
wordlists      danielmiessler/SecLists              (~1.9 GB full repo; shallow=fast)
payloads       swisskyrepo/PayloadsAllTheThings     (~40 MB)
nuclei         projectdiscovery/nuclei-templates    (~80 MB)
fuzzdb         fuzzdb-project/fuzzdb                (~50 MB)
hacktricks     hacktricks-wsec/hacktricks (pdf/wiki clone keeps offline hunting)
waf-bypass     waf-bypass payloads (Tamper/0xInfection repos are curated, small)

Usage:
    python scripts/arsenal_fetch.py list
    python scripts/arsenal_fetch.py pull payloads          # one category
    python scripts/arsenal_fetch.py pull all --shallow     # shallow clones only
    python scripts/arsenal_fetch.py clean payloads         # remove one
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "arsenal"

CATALOG = {
    "wordlists": {
        "repo": "https://github.com/danielmiessler/SecLists.git",
        "about": "master password/param/dir/smart wordlists (JSON dirs, fuzz, sqli, xss)",
        "license": "MIT",
    },
    "payloads": {
        "repo": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "about": "injection technique payload collections + bypass tables (XSS/SQLi/SSTI...)",
        "license": "MIT",
    },
    "nuclei": {
        "repo": "https://github.com/projectdiscovery/nuclei-templates.git",
        "about": "community CVE/exposures templates for nuclei sweeps",
        "license": "MIT",
    },
    "fuzzdb": {
        "repo": "https://github.com/fuzzdb-project/fuzzdb.git",
        "about": "generic fuzzing dictionaries + discovery lists",
        "license": "MIT",
    },
    "waf-bypass": {
        "repo": "https://github.com/nemesida-waf/waf_bypass.git",
        "about": "WAF/IPS bypass payloads testing suite (multiple engines)",
        "license": "MIT",
    },
}


def _sh(*args: str) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout.strip()


def list() -> None:
    installed = {p.name for p in DEST.glob("*")} if DEST.exists() else set()
    print(f"{'category':<14} {'installed':<10} repo")
    print("-" * 78)
    for name, meta in CATALOG.items():
        ok = "YES" if name in installed else "no"
        print(f"{name:<14} {ok:<10} {meta['repo']}")
    print()
    print("usage:")
    print("    python scripts/arsenal_fetch.py pull <category>")
    print("    python scripts/arsenal_fetch.py pull all --shallow")
    print("    python scripts/arsenal_fetch.py clean <category>")


def pull(categories: list[str], shallow: bool) -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    if "all" in categories:
        categories = list(CATALOG)
    rc = 0
    for cat in categories:
        meta = CATALOG.get(cat)
        if not meta:
            print(f"[!] unknown category '{cat}' — run: list")
            rc = 1
            continue
        target = DEST / cat
        if (target / ".git").exists():
            print(f"[=] '{cat}' already present — git pull")
            subprocess.run(["git", "-C", str(target), "pull", "--ff-only"])
            continue
        cmd = ["git", "clone"]
        if shallow:
            cmd += ["--depth", "1", "--single-branch"]
        cmd += [meta["repo"], str(target)]
        print(f"[+] cloning {cat} ...")
        result = subprocess.run(cmd)
        if result.returncode == 0:
            print(f"    -> {target}")
    _write_manifest()
    return rc


def clean(category: str) -> int:
    target = DEST / category
    if not target.exists():
        print(f"[-] '{category}' not installed at {target}")
        return 1
    import shutil
    shutil.rmtree(target)
    print(f"[-] removed {target}")
    _write_manifest()
    return 0


def _write_manifest() -> None:
    manifest = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "catalog": [
            {"name": name, **meta, "installed": (DEST / name).exists()}
            for name, meta in CATALOG.items()
        ],
    }
    (DEST / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="show categories + install status")
    gp = sub.add_parser("pull", help="fetch one/more categories (or 'all')")
    gp.add_argument("what", nargs="+", choices=[*CATALOG, "all"])
    gp.add_argument("--shallow", action="store_true", help="depth=1")
    cp = sub.add_parser("clean", help="delete a category")
    cp.add_argument("what", choices=[*CATALOG])
    args = p.parse_args()

    if args.cmd == "list":
        list()
        return 0
    if args.cmd == "pull":
        return pull(args.what, args.shallow)
    if args.cmd == "clean":
        return clean(args.what)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
