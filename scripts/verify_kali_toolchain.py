#!/usr/bin/env python3
"""Safe local readiness check for the HunterAI Kali toolchain.

This script never contacts a target.  It only checks local executables and
invokes their version/help output to distinguish an installed tool from one
that is merely present on PATH but broken.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "tools.yaml"
MANIFEST_PATH = ROOT / "environment" / "manifest.json"


def probe(binary: str, timeout: float) -> Dict[str, Any]:
    path = shutil.which(binary)
    if not path:
        return {"status": "MISSING", "binary": binary, "path": None, "detail": "Not found on PATH"}

    for argument in ("--version", "--help", "-h"):
        try:
            completed = subprocess.run(
                [path, argument], capture_output=True, text=True, timeout=timeout, check=False
            )
            output = (completed.stdout or completed.stderr or "").strip().splitlines()
            if completed.returncode == 0 or output:
                return {
                    "status": "READY",
                    "binary": binary,
                    "path": path,
                    "detail": output[0][:180] if output else f"Exited {completed.returncode}",
                }
        except subprocess.TimeoutExpired:
            return {"status": "UNHEALTHY", "binary": binary, "path": path, "detail": "Help command timed out"}
        except OSError as exc:
            return {"status": "UNHEALTHY", "binary": binary, "path": path, "detail": str(exc)}
    return {"status": "UNHEALTHY", "binary": binary, "path": path, "detail": "Executable did not produce usable help/version output"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify HunterAI's local Kali toolchain without scanning anything.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if a required tool is not ready.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Maximum seconds for each local help/version check.")
    parser.add_argument("--output", type=Path, help="Optional JSON report path.")
    args = parser.parse_args()

    configured = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    required = set(manifest.get("required_kali_tools", []))
    tools: List[Dict[str, Any]] = []
    for category, entries in configured.items():
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if not isinstance(spec, dict) or "cmd" not in spec:
                continue
            item = probe(str(spec["cmd"]), args.timeout)
            item.update({"name": name, "category": category, "required": name in required})
            tools.append(item)

    tools.sort(key=lambda item: (item["status"] != "READY", item["category"], item["name"]))
    counts = {status: sum(item["status"] == status for item in tools) for status in ("READY", "UNHEALTHY", "MISSING")}
    wordlist_roots = [Path("/usr/share/seclists"), Path("/usr/share/wordlists/seclists"), Path.home() / "wordlist" / "SecLists"]
    report = {
        "host": {"system": platform.system(), "release": platform.release(), "python": sys.version.split()[0]},
        "safe_check": "Only local --version/--help commands were run; no target was contacted.",
        "summary": {"configured": len(tools), **counts, "required_ready": all(item["status"] == "READY" for item in tools if item["required"])},
        "seclists": next((str(path) for path in wordlist_roots if path.is_dir()), None),
        "tools": tools,
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not args.strict or report["summary"]["required_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
