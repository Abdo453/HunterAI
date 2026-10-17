#!/usr/bin/env python3
"""Safe local readiness check for the HunterAI Kali toolchain.

This script never contacts an assessment target.  It only runs local
``--version``/``--help`` probes so we can distinguish an installed tool from one
that is merely on PATH but broken.  It also verifies the Ollama models the
agent needs to think (xploiter/pentester, qwen2.5-coder, WhiteRabbitNeo).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config" / "tools.yaml"
MANIFEST_PATH = ROOT / "environment" / "manifest.json"
ENV_PATH = ROOT / ".env"


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


def check_ollama_models(host: str, expected_models: List[str], timeout: float) -> List[Dict[str, Any]]:
    """Ask the local Ollama which models it actually has pulled."""
    results: List[Dict[str, Any]] = []
    try:
        completed = subprocess.run(
            ["curl", "-s", "--connect-timeout", str(int(timeout)), f"{host}/api/tags"],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        if completed.returncode != 0:
            return [{"status": "UNHEALTHY", "binary": "ollama", "path": host,
                     "detail": f"curl failed (exit {completed.returncode})"}]
        try:
            data = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            return [{"status": "UNHEALTHY", "binary": "ollama", "path": host,
                     "detail": "Ollama /api/tags returned non-JSON"}]
        available = {m.get("name", "") for m in data.get("models", [])}
        for model in expected_models:
            ok = any(model in a or a.split(":")[0] == model.split(":")[0] for a in available)
            results.append({
                "status": "READY" if ok else "MISSING",
                "binary": "ollama",
                "path": host,
                "name": f"ollama:{model}",
                "detail": f"model {model} {'available' if ok else 'NOT PULLED'}",
            })
    except (subprocess.TimeoutExpired, OSError) as exc:
        results.append({"status": "UNHEALTHY", "binary": "ollama", "path": host, "name": "ollama", "detail": str(exc)})
    return results


def load_env_host() -> str:
    """Read OLLAMA_HOST from .env (fallback to localhost:11434)."""
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("OLLAMA_HOST="):
                return line.split("=", 1)[1].strip().strip('"')
    return "http://localhost:11434"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify HunterAI's local Kali toolchain without scanning anything.")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if a required tool/model is not ready.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Maximum seconds for each local help/version check.")
    parser.add_argument("--output", type=Path, help="Optional JSON report path.")
    args = parser.parse_args()

    configured = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    required = set(manifest.get("required_kali_tools", []))
    expected_models = manifest.get("components", {}).get("ollama", {}).get("expected_models", [])

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

    # Ollama model readiness (the agent must have models to actually *think*).
    ollama_host = load_env_host()
    ollama_results = check_ollama_models(ollama_host, expected_models, args.timeout)
    for r in ollama_results:
        r["category"] = "ai_models"
        r["required"] = True
        tools.append(r)

    tools.sort(key=lambda item: (item["status"] != "READY", item["category"], item["name"]))
    counts = {status: sum(item["status"] == status for item in tools) for status in ("READY", "UNHEALTHY", "MISSING")}
    required_ready = all(item["status"] == "READY" for item in tools if item["required"])
    wordlist_roots = [Path("/usr/share/seclists"), Path("/usr/share/wordlists/seclists"), Path.home() / "wordlist" / "SecLists"]
    report = {
        "host": {"system": platform.system(), "release": platform.release(), "python": sys.version.split()[0]},
        "ollama_host": ollama_host,
        "safe_check": "Only local --version/--help commands (and Ollama /api/tags) were run; no target was contacted.",
        "summary": {
            "configured": len(tools),
            **counts,
            "required_ready": required_ready,
        },
        "seclists": next((str(path) for path in wordlist_roots if path.is_dir()), None),
        "tools": tools,
    }
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not args.strict or required_ready else 2


if __name__ == "__main__":
    raise SystemExit(main())
