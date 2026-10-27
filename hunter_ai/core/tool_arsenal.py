"""
HunterAI Tool Arsenal — Installed External Tools Registry
=========================================================
Single source of truth for "which external tools does this project actually
use, and are they installed?".

Previously this file carried a hardcoded 21-item list that had drifted away
from the real execution paths — the pipeline registry
(``hunter_ai.pipeline.tool_specs.MasterToolRegistry``) alone declares more
tools than the old list contained.  The list below is now **derived** from the
live registries so ``pentest arsenal`` can never under-report again.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# kept for backwards compatibility with callers importing this name directly
KNOWN_TOOLS = [
    "subfinder", "httpx", "nuclei", "katana", "ffuf", "nmap",
    "gobuster", "dirsearch", "dalfox", "sqlmap", "amass",
    "gau", "waybackurls", "hakrawler", "assetfinder", "wpscan",
    "trivy", "wafw00f", "wafryt", "arjun", "naabu", "masscan",
    "sniper",
]

_ROOT = Path(__file__).resolve().parent.parent.parent


def _from_pipeline_registry() -> Dict[str, str]:
    """الأدوات التي ينفّذها الـ pipeline فعلياً (binary name -> stage)."""
    out: Dict[str, str] = {}
    try:
        from hunter_ai.pipeline.tool_specs import MasterToolRegistry
        for spec in MasterToolRegistry().specs.values():
            for binary in spec.prerequisites or []:
                if binary:
                    out.setdefault(binary.lower(), spec.stage)
    except Exception:
        pass
    return out


def _from_tools_yaml() -> Set[str]:
    out: Set[str] = set()
    try:
        import yaml
        path = _ROOT / "config" / "tools.yaml"
        if path.is_file():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for category, entries in data.items():
                if not isinstance(entries, dict):
                    continue
                for name, spec in entries.items():
                    if not isinstance(spec, dict):
                        continue
                    out.add(name.lower())
                    cmd = spec.get("cmd")
                    if cmd:
                        out.add(str(cmd).lower())
    except Exception:
        pass
    return out


def _from_tools_json() -> Set[str]:
    out: Set[str] = set()
    try:
        path = _ROOT / "config" / "tools.json"
        if path.is_file():
            for entry in json.loads(path.read_text(encoding="utf-8")):
                if isinstance(entry, dict) and entry.get("name"):
                    out.add(str(entry["name"]).lower())
    except Exception:
        pass
    return out


def _from_skill_manifests() -> Set[str]:
    out: Set[str] = set()
    skills_root = _ROOT / "skills"
    if not skills_root.is_dir():
        return out
    try:
        import yaml
        for yaml_path in skills_root.rglob("skill.yaml"):
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
            for key in ("tools_required", "fallback_tools"):
                for tool in data.get(key) or []:
                    if tool:
                        out.add(str(tool).lower())
    except Exception:
        pass
    return out


def collect_tool_names() -> Dict[str, List[str]]:
    """يجمع كل الأدوات المعروفة مع مصدر كل منها."""
    names: Dict[str, Set[str]] = {}

    def _add(name: str, source: str) -> None:
        key = (name or "").strip().lower()
        if not key or " " in key:
            return
        names.setdefault(key, set()).add(source)

    for t in KNOWN_TOOLS:
        _add(t, "builtin")

    for binary, stage in _from_pipeline_registry().items():
        _add(binary, f"pipeline:{stage}")

    for t in _from_tools_yaml():
        _add(t, "tools.yaml")
    for t in _from_tools_json():
        _add(t, "tools.json")
    for t in _from_skill_manifests():
        _add(t, "skill.yaml")

    return {k: sorted(v) for k, v in sorted(names.items())}


def list_tools() -> List[Dict[str, Any]]:
    """Return list of tools with availability status."""
    result: List[Dict[str, Any]] = []
    for name, sources in collect_tool_names().items():
        path = shutil.which(name)
        result.append({
            "name": name,
            "status": "INSTALLED" if path else "MISSING",
            "path": path or "",
            "sources": sources,
        })
    return result


def summary() -> Dict[str, Any]:
    """ملخص سريع: كم أداة معرَّفة وكم منها مثبّتة."""
    tools = list_tools()
    installed = [t for t in tools if t["status"] == "INSTALLED"]
    return {
        "total": len(tools),
        "installed": len(installed),
        "missing": len(tools) - len(installed),
        "installed_names": [t["name"] for t in installed],
    }


__all__ = ["list_tools", "collect_tool_names", "summary", "KNOWN_TOOLS"]
