#!/usr/bin/env python3
"""
Canonical Tool Manifest Synchronizer & Validator
================================================
Reads ``config/tools.catalog.yaml`` (the single declarative source of truth)
and validates or regenerates the derived manifests:
  - ``config/tools.json``
  - ``config/tools.yaml``
  - ``tools_mcp.json``

Usage:
    python scripts/sync_tool_manifests.py --write   # sync all derived files
    python scripts/sync_tool_manifests.py --check   # CI check (exit 1 on drift)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CATALOG_PATH = REPO_ROOT / "config" / "tools.catalog.yaml"
VALID_RISKS = {"low", "medium", "high", "critical"}
VALID_YAML_GROUPS = ("network", "web", "recon", "password", "binary", "cloud", "osint", "ctf")


class CatalogValidationError(ValueError):
    """Raised when config/tools.catalog.yaml violates schema or parity rules."""


def load_catalog(catalog_path: Path = DEFAULT_CATALOG_PATH) -> Dict[str, Any]:
    if not catalog_path.is_file():
        raise CatalogValidationError(f"Catalog file not found: {catalog_path}")
    data = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CatalogValidationError("Catalog root must be a YAML mapping")
    validate_catalog(data)
    return data


def validate_catalog(data: Dict[str, Any]) -> None:
    if data.get("schema") != "hunterai-tools-catalog/1":
        raise CatalogValidationError(f"Unsupported catalog schema: {data.get('schema')!r}")
    tools = data.get("tools")
    if not isinstance(tools, list) or not tools:
        raise CatalogValidationError("Catalog must define a non-empty 'tools' list")

    seen_ids: set[str] = set()
    known_names: set[str] = set()
    for idx, entry in enumerate(tools):
        if not isinstance(entry, dict):
            raise CatalogValidationError(f"Tool entry #{idx} must be a mapping")
        tid = str(entry.get("id") or "").strip()
        name = str(entry.get("name") or tid).strip()
        exe = str(entry.get("executable") or "").strip()
        risk = str(entry.get("risk") or "").lower()
        if not tid:
            raise CatalogValidationError(f"Tool entry #{idx} missing 'id'")
        if tid in seen_ids:
            raise CatalogValidationError(f"Duplicate tool id in catalog: {tid!r}")
        if not exe:
            raise CatalogValidationError(f"Tool {tid!r} missing 'executable'")
        if risk not in VALID_RISKS:
            raise CatalogValidationError(f"Tool {tid!r} has invalid risk {risk!r}")
        seen_ids.add(tid)
        known_names.add(tid)
        known_names.add(name)

    tiers = data.get("tiers") or {}
    if not isinstance(tiers, dict) or not tiers:
        raise CatalogValidationError("Catalog must define non-empty 'tiers'")
    for tier_name, tier in tiers.items():
        if not isinstance(tier, dict):
            raise CatalogValidationError(f"Tier {tier_name!r} must be a mapping")
        for ref in tier.get("tools", []):
            if ref not in known_names:
                raise CatalogValidationError(
                    f"Tier {tier_name!r} references unknown tool {ref!r}"
                )


def render_tools_json(catalog: Dict[str, Any]) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for tool in catalog["tools"]:
        if not tool.get("in_tools_json", False):
            continue
        entries.append(
            {
                "id": tool["id"],
                "name": tool.get("name", tool["id"]),
                "type": tool.get("type", "recon"),
                "category": tool.get("category", "recon"),
                "risk": tool.get("risk", "low"),
                "permissions": list(tool.get("permissions") or ["recon"]),
                "purpose": tool.get("purpose", ""),
                "requires_authorization": bool(tool.get("requires_authorization", False)),
                "command_template": tool.get("command_template", ""),
            }
        )
    return entries


def render_tools_yaml(catalog: Dict[str, Any]) -> str:
    grouped: Dict[str, List[Dict[str, Any]]] = {g: [] for g in VALID_YAML_GROUPS}
    for tool in catalog["tools"]:
        grp = tool.get("yaml_group")
        if grp in grouped:
            grouped[grp].append(tool)

    lines: List[str] = [
        "# ============================================================",
        "# PentestAI Unified - Security Tools Manifest",
        "# Generated from config/tools.catalog.yaml via scripts/sync_tool_manifests.py",
        "# ============================================================",
        "",
    ]
    for grp in VALID_YAML_GROUPS:
        items = grouped[grp]
        if not items:
            continue
        lines.append(f"{grp}:")
        for item in items:
            ykey = str(item.get("yaml_key") or item["id"])
            cmd = str(item["executable"])
            args = str(item.get("yaml_args", ""))
            timeout = int(item.get("timeout_s", 120))
            lines.append(
                f"  {ykey + ':':<14} {{cmd: {cmd}, args: {json.dumps(args)}, timeout: {timeout}}}"
            )
        lines.append("")

    browser = catalog.get("browser") or {}
    if browser:
        lines.append("browser:")
        for k, v in browser.items():
            if isinstance(v, bool):
                v_str = "true" if v else "false"
            elif isinstance(v, (int, float)):
                v_str = str(v)
            else:
                v_str = json.dumps(str(v))
            lines.append(f"  {k + ':':<17} {v_str}")
        lines.append("")
    return "\n".join(lines)


def render_tools_mcp_json(catalog: Dict[str, Any]) -> Dict[str, Any]:
    tiers_out: Dict[str, Any] = {}
    for tier_name, tier in (catalog.get("tiers") or {}).items():
        entry: Dict[str, Any] = {
            "risk": tier["risk"],
            "requires_authorization": bool(tier.get("requires_authorization", False)),
            "action_class": tier.get("action_class", "read_only"),
            "tools": list(tier.get("tools") or []),
        }
        if tier.get("constraints"):
            entry["constraints"] = list(tier["constraints"])
        tiers_out[tier_name] = entry

    return {
        "version": str(catalog.get("version", "1.0.0")),
        "description": str(catalog.get("description", "")),
        "source_of_truth": {
            "catalog": "config/tools.catalog.yaml",
            "tools": "config/tools.json",
            "tools_yaml": "config/tools.yaml",
            "mcp_servers": "config/mcp.example.json",
            "registry": "core.tool_registry.ToolRegistry",
        },
        "tiers": tiers_out,
        "mcp_servers": list(catalog.get("mcp_servers") or []),
        "invariants": list(catalog.get("invariants") or []),
    }


def _semantic_equal_json(existing_text: str, rendered_obj: Any) -> bool:
    try:
        return json.loads(existing_text) == rendered_obj
    except Exception:
        return False


def _semantic_equal_yaml(existing_text: str, rendered_text: str) -> bool:
    try:
        return yaml.safe_load(existing_text) == yaml.safe_load(rendered_text)
    except Exception:
        return False


def sync_manifests(
    repo_root: Path = REPO_ROOT,
    catalog_path: Path | None = None,
    *,
    write: bool = False,
) -> Tuple[bool, List[str]]:
    """Validate (and optionally write) derived manifests.

    Returns ``(in_sync, messages)``.
    """
    cat_path = catalog_path or (repo_root / "config" / "tools.catalog.yaml")
    catalog = load_catalog(cat_path)

    tools_json_path = repo_root / "config" / "tools.json"
    tools_yaml_path = repo_root / "config" / "tools.yaml"
    tools_mcp_path = repo_root / "tools_mcp.json"

    rendered_json_obj = render_tools_json(catalog)
    rendered_json_str = json.dumps(rendered_json_obj, indent=2, ensure_ascii=False) + "\n"
    rendered_yaml_str = render_tools_yaml(catalog)
    rendered_mcp_obj = render_tools_mcp_json(catalog)
    rendered_mcp_str = json.dumps(rendered_mcp_obj, indent=2, ensure_ascii=False) + "\n"

    drift: List[str] = []

    if write:
        tools_json_path.write_text(rendered_json_str, encoding="utf-8")
        tools_yaml_path.write_text(rendered_yaml_str, encoding="utf-8")
        tools_mcp_path.write_text(rendered_mcp_str, encoding="utf-8")
        return True, [
            f"Synced {tools_json_path.relative_to(repo_root)} ({len(rendered_json_obj)} tools)",
            f"Synced {tools_yaml_path.relative_to(repo_root)}",
            f"Synced {tools_mcp_path.relative_to(repo_root)} ({len(rendered_mcp_obj['tiers'])} tiers)",
        ]

    if not tools_json_path.is_file() or not _semantic_equal_json(
        tools_json_path.read_text(encoding="utf-8"), rendered_json_obj
    ):
        drift.append("config/tools.json is out of sync with config/tools.catalog.yaml")

    if not tools_yaml_path.is_file() or not _semantic_equal_yaml(
        tools_yaml_path.read_text(encoding="utf-8"), rendered_yaml_str
    ):
        drift.append("config/tools.yaml is out of sync with config/tools.catalog.yaml")

    if not tools_mcp_path.is_file() or not _semantic_equal_json(
        tools_mcp_path.read_text(encoding="utf-8"), rendered_mcp_obj
    ):
        drift.append("tools_mcp.json is out of sync with config/tools.catalog.yaml")

    if drift:
        return False, drift
    return True, [
        f"All tool manifests match {cat_path.relative_to(repo_root)} "
        f"({len(catalog['tools'])} catalog tools, {len(rendered_json_obj)} tools.json entries, "
        f"{len(rendered_mcp_obj['tiers'])} tiers)"
    ]


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="Verify derived manifests match catalog")
    group.add_argument("--write", action="store_true", help="Write derived manifests from catalog")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG_PATH)
    args = parser.parse_args(argv)

    write = bool(args.write) and not bool(args.check)
    try:
        ok, messages = sync_manifests(REPO_ROOT, args.catalog, write=write)
    except CatalogValidationError as exc:
        print(f"[-] Catalog validation error: {exc}", file=sys.stderr)
        return 1

    for msg in messages:
        prefix = "[+]" if ok else "[-]"
        stream = sys.stdout if ok else sys.stderr
        print(f"{prefix} {msg}", file=stream)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
