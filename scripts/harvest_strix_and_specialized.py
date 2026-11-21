#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harvest_strix_and_specialized.py — Ingest Strix, Shannon, WSTG, and Specialized Agent Skills
===========================================================================================
Deeply extracts all sub-skills from:
  - usestrix_strix/strix/skills/**/*.md
  - KeygraphHQ_shannon
  - OWASP_WSTG
  - FiredMosquito831_bugbounty-cybersec-ai-agent-resources
And installs them into .opencode/skills/ and .agents/skills/ with 100% valid YAML frontmatter.
"""

import os
import re
import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMUNITY = REPO_ROOT / "skills_library" / "community_packs"
OPENCODE_SKILLS = REPO_ROOT / ".opencode" / "skills"
AGENTS_SKILLS = REPO_ROOT / ".agents" / "skills"

def sanitize_name(name: str) -> str:
    name = name.lower()
    name = re.sub(r"[^a-z0-9\-]+", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    if len(name) > 64:
        name = name[:64].rstrip("-")
    return name

def install_markdown_file(source: Path, prefix: str):
    try:
        content = source.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    if len(content.strip()) < 200:
        return None

    stem = source.stem
    if stem.lower() in ("readme", "contributing", "license"):
        stem = source.parent.name

    name = sanitize_name(f"{prefix}-{stem}")
    if not name or len(name) < 3:
        name = sanitize_name(f"{prefix}-{source.parent.name}-{stem}")

    # Extract clean description
    first_lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith(("#", "```", "---"))][:3]
    raw_desc = " ".join(first_lines)[:250] if first_lines else f"Advanced security testing skill from {prefix}"
    clean_desc = re.sub(r"\s+", " ", raw_desc).strip()
    if len(clean_desc) > 300:
        clean_desc = clean_desc[:297] + "..."

    import json
    name_escaped = json.dumps(name)
    desc_escaped = json.dumps(clean_desc, ensure_ascii=False)
    dumped_fm = f"name: {name_escaped}\ndescription: {desc_escaped}"

    body = content
    if body.startswith("---"):
        parts = body.split("---", 2)
        if len(parts) >= 3:
            body = parts[2].lstrip("\r\n")

    skill_text = f"---\n{dumped_fm}\n---\n\n# {name.replace('-', ' ').title()}\n\n*Integrated from {prefix}*\n\n{body}\n"

    # Save to .opencode/skills/<name>/SKILL.md
    op_dir = OPENCODE_SKILLS / name
    op_dir.mkdir(parents=True, exist_ok=True)
    (op_dir / "SKILL.md").write_text(skill_text, encoding="utf-8")

    # Save to .agents/skills/<name>/SKILL.md
    ag_dir = AGENTS_SKILLS / name
    ag_dir.mkdir(parents=True, exist_ok=True)
    (ag_dir / "SKILL.md").write_text(skill_text, encoding="utf-8")

    return {
        "name": name,
        "description": clean_desc,
        "pack": prefix,
        "source": str(source.relative_to(REPO_ROOT)),
        "status": "Available"
    }

def main():
    print("=" * 70)
    print("🚀 DEEP EXTRACTION FOR STRIX, SHANNON, WSTG & AGENT ATLAS")
    print("=" * 70)

    extracted = []

    # 1. Strix Skills
    strix_dir = COMMUNITY / "usestrix_strix" / "strix" / "skills"
    if strix_dir.exists():
        print(f"[*] Processing Strix skills at {strix_dir}...")
        for root, dirs, files in os.walk(strix_dir):
            for f in files:
                if f.endswith(".md") and f.lower() != "readme.md":
                    sub = Path(root).name
                    res = install_markdown_file(Path(root) / f, f"strix-{sub}")
                    if res:
                        extracted.append(res)

    # 2. KeygraphHQ Shannon
    shannon_dir = COMMUNITY / "KeygraphHQ_shannon"
    if shannon_dir.exists():
        print(f"[*] Processing Shannon at {shannon_dir}...")
        for root, dirs, files in os.walk(shannon_dir):
            if ".git" in dirs: dirs.remove(".git")
            for f in files:
                if f.endswith(".md") and f.lower() not in ("readme.md", "license.md", "contributing.md"):
                    res = install_markdown_file(Path(root) / f, "shannon-agent")
                    if res:
                        extracted.append(res)

    # 3. OWASP WSTG
    wstg_dir = COMMUNITY / "OWASP_WSTG" / "latest" / "4-Web_Application_Security_Testing"
    if wstg_dir.exists():
        print(f"[*] Processing OWASP WSTG testing guides at {wstg_dir}...")
        for root, dirs, files in os.walk(wstg_dir):
            if ".git" in dirs: dirs.remove(".git")
            for f in files:
                if f.endswith(".md") and f.lower() not in ("readme.md", "index.md", "info.md", "summary.md"):
                    category_sub = Path(root).name
                    res = install_markdown_file(Path(root) / f, f"owasp-wstg-{category_sub}")
                    if res:
                        extracted.append(res)

    # 4. DanubeLabs FiredMosquito831 Bounty Resources
    bounty_dir = COMMUNITY / "FiredMosquito831_bugbounty-cybersec-ai-agent-resources"
    if bounty_dir.exists():
        print(f"[*] Processing DanubeLabs Atlas at {bounty_dir}...")
        for root, dirs, files in os.walk(bounty_dir):
            if ".git" in dirs: dirs.remove(".git")
            for f in files:
                if f.endswith(".md") and f.lower() != "readme.md":
                    res = install_markdown_file(Path(root) / f, "bounty-atlas")
                    if res:
                        extracted.append(res)

    print(f"\n[+] Extracted and compiled {len(extracted)} specialized skills!")

    # Update MANIFEST.json
    manifest_path = OPENCODE_SKILLS / "MANIFEST.json"
    manifest_data = {}
    if manifest_path.exists():
        try:
            import json
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            manifest_data = {}

    skills_dict = manifest_data.get("skills", {})
    if isinstance(skills_dict, list):
        skills_dict = {s["name"]: s for s in skills_dict}

    for item in extracted:
        skills_dict[item["name"]] = item

    manifest_data["skills"] = skills_dict
    manifest_data["total_active_skills"] = len(os.listdir(OPENCODE_SKILLS))

    import json
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
    print(f"[+] MANIFEST.json updated with {len(skills_dict)} total registered skills!")
    print("=" * 70)

if __name__ == "__main__":
    main()
