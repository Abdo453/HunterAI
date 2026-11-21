#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sanitize_all_skills_frontmatter.py — Fix and Validate YAML Frontmatter for All Skills
=====================================================================================
Ensures 100% compliance with YAML standards across .agents/skills and .opencode/skills.
Uses PyYAML's yaml.dump to guarantee proper quoting, escaping, and formatting.
"""

import os
import re
import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

def sanitize_skill_file(skill_path: Path):
    try:
        content = skill_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return False, f"Read error: {e}"

    body = content
    raw_name = skill_path.parent.name
    raw_desc = f"Security skill for {raw_name}"

    if content.startswith("---"):
        parts = content.split("---", 2)
        if len(parts) >= 3:
            fm_text = parts[1]
            body = parts[2].lstrip("\r\n")

            # Try to extract name and desc from raw frontmatter
            name_m = re.search(r"^name:\s*(.+)$", fm_text, re.MULTILINE)
            desc_m = re.search(r"^description:\s*(.+)$", fm_text, re.MULTILINE)

            if name_m:
                raw_name = name_m.group(1).strip().strip("'\"")
            if desc_m:
                raw_desc = desc_m.group(1).strip().strip("'\"")
        else:
            body = content.lstrip("-").strip()

    # Clean name: lowercase alphanumeric and hyphens only, max 64 chars
    clean_name = re.sub(r"[^a-z0-9\-]+", "-", raw_name.lower())
    clean_name = re.sub(r"-+", "-", clean_name).strip("-")
    if not clean_name or len(clean_name) < 2:
        clean_name = skill_path.parent.name.lower()
    clean_name = clean_name[:64].rstrip("-")

    # Clean description: one-line, stripped of control characters, max 300 chars
    clean_desc = re.sub(r"\s+", " ", raw_desc).strip()
    if len(clean_desc) > 300:
        clean_desc = clean_desc[:297] + "..."
    if not clean_desc:
        clean_desc = f"Cybersecurity skill {clean_name}"

    fm_dict = {
        "name": clean_name,
        "description": clean_desc
    }

    try:
        dumped_fm = yaml.dump(fm_dict, allow_unicode=True, default_flow_style=False, sort_keys=False).strip()
    except Exception:
        # Fallback to json-safe quoting
        import json
        dumped_fm = f"name: {json.dumps(clean_name)}\ndescription: {json.dumps(clean_desc)}"

    new_content = f"---\n{dumped_fm}\n---\n\n{body}"
    try:
        skill_path.write_text(new_content, encoding="utf-8")
        return True, "fixed"
    except Exception as e:
        return False, f"Write error: {e}"

def process_directory(base_dir: Path):
    if not base_dir.exists():
        return
    print(f"[*] Processing skills in {base_dir}...")
    fixed_count = 0
    total = 0
    for d in base_dir.iterdir():
        if not d.is_dir():
            continue
        skill_file = d / "SKILL.md"
        if skill_file.exists():
            total += 1
            ok, msg = sanitize_skill_file(skill_file)
            if ok:
                fixed_count += 1

    print(f"[+] {base_dir}: Checked {total} skills, validated/fixed {fixed_count}.")

def verify_all(base_dir: Path):
    failed = []
    passed = 0
    for d in base_dir.iterdir():
        if not d.is_dir():
            continue
        skill_file = d / "SKILL.md"
        if not skill_file.exists():
            continue
        try:
            content = skill_file.read_text(encoding="utf-8", errors="replace")
            parts = content.split("---", 2)
            if len(parts) >= 3:
                yaml.safe_load(parts[1])
                passed += 1
            else:
                failed.append((d.name, "Missing frontmatter delimiters"))
        except Exception as e:
            failed.append((d.name, str(e)))

    print(f"[Verification for {base_dir.name}] Passed: {passed}, Failed: {len(failed)}")
    if failed:
        print("Failures:")
        for name, err in failed[:5]:
            print(f"  - {name}: {err}")
    return len(failed) == 0

def main():
    print("=" * 70)
    print("🔧 FRONTMATTER SANITIZER & VALIDATOR")
    print("=" * 70)

    agents_dir = REPO_ROOT / ".agents" / "skills"
    opencode_dir = REPO_ROOT / ".opencode" / "skills"

    process_directory(agents_dir)
    process_directory(opencode_dir)

    print("\n" + "=" * 70)
    print("🔎 FINAL VERIFICATION")
    print("=" * 70)
    ok_agents = verify_all(agents_dir)
    ok_opencode = verify_all(opencode_dir)

    if ok_agents and ok_opencode:
        print("\n🎉 ALL SKILLS NOW HAVE 100% VALID YAML FRONTMATTER! ZERO PARSING ERRORS!")
    else:
        print("\n⚠️ Some skills still have issues.")

if __name__ == "__main__":
    main()
