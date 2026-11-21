#!/usr/bin/env python3
"""
merge_skillssh.py
=================
يدمج المهارات المثبتة من skills.sh في MANIFEST.json الخاص بالمشروع،
ويتحقق من صحة ملفات SKILL.md، ويطبع تقريراً بالنتائج.

Usage:
    python tools/merge_skillssh.py [--skills-dir .opencode/skills] [--dry-run]
"""

import argparse
import json
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_SKILLS_DIR = BASE_DIR / ".opencode" / "skills"
MANIFEST_PATH = DEFAULT_SKILLS_DIR / "MANIFEST.json"

# Skills installed from skills.sh land in .skills/ at project root by default
# We also scan .opencode/skills for newly added SKILL.md directories
SKILLSSH_LANDING_DIR = BASE_DIR / ".skills"


def parse_frontmatter(content: str) -> dict:
    """استخراج YAML frontmatter من SKILL.md"""
    result = {}
    if not content.startswith("---"):
        return result
    parts = content.split("---", 2)
    if len(parts) < 3:
        return result
    fm = parts[1].strip()
    for line in fm.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            result[key.strip()] = value.strip().strip('"\'')
    return result


def scan_skills_dir(skills_dir: Path) -> list:
    """مسح مجلد المهارات وإرجاع قائمة المهارات مع بياناتها"""
    found = []
    for skill_path in sorted(skills_dir.iterdir()):
        if not skill_path.is_dir():
            continue
        skill_md = skill_path / "SKILL.md"
        if not skill_md.exists():
            continue
        try:
            content = skill_md.read_text(encoding="utf-8", errors="ignore")
            fm = parse_frontmatter(content)
            # استخراج وصف من أول فقرة بعد الـ frontmatter
            body = ""
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    body = parts[2].strip()
            # أول سطر غير فارغ وليس header
            desc_lines = [
                l.strip() for l in body.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]
            description = desc_lines[0][:200] if desc_lines else fm.get("description", "")

            found.append({
                "name": skill_path.name,
                "title": fm.get("name", fm.get("title", skill_path.name)),
                "description": description,
                "source": "skills.sh",
                "version": fm.get("version", "1.0.0"),
                "tags": fm.get("tags", "").split(",") if fm.get("tags") else [],
            })
        except Exception as e:
            print(f"⚠️  Error reading {skill_path}: {e}", file=sys.stderr)
    return found


def load_manifest() -> dict:
    """تحميل MANIFEST.json الحالي"""
    if MANIFEST_PATH.exists():
        try:
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"count": 0, "skills": [], "profiles": {}}


def merge_skills(manifest: dict, new_skills: list) -> tuple[dict, int, int]:
    """دمج المهارات الجديدة في MANIFEST دون تكرار"""
    existing_names = {s.get("name", "") for s in manifest.get("skills", [])}
    added = 0
    skipped = 0

    for skill in new_skills:
        if skill["name"] in existing_names:
            skipped += 1
            continue
        manifest["skills"].append(skill)
        existing_names.add(skill["name"])
        added += 1

    manifest["count"] = len(manifest["skills"])
    return manifest, added, skipped


def main():
    parser = argparse.ArgumentParser(description="Merge skills.sh skills into MANIFEST.json")
    parser.add_argument("--skills-dir", default=str(DEFAULT_SKILLS_DIR),
                        help="Path to skills directory")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview changes without writing")
    parser.add_argument("--source-dir", default=None,
                        help="Additional source directory (e.g. .skills from skills.sh)")
    args = parser.parse_args()

    skills_dir = Path(args.skills_dir)
    source_dir = Path(args.source_dir) if args.source_dir else SKILLSSH_LANDING_DIR

    print(f"🔍 Scanning for new skills in: {skills_dir}")

    # مسح المجلد الرئيسي
    all_new_skills = scan_skills_dir(skills_dir)

    # مسح مجلد skills.sh إذا كان موجوداً
    if source_dir.exists() and source_dir != skills_dir:
        print(f"🔍 Also scanning: {source_dir}")
        sh_skills = scan_skills_dir(source_dir)
        # نسخ SKILL.md إلى مجلد .opencode/skills
        for skill in sh_skills:
            src = source_dir / skill["name"]
            dst = skills_dir / skill["name"]
            if not dst.exists():
                import shutil
                shutil.copytree(src, dst)
                print(f"  📂 Copied: {skill['name']} → {dst}")
        all_new_skills.extend(sh_skills)

    manifest = load_manifest()
    before_count = manifest.get("count", 0)

    manifest, added, skipped = merge_skills(manifest, all_new_skills)

    print(f"\n📊 Results:")
    print(f"  Before: {before_count} skills")
    print(f"  Added:  {added} new skills")
    print(f"  Skipped (already in manifest): {skipped}")
    print(f"  Total:  {manifest['count']} skills")

    if added > 0:
        print(f"\n✅ New skills added:")
        for s in manifest["skills"][-added:]:
            print(f"  + {s['name']:40s} | {s['description'][:60]}")

    if not args.dry_run and added > 0:
        with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
        print(f"\n💾 MANIFEST.json updated: {MANIFEST_PATH}")
    elif args.dry_run:
        print("\n[DRY RUN] No changes written.")

    return 0 if added >= 0 else 1


if __name__ == "__main__":
    sys.exit(main())
