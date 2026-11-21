#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
harvest_all_skills.py — Mass Harvester & Ingestion Engine for Security Skills
=============================================================================
Clones 58+ community security repositories, parses agent skills, converts
methodologies and guides to executable SKILL.md format, and deploys them
into .opencode/skills/ and .agents/skills/.
"""

import os
import re
import sys
import json
import shutil
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMUNITY_PACKS = REPO_ROOT / "skills_library" / "community_packs"
OPENCODE_SKILLS = REPO_ROOT / ".opencode" / "skills"
AGENTS_SKILLS = REPO_ROOT / ".agents" / "skills"

REPOS = [
    "0x002132/skills-bugbounty",
    "0xAnalyst/hermes-cyber-skills",
    "0xGhostCAT/claude-ai-cyber-security-skills",
    "26zl/cybersec-toolkit",
    "Abdo453/HunterAI",
    "Aetherdz/huntpack",
    "EdOverflow/bugbounty-cheatsheet",
    "EdOverflow/bugbountyguide",
    "Eyadkelleh/awesome-skills-security",
    "Gabson0x/bountyforge",
    "H-mmer/pentest-agents",
    "ItsDarker/Bug-Bounty-Methodology-2026",
    "KeygraphHQ/shannon",
    "MyuriKanao/src-hunter-skill",
    "NULL200OK/null200ok-bug-bounty-skill",
    "OWASP/ASVS",
    "OWASP/CheatSheetSeries",
    "OWASP/secure-agent-playbook",
    "OWASP/www-project-web-security-testing-guide",
    "Orizon-eu/claude-code-pentest",
    "Razor25000/CybersecuritySkills",
    "S1N6H/Bug-Bounty-Skills",
    "Security-Talent/bugskill-ai",
    "SnailSploit/Claude-Red",
    "UnboundCompute/security-agent-skills",
    "WolzenGeorgi/claude-skills-pentest",
    "akashrpatil/awesome-offensive-security-skills",
    "aliasrobotics/cai",
    "amrelsagaei/Bug-Bounty-Hunting-Methodology-2025",
    "ctahok/hermes-bug-bounty-skills",
    "danielmiessler/claude-code-plugins-plus",
    "elementalsouls/Claude-BugHunter",
    "elementalsouls/Claude-OSINT",
    "enaqx/awesome-pentest",
    "groundfeel/securityskills",
    "h4ckologic/bughunter-ai",
    "instavm/security-skills",
    "javadominic/ai-security-tools",
    "killvxk/malskills-zh",
    "l3tchupkt/Bug-Bounty-Roadmap-2025",
    "mrgoonie/claudekit-skills",
    "mukul975/Threatswarm",
    "murrtada/bug-bounty-agent-skills",
    "nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters",
    "shuvonsec/claude-bug-bounty",
    "shuvonsec/public-skills-builder",
    "stickman230/claude-pentest",
    "swisskyrepo/HardwareAllTheThings",
    "swisskyrepo/InternalAllTheThings",
    "swisskyrepo/PayloadsAllTheThings",
    "trailofbits/skills",
    "trailofbits/skills-curated",
    "transilienceai/communitytools",
    "trilwu/secskills",
    "uhub/awesome-agent-skills",
    "usestrix/strix",
    "vigilantshield/Claude-HunterKit",
    "vxcontrol/pentagi",
]

def sanitize_name(name: str) -> str:
    name = name.lower()
    name = re.sub(r"[^a-z0-9\-]+", "-", name)
    name = re.sub(r"-+", "-", name).strip("-")
    if len(name) > 64:
        name = name[:64].rstrip("-")
    return name

def clone_repo(repo_slug: str):
    target_dir = COMMUNITY_PACKS / repo_slug.replace("/", "_")
    if target_dir.exists() and (target_dir / ".git").exists():
        try:
            # Pull updates
            subprocess.run(["git", "-C", str(target_dir), "pull", "--ff-only"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            return repo_slug, True, "updated"
        except Exception:
            return repo_slug, True, "existing"
    
    url = f"https://github.com/{repo_slug}.git"
    try:
        res = subprocess.run(["git", "clone", "--depth", "1", url, str(target_dir)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        if res.returncode == 0:
            return repo_slug, True, "cloned"
        else:
            return repo_slug, False, f"exit_{res.returncode}"
    except Exception as e:
        return repo_slug, False, str(e)

def extract_skills_from_pack(pack_dir: Path):
    discovered = []
    # 1. Look for existing SKILL.md
    for root, dirs, files in os.walk(pack_dir):
        # Skip .git
        if ".git" in dirs:
            dirs.remove(".git")
        if "node_modules" in dirs:
            dirs.remove("node_modules")

        for f in files:
            if f.lower() == "skill.md":
                skill_path = Path(root) / f
                discovered.append((skill_path, "existing_skill"))

    # 2. Look for markdown guides/methodologies if no SKILL.md found in directory
    if len(discovered) < 3:
        for root, dirs, files in os.walk(pack_dir):
            if ".git" in dirs:
                dirs.remove(".git")
            if "node_modules" in dirs:
                dirs.remove("node_modules")
            for f in files:
                if f.endswith(".md") and f.lower() not in ("readme.md", "contributing.md", "license.md", "changelog.md", "code_of_conduct.md"):
                    p = Path(root) / f
                    if p.stat().st_size > 500: # non-trivial
                        discovered.append((p, "markdown_guide"))

    return discovered

def convert_to_skill(source_path: Path, pack_name: str, kind: str) -> tuple[str, str, str]:
    """Returns (skill_name, description, full_skill_content)"""
    try:
        content = source_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return "", "", ""

    # Check for frontmatter
    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", content, re.DOTALL)
    if fm_match and kind == "existing_skill":
        fm_text = fm_match.group(1)
        body = fm_match.group(2)
        name_m = re.search(r"^name:\s*([^\n]+)", fm_text, re.MULTILINE)
        desc_m = re.search(r"^description:\s*([^\n]+)", fm_text, re.MULTILINE)
        
        raw_name = name_m.group(1).strip().strip("'\"") if name_m else source_path.parent.name
        desc = desc_m.group(1).strip().strip("'\"") if desc_m else f"Security skill from {pack_name}"
    else:
        raw_name = f"{pack_name}-{source_path.stem}"
        first_lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")][:3]
        desc = " ".join(first_lines)[:250] if first_lines else f"Security methodology from {pack_name}"
        body = content

    name = sanitize_name(raw_name)
    if not name or len(name) < 3:
        name = sanitize_name(f"{pack_name}-{source_path.parent.name}")

    desc = desc.replace("\n", " ").strip()
    if len(desc) > 300:
        desc = desc[:297] + "..."

    skill_content = f"""---
name: {name}
description: {desc}
---

# {name.replace('-', ' ').title()}

*Sourced from {pack_name}*

{body}
"""
    return name, desc, skill_content

def main():
    print("=" * 70)
    print("🚀 STARTING MASS SECURITY SKILLS HARVESTER (58 REPOSITORIES)")
    print("=" * 70)

    COMMUNITY_PACKS.mkdir(parents=True, exist_ok=True)
    OPENCODE_SKILLS.mkdir(parents=True, exist_ok=True)
    AGENTS_SKILLS.mkdir(parents=True, exist_ok=True)

    print(f"[*] Cloning/updating {len(REPOS)} repositories concurrently...")
    results = {"cloned": 0, "updated": 0, "existing": 0, "failed": 0}

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(clone_repo, r): r for r in REPOS}
        for f in as_completed(futures):
            repo_slug, ok, status = f.result()
            if ok:
                results[status] = results.get(status, 0) + 1
                print(f" [+] {repo_slug} -> {status}")
            else:
                results["failed"] += 1
                print(f" [!] {repo_slug} -> FAILED ({status})")

    print("\n[*] Clone Summary:", results)
    print("[*] Extracting and indexing skills into OpenCode & Agent system...")

    total_installed = 0
    manifest_entries = {}

    for pack_dir in COMMUNITY_PACKS.iterdir():
        if not pack_dir.is_dir():
            continue
        pack_name = sanitize_name(pack_dir.name.replace("_", "-"))
        discovered = extract_skills_from_pack(pack_dir)
        print(f" [*] Processing {pack_name}: found {len(discovered)} potential skills")

        for source_path, kind in discovered:
            skill_name, desc, content = convert_to_skill(source_path, pack_name, kind)
            if not skill_name:
                continue

            # Target 1: .opencode/skills/<skill_name>/SKILL.md
            opencode_target_dir = OPENCODE_SKILLS / skill_name
            opencode_target_dir.mkdir(parents=True, exist_ok=True)
            (opencode_target_dir / "SKILL.md").write_text(content, encoding="utf-8")

            # Target 2: If high value or core, also install in .agents/skills/
            if any(k in skill_name for k in ("bounty", "recon", "exploit", "idor", "ssrf", "xss", "sqli", "strix", "shannon", "owasp", "hunter", "audit", "logic", "auth", "api", "cloud")):
                agent_target_dir = AGENTS_SKILLS / skill_name
                agent_target_dir.mkdir(parents=True, exist_ok=True)
                (agent_target_dir / "SKILL.md").write_text(content, encoding="utf-8")

            manifest_entries[skill_name] = {
                "name": skill_name,
                "description": desc,
                "pack": pack_name,
                "source": str(source_path.relative_to(REPO_ROOT)),
                "kind": kind
            }
            total_installed += 1

    # Update MANIFEST.json
    manifest_path = OPENCODE_SKILLS / "MANIFEST.json"
    manifest_data = {
        "version": "2.0.0",
        "total_active_skills": len(os.listdir(OPENCODE_SKILLS)),
        "community_installed": total_installed,
        "skills": manifest_entries
    }
    manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    print("=" * 70)
    print(f"✅ HARVESTING COMPLETE!")
    print(f" • Total Skills Installed in .opencode/skills/: {len(os.listdir(OPENCODE_SKILLS))}")
    print(f" • Total Skills Installed in .agents/skills/:   {len(os.listdir(AGENTS_SKILLS))}")
    print(f" • Manifest written to: {manifest_path}")
    print("=" * 70)

if __name__ == "__main__":
    main()
