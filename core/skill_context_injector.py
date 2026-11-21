#!/usr/bin/env python3
"""
Skill Context Injector (Internal Semantic RAG)
==============================================
يقوم بالبحث الذكي في ترسانة المهارات (600 مهارة في .opencode/skills)
واستخراج التكتيكات والأوامر الأكثر صلة بالمهمة وحقنها مباشرة في سياق النموذج المناسب.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
SKILLS_DIR = BASE_DIR / ".opencode" / "skills"
AGENTS_SKILLS_DIR = BASE_DIR / ".agents" / "skills"
MANIFEST_PATH = SKILLS_DIR / "MANIFEST.json"

ROLE_KEYWORDS = {
    "dialogue": [
        "agent-browser", "browser", "recon", "osint", "crawl", "subdomain", "endpoint",
        "url", "mapping", "passive", "dns", "discovery", "intelligence", "teach"
    ],
    "coder": [
        "skill-creator", "tdd", "teach", "script", "code", "forge", "exploit", "python",
        "automation", "sast", "semgrep", "review", "fuzzing", "ci/cd", "development"
    ],
    "redteam": [
        "web-api-graphql-pentest", "modern-web-exploit-chains", "hack", "api-fuzzing-bug-bounty", "security-fuzzing", "security-payloads",
        "security-patterns", "security-passwords", "security-webshells", "burp",
        "waf", "bypass", "idor", "ssrf", "injection", "gate", "triage", "token",
        "jwt", "race", "tampering", "xss"
    ],
    "deep_thinker": [
        "abh-network-killchain", "network-segmentation", "vlan", "firewall", "wireshark",
        "scapy", "packet", "grill-me", "llm-testing", "threat", "modeling", "apt",
        "killchain", "analysis", "logic", "strategy", "risk", "mitre", "decision", "attack-path"
    ],
    "cve_hunter": [
        "network-services-pentest", "metasploit-automation", "linux-privesc-arsenal",
        "abh-network-killchain", "network", "port", "nmap", "naabu", "smb", "rpc", "nfs",
        "telnet", "ftp", "vnc", "snmp", "service", "active-directory", "adcs", "kerberos",
        "security-webshells", "security-patterns", "cve", "vulnerability", "scan", "audit", "c2"
    ],
    "adversary_chainer": [
        "container-cloud-escape", "active-directory-attacks", "infrastructure-pivoting", "linux-privesc-arsenal", "metasploit-automation",
        "abh-network-killchain", "lateral", "pivot", "tunnel", "socks5", "chisel",
        "impacket", "netexec", "smbexec", "psexec", "privesc", "chain", "escape",
        "escalation", "kerberoasting", "persistence", "dcsync", "pass-the-ticket",
        "security-payloads", "security-passwords", "security-usernames"
    ],
    "network_analyst": [
        "network-services-pentest", "infrastructure-pivoting", "metasploit-automation", "linux-privesc-arsenal",
        "abh-network-killchain", "network", "port", "nmap", "naabu", "netexec", "impacket",
        "smb", "rpc", "nfs", "telnet", "ftp", "ssh", "vnc", "snmp", "active-directory",
        "kerberos", "ldap", "wireshark", "scapy", "lateral", "pivot", "cve", "audit"
    ]
}

class SkillContextInjector:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.skills: List[Dict[str, Any]] = []
        self._load_manifest()
        self._initialized = True

    def _load_manifest(self):
        if not MANIFEST_PATH.exists():
            self._load_from_disk()
            return
        try:
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                raw_skills = data.get("skills", [])
                if isinstance(raw_skills, dict):
                    self.skills = list(raw_skills.values())
                elif isinstance(raw_skills, list):
                    self.skills = raw_skills
                else:
                    self.skills = []
        except Exception as e:
            self._load_from_disk()

    def _load_from_disk(self):
        self.skills = []
        for base in [SKILLS_DIR, AGENTS_SKILLS_DIR]:
            if not base.exists():
                continue
            for d in base.iterdir():
                if d.is_dir() and (d / "SKILL.md").exists():
                    self.skills.append({
                        "name": d.name,
                        "description": f"Cybersecurity skill {d.name}",
                        "source": str(d / "SKILL.md")
                    })

    def get_relevant_skills(self, role: str, query: str = "", limit: int = 5) -> List[Dict[str, Any]]:
        """
        البحث الذكي عن المهارات المطابقة لدور النموذج وسياق المهمة
        """
        if not self.skills:
            return []

        role_keys = [k.lower() for k in ROLE_KEYWORDS.get(role, [])]
        query_words = [w.lower() for w in re.findall(r"\w+", query)] if query else []

        scored_skills = []
        for s in self.skills:
            score = 0
            name = s.get("name", "").lower()
            desc = s.get("description", "").lower()

            # High weight for specific query keywords (target vuln class / objective)
            for q_term in query_words:
                if len(q_term) < 2:
                    continue
                if q_term in name:
                    score += 30
                if q_term in desc:
                    score += 12

            # Background weight for agent role specialization
            for r_term in role_keys:
                if len(r_term) < 3:
                    continue
                if r_term in name:
                    score += 3
                if r_term in desc:
                    score += 1

            if score > 0:
                scored_skills.append((score, s))

        scored_skills.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in scored_skills[:limit]]

    def extract_skill_summary(self, skill_name: str, max_chars: int = 600) -> str:
        """
        قراءة التعليمات الأساسية من ملف SKILL.md للمهارة
        """
        skill_file = SKILLS_DIR / skill_name / "SKILL.md"
        if not skill_file.exists():
            skill_file = AGENTS_SKILLS_DIR / skill_name / "SKILL.md"
        if not skill_file.exists():
            return ""

        try:
            content = skill_file.read_text(encoding="utf-8", errors="ignore")
            # إزالة frontmatter
            if content.startswith("---"):
                parts = content.split("---", 2)
                if len(parts) >= 3:
                    content = parts[2].strip()

            lines = [line.strip() for line in content.splitlines() if line.strip()]
            summary_lines = []
            char_count = 0
            for line in lines:
                if line.startswith("#"):
                    summary_lines.append(line)
                elif line.startswith("-") or line.startswith("*") or line.startswith("["):
                    summary_lines.append(line)
                elif len(line) < 150:
                    summary_lines.append(line)
                char_count += len(line)
                if char_count >= max_chars:
                    break

            return "\n".join(summary_lines[:15])
        except Exception:
            return ""

    def build_injected_context(self, role: str, query: str = "", max_skills: int = 4) -> str:
        """
        بناء قالب السياق التكتيكي المحقون في الـ System Prompt
        """
        relevant = self.get_relevant_skills(role, query, limit=max_skills)
        if not relevant:
            return ""

        context_blocks = []
        context_blocks.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        context_blocks.append(f"🎯 الترسانة المعرفية التكتيكية المحقونة ({len(relevant)} مهارات تخصصية):")
        context_blocks.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        for skill in relevant:
            name = skill.get("name", "")
            title = skill.get("title", name)
            summary = self.extract_skill_summary(name, max_chars=400)
            if not summary:
                summary = skill.get("description", "")[:250]

            block = f"■ [SKILL: {title}]\n{summary}"
            context_blocks.append(block)

        context_blocks.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
        return "\n".join(context_blocks)

# كائن عام جاهز للاستدعاء الفوري
skill_injector = SkillContextInjector()

if __name__ == "__main__":
    import sys
    role_arg = sys.argv[1] if len(sys.argv) > 1 else "redteam"
    query_arg = sys.argv[2] if len(sys.argv) > 2 else "bypass rate limit and test race condition"
    ctx = skill_injector.build_injected_context(role_arg, query_arg)
    print(ctx)
