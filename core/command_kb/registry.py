"""
سجل الأوامر الموثقة (Command Registry) لـ EKG-CG.
يوفر أوامر Nmap, ffuf, sqlmap, curl، إلخ موثقة مسبقاً ومستعدة للاستخدام الآمن.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any

from core.command_kb.models import (
    CommandEntry,
    CommandSafetyLevel,
    CommandCategory,
)

log = logging.getLogger("core.command_kb.registry")


class CommandRegistry:
    """
    سجل الأوامر الموثقة.
    - register(entry): إضافة أمر جديد.
    - find_by_tool(tool): البحث عن أوامر بأداة معينة.
    - find_by_category(category): البحث حسب الفئة.
    - find_safe_for_target(target, context): العثور على أوامر آمنة لتنفيذها على الهدف.
    - get(entry_id): جلب أمر بمعرّفه.
    """

    def __init__(self):
        self._commands: Dict[str, CommandEntry] = {}
        self._by_tool: Dict[str, List[str]] = {}       # tool -> [command ids]
        self._by_category: Dict[str, List[str]] = {}   # category -> [command ids]

    def register(self, entry: CommandEntry) -> None:
        self._commands[entry.id] = entry
        self._by_tool.setdefault(entry.tool, []).append(entry.id)
        self._by_category.setdefault(entry.category.value, []).append(entry.id)
        log.debug(f"[CMD-KB] Registered {entry.tool}: {entry.description} ({entry.id})")

    def get(self, command_id: str) -> Optional[CommandEntry]:
        return self._commands.get(command_id)

    def find_by_tool(self, tool: str) -> List[CommandEntry]:
        return [self._commands[cid] for cid in self._by_tool.get(tool, [])]

    def find_by_category(self, category: CommandCategory) -> List[CommandEntry]:
        return [self._commands[cid] for cid in self._by_category.get(category.value, [])]

    def find_by_safety(self, safety_level: CommandSafetyLevel) -> List[CommandEntry]:
        return [c for c in self._commands.values() if c.safety_level == safety_level]

    def all_commands(self) -> List[CommandEntry]:
        return list(self._commands.values())

    def to_dict(self) -> Dict[str, Any]:
        return {
            cid: entry.to_dict() for cid, entry in self._commands.items()
        }


# --------------------------------------------------------------------------- #
# تهيئة الأوامر المبدئية (Nmap, ffuf, sqlmap, curl, whois, dig)
# --------------------------------------------------------------------------- #
def bootstrap_command_kb() -> CommandRegistry:
    """
    إنشاء سجل الأوامر مع الأوامر الأساسية الموثقة.
    يمكن توسيعه لاحقاً بأوامر مخصصة للبيئات المختلفة.
    """
    reg = CommandRegistry()

    # ── Reconnaissance ──
    reg.register(CommandEntry(
        tool="nmap",
        command_template="nmap -sV -sC -p {ports} {target}",
        description="Service and version detection on specified ports",
        category=CommandCategory.RECON,
        safety_level=CommandSafetyLevel.MODERATE,
        required_tools=["nmap"],
        required_ports=[],
        tags=["nmap", "service-detection", "recon"],
    ))

    reg.register(CommandEntry(
        tool="nmap",
        command_template="nmap -sn {target}",
        description="Ping sweep / host discovery",
        category=CommandCategory.RECON,
        safety_level=CommandSafetyLevel.SAFE,
        required_tools=["nmap"],
        tags=["nmap", "host-discovery", "safe"],
    ))

    reg.register(CommandEntry(
        tool="nmap",
        command_template="nmap -p- --min-rate 1000 {target}",
        description="Full TCP port scan",
        category=CommandCategory.RECON,
        safety_level=CommandSafetyLevel.MODERATE,
        required_tools=["nmap"],
        tags=["nmap", "full-port-scan"],
    ))

    # ── Enumeration ──
    reg.register(CommandEntry(
        tool="ffuf",
        command_template="ffuf -u {url}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403",
        description="Directory and file brute-forcing",
        category=CommandCategory.ENUMERATION,
        safety_level=CommandSafetyLevel.MODERATE,
        required_tools=["ffuf"],
        tags=["ffuf", "directory-busting", "enumeration"],
    ))

    reg.register(CommandEntry(
        tool="ffuf",
        command_template="ffuf -u {url}?{param}=FUZZ -w {wordlist} -mc 200",
        description="Parameter value fuzzing",
        category=CommandCategory.ENUMERATION,
        safety_level=CommandSafetyLevel.MODERATE,
        required_tools=["ffuf"],
        tags=["ffuf", "parameter-fuzzing"],
    ))

    # ── Vulnerability Scanning ──
    reg.register(CommandEntry(
        tool="sqlmap",
        command_template="sqlmap -u {url} --batch --level=1 --risk=1",
        description="SQL injection detection (safe level)",
        category=CommandCategory.VULN_SCAN,
        safety_level=CommandSafetyLevel.MODERATE,
        required_tools=["sqlmap"],
        tags=["sqlmap", "sqli", "vuln-scan"],
    ))

    reg.register(CommandEntry(
        tool="sqlmap",
        command_template="sqlmap -u {url} --batch --os-shell",
        description="SQL injection OS shell (intrusive)",
        category=CommandCategory.EXPLOIT,
        safety_level=CommandSafetyLevel.INTRUSIVE,
        required_tools=["sqlmap"],
        tags=["sqlmap", "os-shell", "intrusive"],
    ))

    # ── Utility ──
    reg.register(CommandEntry(
        tool="curl",
        command_template="curl -s -I {url}",
        description="HTTP headers check",
        category=CommandCategory.UTILITY,
        safety_level=CommandSafetyLevel.SAFE,
        required_tools=["curl"],
        tags=["curl", "headers", "safe"],
    ))

    reg.register(CommandEntry(
        tool="whois",
        command_template="whois {target}",
        description="WHOIS lookup",
        category=CommandCategory.UTILITY,
        safety_level=CommandSafetyLevel.SAFE,
        required_tools=["whois"],
        tags=["whois", "safe"],
    ))

    reg.register(CommandEntry(
        tool="dig",
        command_template="dig {target} ANY",
        description="DNS enumeration",
        category=CommandCategory.UTILITY,
        safety_level=CommandSafetyLevel.SAFE,
        required_tools=["dig"],
        tags=["dig", "dns", "safe"],
    ))

    # ── Privilege Escalation (Linux) ──
    reg.register(CommandEntry(
        tool="linux-exploit-suggester",
        command_template="perl linux-exploit-suggester.pl",
        description="Linux kernel exploit suggestion",
        category=CommandCategory.PRIVESC,
        safety_level=CommandSafetyLevel.INTRUSIVE,
        required_tools=["perl"],
        tags=["priv-esc", "kernel"],
    ))

    log.info(f"[CMD-KB] Bootstrap complete: {len(reg.all_commands())} commands registered")
    return reg
