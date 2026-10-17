"""NetExec (nxc) — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.netexec.schemas import NetExecHostRecord

log = logging.getLogger("netexec.context")


class ContextEnricher:
    """L3: يضيف سياقًا لكل نتيجة netexec (دور المضيف + سطح الهجوم)."""

    def __init__(self, ad_domains: Optional[List[str]] = None):
        self.ad_domains = [d.lower() for d in (ad_domains or [])]

    def enrich(self, record: NetExecHostRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "role": "unknown",
            "is_domain_joined": False,
            "attack_surface": [],
            "notes": [],
        }
        if record.domain:
            context["is_domain_joined"] = True
            context["role"] = "domain_member"
            if record.hostname and record.hostname.upper().startswith("DC"):
                context["role"] = "domain_controller"
                context["notes"].append("يبدو Domain Controller (اسم يبدأ بـ DC)")

        if record.signing is False:
            context["attack_surface"].append("ntlm_relay")
        if record.smbv1 is True:
            context["attack_surface"].append("smbv1")
        if record.pwned:
            context["attack_surface"].append("admin_access")
            context["notes"].append("وصول إداري مؤكد بـ (Pwn3d!)")
        if record.username:
            context["notes"].append(f"بيانات اعتماد صالحة للمستخدم: {record.username}")

        return context


class AdaptiveTestAdvisor:
    """L4: يقترح الخطوة التالية بناءً على بروتوكول/نتيجة netexec."""

    def advise(
        self,
        record: NetExecHostRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        host = record.host
        s: List[str] = []

        if record.protocol == "smb":
            s.append(f"netexec smb {host} --shares --users --pass-pol")
            if record.pwned:
                s.append(f"netexec smb {host} -u <user> -p <pass> --sam")
                s.append(f"netexec smb {host} -u <user> -p <pass> -M lsassy")
        if record.protocol == "ldap":
            s.append(f"netexec ldap {host} -u <user> -p <pass> --query '(objectClass=*)'")
        if record.protocol in ("winrm", "mssql", "rdp"):
            s.append(f"netexec {record.protocol} {host} -u <user> -p <pass>")
        if context.get("role") == "domain_controller":
            s.append(f"netexec smb {host} -u <user> -p <pass> --ntds  # احذر أثر النسخ")
            s.append(f"bloodhound-python -d {record.domain or '<domain>'} -ns {host} -u <user> -p <pass> -c All")

        s.append(f"netexec smb {host} -u <user> -p <pass> --rid-brute")

        seen: set = set()
        unique: List[str] = []
        for item in s:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique[:8]
