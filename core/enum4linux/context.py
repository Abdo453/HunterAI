"""enum4linux-ng — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.enum4linux.schemas import Enum4LinuxAssetRecord

log = logging.getLogger("enum4linux.context")


class ContextEnricher:
    """L3: يضيف سياقًا لكل مضيف AD/SMB بعد التعداد."""

    def __init__(self, nmap_services: Optional[Dict[int, str]] = None):
        self.nmap_services = nmap_services or {}

    def enrich(self, record: Enum4LinuxAssetRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "role": "standalone",
            "is_domain_joinable": bool(record.domain),
            "attack_surface": [],
            "notes": [],
        }

        if record.is_dc:
            context["role"] = "domain_controller"
            context["notes"].append("Domain Controller — هدف عالي القيمة (Kerberos/LDAP/GC)")
        elif record.domain:
            context["role"] = "domain_member"
            context["notes"].append(f"عضو في النطاق {record.domain}")

        if record.anonymous_access:
            context["attack_surface"].append("anonymous_smb")
            context["notes"].append("وصول SMB مجهول (null session) متاح")

        if record.users:
            context["attack_surface"].append("user_enumeration")
        if record.shares:
            context["attack_surface"].append("share_enumeration")

        writable = [s for s in record.shares if s.writable]
        if writable:
            context["attack_surface"].append("writable_share")
            context["notes"].append(
                "مشاركات قابلة للكتابة: " + ", ".join(s.name for s in writable[:5])
            )

        # ربط بمنافذ nmap المعروفة
        related = {p: s for p, s in self.nmap_services.items() if p in (88, 135, 139, 389, 445, 464, 636, 3268, 5985)}
        if related:
            context["related_services"] = related

        return context


class AdaptiveTestAdvisor:
    """L4: يقترح خطوات AD التالية بناءً على نتائج التعداد."""

    def advise(
        self,
        record: Enum4LinuxAssetRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        host = record.host
        domain = record.domain or "<domain>"
        s: List[str] = []

        # تعداد SMB/مشاركات أساسي دائمًا
        s.append(f"netexec smb {host} --shares --users --pass-pol")

        if record.is_dc or context.get("role") == "domain_controller":
            s.append(f"netexec ldap {host} -u <user> -p <pass> --query '(objectClass=*)'")
            s.append(f"bloodhound-python -d {domain} -ns {host} -u <user> -p <pass> -c All")

        # عند الوصول المجهول، جرّب AS-REP roasting مباشرة (لا يحتاج بيانات اعتماد)
        if record.anonymous_access:
            s.append(
                f"impacket-GetNPUsers {domain}/ -no-pass -dc-ip {host} -usersfile users.txt"
            )

        if record.users:
            s.append(f"netexec smb {host} -u {record.users[0].username} -p '<pass>' --rid-brute")

        writable = [x for x in record.shares if x.writable]
        if writable:
            s.append(f"smbclient //{host}/{writable[0].name} -N -c 'dir'")

        # Kerberoast يحتاج بيانات اعتماد
        s.append(f"impacket-GetUserSPNs -request -dc-ip {host} {domain}/<user>:<pass>")

        seen: set = set()
        unique: List[str] = []
        for item in s:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        return unique[:8]
