"""Masscan Port Discovery — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional

from core.masscan.schemas import MasscanPortRecord

log = logging.getLogger("masscan.context")

# خريطة المنافذ الشائعة → الخدمة المتوقعة (للسياق والاقتراح، لا للإثبات)
WELL_KNOWN_PORTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 512: "exec", 513: "login", 514: "shell", 587: "smtp",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc", 5985: "winrm",
    5986: "winrm-tls", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 9300: "elasticsearch", 10250: "kubelet",
    27017: "mongodb", 5000: "upnp/registry",
}

# منافذ عالية القيمة: خدمات إدارية/قواعد بيانات يترتب على كشفها أثر مرتفع
HIGH_VALUE_PORTS: set = {
    21, 22, 23, 135, 139, 445, 512, 513, 514, 1433, 1521, 2049, 2375, 2376,
    3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 9300, 10250, 27017,
}


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل منفذ مكتشف:
      - الخدمة المتوقعة من المنفذ (Well-known)
      - علم المنفذ عالي القيمة
      - ملاحظات حول الحالة/البروتوكول
    """

    def __init__(self, nmap_services: Optional[Dict[int, str]] = None):
        # port -> service name مؤكد من nmap (إن توفّر) لتعزيز السياق
        self.nmap_services = nmap_services or {}

    def enrich(self, record: MasscanPortRecord) -> Dict[str, Any]:
        port = record.port
        context: Dict[str, Any] = {
            "expected_service": WELL_KNOWN_PORTS.get(port, "unknown"),
            "is_high_value": port in HIGH_VALUE_PORTS,
            "is_non_standard": port not in WELL_KNOWN_PORTS,
            "confirmed_service": self.nmap_services.get(port),
            "notes": [],
        }

        if context["is_high_value"]:
            context["notes"].append(
                f"منفذ عالي القيمة ({port}) — خدمة إدارية/قاعدة بيانات محتملة"
            )
        if context["is_non_standard"]:
            context["notes"].append(f"منفذ غير قياسي ({port}) — قد يكون خدمة مخفية")
        if context["confirmed_service"]:
            context["notes"].append(
                f"خدمة مؤكدة من nmap: {context['confirmed_service']}"
            )
        if record.protocol == "udp":
            context["notes"].append("بروتوكول UDP — قد ينتج إيجابيات/سلبيات زائفة بسهولة")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح خطوة التأكيد التالية بناءً على المنافذ المكتشفة (fingerprint بدل مسح عام).
    """

    def advise(
        self,
        record: MasscanPortRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        port = record.port
        host = record.host
        svc = context.get("expected_service", "unknown")
        suggestions: List[str] = []

        # التأكيد الأساسي: nmap -sV على المنفذ
        suggestions.append(f"nmap -sV -p {port} {host}")

        # اقتراحات خاصة بالخدمة
        service_hints = {
            "smb": [f"nmap -p {port} --script smb-enum-shares,smb-security-mode {host}"],
            "ldap": [f"nmap -p {port} --script ldap-rootdse {host}"],
            "rdp": [f"nmap -p {port} --script rdp-enum-encryption {host}"],
            "vnc": [f"nmap -p {port} --script vnc-info,vnc-brute {host}"],
            "ssh": [f"ssh-audit -p {port} {host}"],
            "ftp": [f"nmap -p {port} --script ftp-anon {host}"],
            "redis": [f"redis-cli -h {host} -p {port} INFO"],
            "mongodb": [f"nmap -p {port} --script mongodb-info {host}"],
            "elasticsearch": [f"curl -s http://{host}:{port}/_cat/indices"],
            "docker": [f"curl -s http://{host}:{port}/version"],
            "kubelet": [f"curl -sk https://{host}:{port}/pods"],
            "winrm": [f"nmap -p {port} --script http-title {host}"],
            "telnet": [f"nmap -p {port} --script telnet-encryption {host}"],
            "mysql": [f"nmap -p {port} --script mysql-info,mysql-empty-password {host}"],
            "mssql": [f"nmap -p {port} --script ms-sql-info {host}"],
            "postgresql": [f"nmap -p {port} --script pgsql-brute {host}"],
            "snmp": [f"nmap -sU -p {port} --script snmp-info {host}"],
        }
        suggestions.extend(service_hints.get(svc, []))
        if svc in ("http", "http-alt", "https", "https-alt"):
            scheme = "https" if "https" in svc else "http"
            suggestions.append(f"nuclei -u {scheme}://{host}:{port}")

        # إزالة التكرار مع الحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
