"""Service→Vulnerability routing rules (v1, rule-based, defensible).

Each rule maps an observed *service* (port / protocol / banner / version) to a
candidate exposure. Rules NEVER assert a confirmed vulnerability: the router
emits ``status="candidate"`` with ``evidence_level="E0"`` and a concrete
reproduction command. Only the network Evidence Court can promote a finding.

Rationale: an open port is an *attack surface*, not a vulnerability. Every rule
therefore ships an explicit verification step the agent must execute (and the
court must adjudicate) before anything is reported.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Pattern, Set


@dataclass
class VulnRule:
    rule_id: str
    vuln_class: str
    severity: str
    title: str
    description: str
    remediation: str
    reproduction: str  # .format(host=..., port=...)
    ports: Set[int] = field(default_factory=set)
    service_names: Set[str] = field(default_factory=set)
    protocols: Set[str] = field(default_factory=lambda: {"tcp"})
    cwe: Optional[str] = None
    references: List[str] = field(default_factory=list)
    version_pattern: Optional[Pattern] = None  # matched against product+version+banner

    def matches_port(self, port: int, protocol: str, service_name: Optional[str]) -> bool:
        if protocol.lower() not in {p.lower() for p in self.protocols}:
            return False
        if self.ports and port not in self.ports:
            return False
        if self.service_names:
            return (service_name or "").strip().lower() in self.service_names
        return True

    def matches_version(self, product: Optional[str], version: Optional[str], banner: Optional[str]) -> bool:
        if self.version_pattern is None:
            return True
        haystack = " ".join(x for x in (product, version, banner) if x)
        return bool(self.version_pattern.search(haystack))


# ── Curated rule set (network exposure v1) ───────────────────────────────────
NETWORK_RULES: List[VulnRule] = [
    VulnRule(
        rule_id="NET-TELNET-CLEARTEXT",
        vuln_class="CLEARTEXT_PROTOCOL",
        severity="HIGH",
        title="Telnet exposed (cleartext credentials)",
        description="Telnet transmits credentials and session data unencrypted and is a classic pivot for credential capture.",
        remediation="Disable Telnet; migrate to SSH (SFTP/SCP).",
        reproduction="nmap -p {port} --script telnet-encryption {host}",
        ports={23}, cwe="CWE-319",
    ),
    VulnRule(
        rule_id="NET-FTP-ANON",
        vuln_class="ANONYMOUS_ACCESS",
        severity="MEDIUM",
        title="FTP exposed (possible anonymous access)",
        description="FTP is cleartext and frequently allows anonymous login or weak credentials.",
        remediation="Disable anonymous FTP; require FTPS/SFTP.",
        reproduction="nmap -p {port} --script ftp-anon {host}",
        ports={21}, cwe="CWE-287",
    ),
    VulnRule(
        rule_id="NET-REDIS-NOAUTH",
        vuln_class="UNAUTHENTICATED_SERVICE",
        severity="HIGH",
        title="Redis exposed (possible unauthenticated access)",
        description="Redis bound to the network without authentication permits arbitrary key access and, in many builds, RCE via module loading.",
        remediation="Bind to loopback, enable requirepass/ACLs, and firewax the port.",
        reproduction="redis-cli -h {host} -p {port} INFO",
        ports={6379}, service_names={"redis"}, cwe="CWE-306",
    ),
    VulnRule(
        rule_id="NET-MONGO-NOAUTH",
        vuln_class="UNAUTHENTICATED_SERVICE",
        severity="HIGH",
        title="MongoDB exposed (possible unauthenticated access)",
        description="MongoDB without authentication exposes entire databases.",
        remediation="Enable authentication and bind to a private interface.",
        reproduction="nmap -p {port} --script mongodb-info {host}",
        ports={27017}, service_names={"mongodb"}, cwe="CWE-306",
    ),
    VulnRule(
        rule_id="NET-ELASTIC-OPEN",
        vuln_class="UNAUTHENTICATED_SERVICE",
        severity="HIGH",
        title="Elasticsearch exposed (possible open indices)",
        description="Elasticsearch without security exposes indices and cluster metadata.",
        remediation="Enable X-Pack security or place behind an authenticating gateway.",
        reproduction="curl -s http://{host}:{port}/_cat/indices",
        ports={9200}, service_names={"elasticsearch"}, cwe="CWE-306",
    ),
    VulnRule(
        rule_id="NET-DOCKER-API",
        vuln_class="UNAUTHENTICATED_SERVICE",
        severity="CRITICAL",
        title="Docker daemon API exposed (host compromise)",
        description="An unauthenticated Docker API allows creating privileged containers and full host takeover.",
        remediation="Never expose the Docker socket/API; require TLS mutual auth.",
        reproduction="curl -s http://{host}:{port}/version",
        ports={2375}, service_names={"docker"}, cwe="CWE-306",
    ),
    VulnRule(
        rule_id="NET-KUBELET-API",
        vuln_class="UNAUTHENTICATED_SERVICE",
        severity="HIGH",
        title="Kubelet API exposed",
        description="An exposed kubelet API can leak pod specs and, when anonymous auth is on, execute commands in pods.",
        remediation="Restrict kubelet to the control plane network and disable anonymous auth.",
        reproduction="curl -sk https://{host}:{port}/pods",
        ports={10250}, service_names={"kubelet"}, cwe="CWE-306",
    ),
    VulnRule(
        rule_id="NET-SMB-SIGNING",
        vuln_class="WEAK_CONFIGURATION",
        severity="MEDIUM",
        title="SMB exposed (signing / null-session check)",
        description="SMB without required signing enables relay attacks; null sessions may leak users and shares.",
        remediation="Require SMB signing and disable null sessions.",
        reproduction="nmap -p {port} --script smb-security-mode,smb-enum-shares {host}",
        ports={445}, service_names={"smb", "microsoft-ds", "netbios-ssn"}, cwe="CWE-287",
    ),
    VulnRule(
        rule_id="NET-LDAP-ANON",
        vuln_class="ANONYMOUS_ACCESS",
        severity="MEDIUM",
        title="LDAP exposed (anonymous bind check)",
        description="An LDAP service permitting anonymous bind leaks directory structure and can aid enumeration.",
        remediation="Disable anonymous binds and require LDAPS.",
        reproduction="nmap -p {port} --script ldap-rootdse {host}",
        ports={389}, service_names={"ldap"}, cwe="CWE-287",
    ),
    VulnRule(
        rule_id="NET-RDP-EXPOSED",
        vuln_class="EXPOSED_ADMIN_SERVICE",
        severity="MEDIUM",
        title="RDP exposed to the network",
        description="Exposed RDP is a high-value brute-force and BlueKeep-class target.",
        remediation="Restrict RDP via VPN/jump host, enforce NLA and MFA.",
        reproduction="nmap -p {port} --script rdp-enum-encryption {host}",
        ports={3389}, service_names={"rdp", "ms-wbt-server"}, cwe="CWE-284",
    ),
    VulnRule(
        rule_id="NET-VNC-EXPOSED",
        vuln_class="EXPOSED_ADMIN_SERVICE",
        severity="MEDIUM",
        title="VNC exposed (possible no/weak authentication)",
        description="VNC commonly ships without authentication or with weak passwords.",
        remediation="Tunnel VNC over SSH and enforce strong authentication.",
        reproduction="nmap -p {port} --script vnc-info,vnc-brute {host}",
        ports={5900}, service_names={"vnc"}, cwe="CWE-306",
    ),
    VulnRule(
        rule_id="NET-WINRM-EXPOSED",
        vuln_class="EXPOSED_ADMIN_SERVICE",
        severity="MEDIUM",
        title="WinRM exposed to the network",
        description="Exposed WinRM enables remote command execution given valid credentials.",
        remediation="Restrict WinRM to management networks; enforce HTTPS and MFA.",
        reproduction="nmap -p {port} --script http-title {host}",
        ports={5985, 5986}, service_names={"winrm", "wsman", "winrm-tls"}, cwe="CWE-284",
    ),
    VulnRule(
        rule_id="NET-RSYNC-ANON",
        vuln_class="ANONYMOUS_ACCESS",
        severity="MEDIUM",
        title="rsync exposed (anonymous module check)",
        description="rsync modules may be world-readable/writable (anonymous rsync).",
        remediation="Require authentication and restrict rsync modules.",
        reproduction="nmap -p {port} --script rsync-list-modules {host}",
        ports={873}, service_names={"rsync"}, cwe="CWE-287",
    ),
    VulnRule(
        rule_id="NET-NFS-EXPORT",
        vuln_class="EXPOSED_ADMIN_SERVICE",
        severity="MEDIUM",
        title="NFS exposed (world-readable exports)",
        description="NFS exports may be world-readable or permit root squash bypass.",
        remediation="Restrict exports by host and enable root_squash.",
        reproduction="showmount -e {host}",
        ports={2049}, service_names={"nfs"}, cwe="CWE-284",
    ),
    VulnRule(
        rule_id="NET-DB-EXPOSED",
        vuln_class="EXPOSED_DATABASE",
        severity="MEDIUM",
        title="Database service exposed to the network",
        description="A database port reachable from untrusted networks expands the brute-force and data-exfiltration surface.",
        remediation="Bind databases to private interfaces and restrict by firewall.",
        reproduction="nmap -p {port} --script {probe} {host}",
        ports={3306, 1433, 5432, 1521},
        service_names={"mysql", "mssql", "postgresql", "oracle"}, cwe="CWE-284",
    ),
    VulnRule(
        rule_id="NET-SNMP-PUBLIC",
        vuln_class="WEAK_CONFIGURATION",
        severity="MEDIUM",
        title="SNMP exposed (public/private community strings)",
        description="SNMP with default community strings leaks extensive system information.",
        remediation="Disable SNMPv1/v2c or rotate community strings; use SNMPv3.",
        reproduction="nmap -sU -p {port} --script snmp-info {host}",
        ports={161}, protocols={"udp"}, service_names={"snmp"}, cwe="CWE-521",
    ),
    # ── Version-based hints (still candidates; must be verified on the wire) ──
    VulnRule(
        rule_id="NET-VSftpd-BACKDOOR",
        vuln_class="KNOWN_CVE",
        severity="CRITICAL",
        title="vsftpd 2.3.4 backdoor (CVE-2011-2523)",
        description="The compromised vsftpd 2.3.4 build opens a backdoor shell on port 6200.",
        remediation="Upgrade vsftpd and reimage the host.",
        reproduction="nmap -p {port} --script ftp-vsftpd-backdoor {host}",
        version_pattern=re.compile(r"vsftpd\s*2\.3\.4", re.IGNORECASE), cwe="CWE-506",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
    ),
    VulnRule(
        rule_id="NET-OPENSSH-ENUM",
        vuln_class="KNOWN_CVE",
        severity="MEDIUM",
        title="OpenSSH < 7.7 user enumeration (CVE-2018-15473)",
        description="Older OpenSSH allows username enumeration via malformed authentication requests.",
        remediation="Upgrade OpenSSH to >= 7.7.",
        reproduction="nmap -p {port} --script ssh-auth-methods --script-args='ssh.user=root' {host}",
        version_pattern=re.compile(r"OpenSSH[_ ]([0-6]\.|7\.[0-6])", re.IGNORECASE), cwe="CWE-200",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
    ),
    VulnRule(
        rule_id="NET-APACHE-TRAVERSAL",
        vuln_class="KNOWN_CVE",
        severity="CRITICAL",
        title="Apache 2.4.49/2.4.50 path traversal + RCE (CVE-2021-41773/42013)",
        description="Specific Apache httpd builds allow path traversal and, with mod_cgi, remote code execution.",
        remediation="Upgrade Apache httpd to >= 2.4.51.",
        reproduction="curl -s --path-as-is http://{host}:{port}/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        version_pattern=re.compile(r"Apache/2\.4\.(49|50)", re.IGNORECASE), cwe="CWE-22",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    ),
]


# reproduction placeholders a rule may reference beyond host/port
PROBE_BY_SERVICE = {
    "mysql": "mysql-info,mysql-empty-password",
    "mssql": "ms-sql-info",
    "postgresql": "pgsql-brute",
    "oracle": "oracle-tns-version",
}
