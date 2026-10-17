"""ADEnumPlanner — turns an ADGraph into an ordered enumeration plan.

Two outputs, both deterministic:

* :meth:`ADEnumPlanner.plan` → candidate :class:`NetworkFinding` objects that
  describe *exposures worth verifying* (Kerberoastable accounts, AS-REP roastable
  accounts, unconstrained delegation, writable shares, anonymous LDAP, weak
  policy, SMBv1 ...). Every one is ``status="candidate"`` / ``evidence_level="E0"``
  — the AD Evidence Court is the only thing that may confirm them.
* :meth:`ADEnumPlanner.tasks` → an ordered, tool-level to-do list the agent can
  execute (enum4linux-ng, netexec smb/ldap, impacket getuserspns/getnpusers, ...).

The planner never assumes credentials; tasks that need them are flagged.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.ad_model.graph import ADGraph
from core.network_model import NetworkFinding

log = logging.getLogger("ad_model.planner")

_SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}


@dataclass
class ADEnumTask:
    """One ordered enumeration step suggested by the planner."""

    phase: str
    tool: str
    target: str
    command: str
    rationale: str
    requires_credentials: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "phase": self.phase,
            "tool": self.tool,
            "target": self.target,
            "command": self.command,
            "rationale": self.rationale,
            "requires_credentials": self.requires_credentials,
        }


_PHASE_ORDER = {
    "fingerprint": 0,
    "anonymous-enum": 1,
    "authenticated-enum": 2,
    "privilege-escalation": 3,
    "credential-access": 4,
    "lateral-movement": 5,
}


class ADEnumPlanner:
    """Deterministic AD enumeration planner (Phase 2)."""

    def plan(self, graph: ADGraph) -> List[NetworkFinding]:
        findings: List[NetworkFinding] = []
        domain = self._primary_domain(graph)
        dc = graph.primary_dc()
        dc_host = (dc.address or dc.host) if dc else ""

        # 0. Baseline: a Domain Controller is present → AD enumeration is the next step.
        if dc:
            findings.append(self._finding(
                title=f"Domain Controller discovered ({dc_host})",
                host=dc_host, vuln_class="AD_DC_DISCOVERED", severity="INFO",
                description="Kerberos/LDAP services indicate an Active Directory domain "
                            "controller; authenticated enumeration is the next step.",
                reproduction=f"enum4linux-ng -A {dc_host}",
                remediation="N/A — informational attack-surface observation.",
            ))

        # 1. Kerberoastable service accounts.
        kerb = graph.kerberoastable(domain)
        if kerb:
            findings.append(self._finding(
                title=f"Kerberoastable service accounts ({len(kerb)})",
                host=dc_host, vuln_class="KERBEROASTABLE_ACCOUNT", severity="HIGH",
                description=(
                    "User accounts with registered SPNs can have their TGS-REP "
                    "requested and cracked offline. Accounts: "
                    + ", ".join(p.sam_account_name or p.name for p in kerb[:10])
                ),
                reproduction=(
                    f"impacket-GetUserSPNs -request -dc-ip {dc_host} "
                    f"{domain}/<user>:<pass>"
                ),
                remediation="Use gMSA / long (>25 char) managed passwords for SPN accounts.",
                cwe="CWE-522",
                evidence_ids=[p.record_id for p in kerb],
            ))

        # 2. AS-REP roastable accounts (no pre-auth).
        asrep = graph.asreproastable(domain)
        if asrep:
            findings.append(self._finding(
                title=f"AS-REP roastable accounts ({len(asrep)})",
                host=dc_host, vuln_class="ASREP_ROASTABLE_ACCOUNT", severity="HIGH",
                description=(
                    "Accounts with 'Do not require Kerberos pre-authentication' "
                    "leak an AS-REP hash crackable offline without credentials. "
                    "Accounts: " + ", ".join(p.sam_account_name or p.name for p in asrep[:10])
                ),
                reproduction=(
                    f"impacket-GetNPUsers {domain}/ -no-pass -dc-ip {dc_host} "
                    "-usersfile users.txt"
                ),
                remediation="Re-enable Kerberos pre-authentication; rotate those passwords.",
                cwe="CWE-522",
                evidence_ids=[p.record_id for p in asrep],
            ))

        # 3. Unconstrained delegation.
        deleg = graph.unconstrained_delegation(domain)
        if deleg:
            findings.append(self._finding(
                title=f"Unconstrained Kerberos delegation ({len(deleg)})",
                host=dc_host, vuln_class="UNCONSTRAINED_DELEGATION", severity="HIGH",
                description=(
                    "Principals trusted for unconstrained delegation can capture "
                    "TGTs of any user authenticating to them (PrinterBug/PetitPotam). "
                    "Principals: " + ", ".join(p.sam_account_name or p.name for p in deleg[:10])
                ),
                reproduction=(
                    f"impacket-findDelegation {domain}/<user>:<pass> -dc-ip {dc_host} "
                    "  # then coerce via PrinterBug/PetitPotam"
                ),
                remediation="Replace unconstrained delegation with constrained/RBCD; "
                            "mark sensitive accounts 'not delegated'.",
                cwe="CWE-269",
                evidence_ids=[p.record_id for p in deleg],
            ))

        # 4. Anonymous SMB shares.
        anon = graph.anonymous_shares()
        if anon:
            findings.append(self._finding(
                title=f"Anonymous SMB access ({len(anon)} share(s))",
                host=anon[0].host, vuln_class="ANONYMOUS_SMB_ACCESS", severity="MEDIUM",
                description="SMB shares reachable without authentication: "
                            + ", ".join(s.name for s in anon[:10]),
                reproduction=f"smbclient -N -L //{anon[0].host}",
                remediation="Disable anonymous/null-session access on the server.",
                cwe="CWE-287",
                evidence_ids=[s.record_id for s in anon],
            ))

        # 5. Writable shares (writing is a distinct risk from anonymous read).
        writable = graph.writable_shares()
        if writable:
            findings.append(self._finding(
                title=f"Writable SMB shares ({len(writable)})",
                host=writable[0].host, vuln_class="WRITABLE_SHARE", severity="MEDIUM",
                description="Shares permitting write access may allow payload staging "
                            "or shortcut/SCF poisoning. Shares: "
                            + ", ".join(s.name for s in writable[:10]),
                reproduction=f"smbclient //{writable[0].host}/{writable[0].name} "
                             "-c 'put test.txt'",
                remediation="Restrict write permissions to least privilege.",
                cwe="CWE-732",
                evidence_ids=[s.record_id for s in writable],
            ))

        # 6. SMB signing disabled on a DC (relay risk).
        signing_off = [d for d in graph.domain_controllers() if d.smb_signing is False]
        if signing_off:
            findings.append(self._finding(
                title="SMB signing disabled on Domain Controller",
                host=signing_off[0].address or signing_off[0].host,
                vuln_class="SMB_SIGNING_DISABLED", severity="MEDIUM",
                description="Without required SMB signing, NTLM relay to the DC is viable.",
                reproduction=f"netexec smb {signing_off[0].address or signing_off[0].host}",
                remediation="Require SMB signing via GPO on all servers/DCs.",
                cwe="CWE-345",
            ))

        # 7. SMBv1 enabled (EternalBlue-class surface).
        smbv1 = [d for d in graph.domain_controllers() if d.smbv1_enabled is True]
        if smbv1:
            findings.append(self._finding(
                title="SMBv1 enabled on Domain Controller",
                host=smbv1[0].address or smbv1[0].host,
                vuln_class="SMBV1_ENABLED", severity="HIGH",
                description="Legacy SMBv1 exposes the host to EternalBlue-class exploits and relay.",
                reproduction=f"nmap -p 445 --script smb-vuln-ms17-010 {smbv1[0].address or smbv1[0].host}",
                remediation="Disable SMBv1 everywhere (it is deprecated and unsafe).",
                cwe="CWE-477",
            ))

        # 8. Weak domain password policy.
        dom = graph.get_domain(domain) if domain else None
        if dom and self._weak_password_policy(dom.password_policy):
            findings.append(self._finding(
                title="Weak domain password policy",
                host=dc_host, vuln_class="WEAK_PASSWORD_POLICY", severity="MEDIUM",
                description=f"Observed policy values suggest weak enforcement: {dom.password_policy}",
                reproduction=f"netexec smb {dc_host} --pass-pol",
                remediation="Enforce >=14 char minimum, lockout threshold, and history.",
                cwe="CWE-521",
            ))

        # 9. Machine account quota 0 (RBCD deployability note).
        if dom and dom.machine_account_quota == 0:
            findings.append(self._finding(
                title="Domain machine account quota is 0",
                host=dc_host, vuln_class="MACHINE_ACCOUNT_QUOTA_ZERO", severity="LOW",
                description="Non-admins cannot join computers; RBCD via machine account "
                            "creation is not directly available (informational).",
                reproduction=f"netexec ldap {dc_host} -u <user> -p <pass> -M maq",
                remediation="Intentional in hardened environments; verify against policy.",
            ))

        findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)
        return findings

    def tasks(self, graph: ADGraph) -> List[ADEnumTask]:
        tasks: List[ADEnumTask] = []
        domain = self._primary_domain(graph)
        dc = graph.primary_dc()
        dc_host = (dc.address or dc.host) if dc else ""

        if dc_host:
            tasks.append(ADEnumTask(
                phase="fingerprint", tool="enum4linux-ng", target=dc_host,
                command=f"enum4linux-ng -A {dc_host}",
                rationale="Baseline SMB/RPC/OS enumeration of the DC.",
            ))
            tasks.append(ADEnumTask(
                phase="anonymous-enum", tool="netexec", target=dc_host,
                command=f"netexec smb {dc_host} --shares --users --pass-pol",
                rationale="Null-session share/user/policy enumeration.",
            ))
            if domain:
                tasks.append(ADEnumTask(
                    phase="anonymous-enum", tool="netexec", target=dc_host,
                    command=f"netexec ldap {dc_host} -u '' -p '' --query '(&(objectClass=user))'",
                    rationale="Test anonymous LDAP bind and directory readability.",
                ))
                tasks.append(ADEnumTask(
                    phase="authenticated-enum", tool="netexec", target=dc_host,
                    command=f"netexec smb {dc_host} -u <user> -p <pass> --groups --loggedon-users",
                    rationale="Authenticated enumeration after first credential.",
                    requires_credentials=True,
                ))
                if graph.kerberoastable(domain):
                    tasks.append(ADEnumTask(
                        phase="credential-access", tool="impacket", target=dc_host,
                        command=f"impacket-GetUserSPNs -request -dc-ip {dc_host} {domain}/<user>:<pass>",
                        rationale="Request TGS-REP for SPN accounts and crack offline.",
                        requires_credentials=True,
                    ))
                if graph.asreproastable(domain):
                    tasks.append(ADEnumTask(
                        phase="credential-access", tool="impacket", target=dc_host,
                        command=f"impacket-GetNPUsers {domain}/ -no-pass -dc-ip {dc_host} -usersfile users.txt",
                        rationale="AS-REP roast accounts without pre-auth (no creds needed).",
                        requires_credentials=False,
                    ))
                tasks.append(ADEnumTask(
                    phase="privilege-escalation", tool="bloodhound", target=dc_host,
                    command=f"bloodhound-python -d {domain} -ns {dc_host} -u <user> -p <pass> -c All",
                    rationale="Collect ACL/relationship data to find escalation paths.",
                    requires_credentials=True,
                ))

        tasks.sort(key=lambda t: _PHASE_ORDER.get(t.phase, 99))
        return tasks

    # ── helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _primary_domain(graph: ADGraph) -> Optional[str]:
        for dom in graph.to_dict().get("domains", []):
            if dom.get("domain"):
                return dom["domain"]
        dc = graph.primary_dc()
        return dc.domain if dc else None

    @staticmethod
    def _weak_password_policy(policy: Dict[str, Any]) -> bool:
        if not policy:
            return False
        min_len = policy.get("min_password_length") or policy.get("minimum_password_length")
        lockout = policy.get("lockout_threshold")
        weak = False
        if isinstance(min_len, int) and min_len < 8:
            weak = True
        if isinstance(lockout, int) and lockout == 0:
            weak = True
        return weak

    @staticmethod
    def _finding(
        title: str,
        host: str,
        vuln_class: str,
        severity: str,
        description: str,
        reproduction: str,
        remediation: str,
        cwe: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
    ) -> NetworkFinding:
        return NetworkFinding(
            title=title,
            host=host,
            port=None,
            service_name="active-directory",
            vuln_class=vuln_class,
            severity=severity,
            confidence=0.5,  # observation-level; never a confirmation
            evidence_level="E0",
            status="candidate",
            description=description,
            reproduction_command=reproduction,
            remediation=remediation,
            cwe=cwe,
            evidence_ids=list(evidence_ids or []),
        )


def plan_from_host_graph(host_graph: Any) -> List[NetworkFinding]:
    """Convenience: project a HostGraph into AD and plan (candidates only)."""
    ad_graph = ADGraph.from_host_graph(host_graph)
    return ADEnumPlanner().plan(ad_graph)
