---
name: "detecting-pass-the-ticket-attacks"
description: "Detect Kerberos Pass-the-Ticket (PtT) attacks by analyzing Windows Event"
---

# Detecting Pass The Ticket Attacks

*Sourced from razor25000-cybersecurityskills*

# Detecting Pass-the-Ticket Attacks

## Overview

Pass-the-Ticket (PtT) is a credential theft technique (MITRE ATT&CK T1550.003) where adversaries steal Kerberos tickets (TGT or TGS) from one system and replay them on another to authenticate without knowing the user's password. This skill teaches detection of PtT attacks by correlating Windows Security Event IDs 4768 (TGT request), 4769 (TGS request), and 4771 (pre-authentication failure) for anomalies such as ticket reuse across different hosts, RC4 encryption downgrades, and unusual service ticket request volumes.


## When to Use

- When a privilege escalation alert fires and you need to trace misconfigured ACLs or group memberships
- When onboarding a new Active Directory environment and running a baseline security audit
- When a red team engagement reveals AD attack paths that require detection coverage
- When investigating a compromised account's lateral movement potential across the domain
- When preparing a BloodHound analysis and needing structured remediation steps for findings
- When validating that GPO and OU permissions follow least-privilege principles post-hardening

## Prerequisites

- Windows Domain Controller with advanced audit policy enabled (Audit Kerberos Authentication Service, Audit Kerberos Service Ticket Operations)
- Splunk or Elastic SIEM ingesting Windows Security event logs
- Sysmon deployed on endpoints for supplementary process telemetry
- Python 3.8+ with `requests` library

## Steps

1. Enable Kerberos audit logging on Domain Controllers via Group Policy
2. Forward Event IDs 4768, 4769, and 4771 to SIEM platform
3. Deploy detection rules for RC4 encryption downgrade (TicketEncryptionType 0x17)
4. Create correlation rule for ticket reuse across multiple source IPs
5. Build baseline of normal TGS request volume per user/host
6. Alert on standard deviation anomalies in ticket request patterns
7. Investigate flagged events with enrichment from Active Directory

## Expected Output

JSON report containing detected PtT indicators including anomalous ticket requests, RC4 downgrades, cross-host ticket reuse events, and risk-scored users with MITRE ATT&CK technique mapping.

