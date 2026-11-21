---
name: "sysmon-process-creation-analysis"
description: ">"
---

# Sysmon Process Creation Analysis

*Sourced from akashrpatil-awesome-offensive-security-skills*

# Sysmon Process Creation Analysis (Event ID 1)

## When to Use
- During proactive threat hunting or reactive incident response to trace the execution flow of malware, scripts, or attacker activity.
- To detect the use of LOLBins (like PowerShell, cmd, certutil) and identify obfuscated command-line arguments indicating malicious intent.


## Prerequisites
- Forensic image or live access to the affected system(s)
- Forensic workstation with analysis tools (Autopsy, Volatility, Timeline Explorer)
- Chain of custody documentation initiated for evidence handling
- Write-blocker for disk forensics or memory acquisition tool (e.g., DumpIt, WinPmem)

## Workflow

### Phase 1: Understanding Event ID 1 Fields

```text
# Concept: Sysmon Event ID 1 ```

### Phase 2: Hunting for Suspicious Parent-Child Relationships

```powershell
# Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { 
  $_.Id -eq 1 -and $_.Message -match "ParentImage:.*winword.exe" -and $_.Message -match "Image:.*(?:powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe)" 
} | Select-Object TimeCreated, Message | Format-List
```

### Phase 3: Detecting Command-Line Obfuscation and Encoding

```splunk
# index=sysmon EventCode=1 (CommandLine="*-e*" OR CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*") Image="*\\powershell.exe"
| table _time, User, ParentImage, Image, CommandLine
```

### Phase 4: Hunting for Known LOLBins (Living Off The Land)

```spl
# index=sysmon EventCode=1 (Image="*\\certutil.exe" AND (CommandLine="*-urlcache*" OR CommandLine="*-f*" OR CommandLine="*-split*"))
| stats count by CommandLine, User, Computer
```

#### Decision Point 🔀
```mermaid
flowchart TD
    A[Analyze Event ] --> B{Suspicious Indicator? ]}
    B -->|Yes| C[Investigate Context ]
    B -->|No| D[Log as Benign ]
    C --> E[Extract Artifacts ]
```

## 🔵 Blue Team Detection & Defense
- **Filter Tuning**: **Contextual Baselines**: - **Correlation Rules**: Key Concepts
| Concept | Description |
|---------|-------------|
## Output Format
```
Sysmon Process Creation Analysis — Assessment Report
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
- Microsoft: [Sysmon Setup and Configuration](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- JPCERT: [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

