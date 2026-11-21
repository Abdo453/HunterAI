---
name: "hunting-for-anomalous-powershell-execution"
description: "Hunt for malicious PowerShell activity by analyzing Script Block Logging"
---

# Hunting For Anomalous Powershell Execution

*Sourced from razor25000-cybersecurityskills*

# Hunting for Anomalous PowerShell Execution

## Overview

PowerShell Script Block Logging (Event ID 4104) records the full deobfuscated script text
executed on a Windows endpoint, making it the primary data source for hunting malicious
PowerShell. Combined with Module Logging (4103) and process creation events, analysts can
detect encoded commands, AMSI bypass patterns, download cradles, credential theft tools,
and fileless attack techniques even when the attacker uses obfuscation layers.


## When to Use

- When new threat intelligence describes TTPs not yet covered by existing detections
- When a hypothesis-driven hunt is initiated after a peer organization reports a breach
- When ATT&CK coverage analysis reveals a gap that needs proactive hunting before alerting is built
- When crown-jewel assets (domain controllers, backup servers) need targeted behavioral monitoring
- When MSSP or MDR service requires documented hunt procedures for client reporting
- When a red team exercise concludes and blue team needs to verify detection of TTPs used

## Prerequisites

- Windows Event Log exports (.evtx) from Microsoft-Windows-PowerShell/Operational
- Python 3.8+ with python-evtx and lxml libraries
- Script Block Logging enabled via Group Policy
- Understanding of common PowerShell attack techniques

## Steps

1. Parse EVTX files extracting Event 4104 script block text and metadata
2. Reassemble multi-part script blocks using ScriptBlock ID correlation
3. Scan script text for AMSI bypass indicators and obfuscation patterns
4. Detect encoded command execution and base64 payloads
5. Identify download cradles, credential dumping, and lateral movement commands
6. Score and prioritize findings by threat severity

## Expected Output

```json
{
  "total_events": 1247,
  "suspicious_events": 23,
  "amsi_bypass_attempts": 2,
  "encoded_commands": 8,
  "download_cradles": 5,
  "credential_access": 3
}
```

