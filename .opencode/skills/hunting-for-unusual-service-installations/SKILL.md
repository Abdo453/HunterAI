---
name: "hunting-for-unusual-service-installations"
description: "Detect suspicious Windows service installations (MITRE ATT&CK T1543.003)"
---

# Hunting For Unusual Service Installations

*Sourced from razor25000-cybersecurityskills*

# Hunting for Unusual Service Installations

## Overview

Attackers frequently install malicious Windows services for persistence and privilege escalation (MITRE ATT&CK T1543.003 — Create or Modify System Process: Windows Service). Event ID 7045 in the System event log records every new service installation. This skill parses .evtx log files to extract service installation events, flags suspicious binary paths (temp directories, PowerShell, cmd.exe, encoded commands), and correlates with known attack patterns.


## When to Use

- When new threat intelligence describes TTPs not yet covered by existing detections
- When a hypothesis-driven hunt is initiated after a peer organization reports a breach
- When ATT&CK coverage analysis reveals a gap that needs proactive hunting before alerting is built
- When crown-jewel assets (domain controllers, backup servers) need targeted behavioral monitoring
- When MSSP or MDR service requires documented hunt procedures for client reporting
- When a red team exercise concludes and blue team needs to verify detection of TTPs used

## Prerequisites

- Python 3.9+ with `python-evtx`, `lxml`
- Windows System event log (.evtx) files
- Access to live System event log (optional, for real-time monitoring)
- Sysmon logs for enhanced process tracking (optional)

## Steps

1. Parse System.evtx for Event ID 7045 (new service installed)
2. Extract service name, binary path, service type, and account
3. Flag services with suspicious binary paths (temp dirs, encoded commands)
4. Detect PowerShell-based service creation patterns
5. Identify services running as LocalSystem with unusual paths
6. Cross-reference with known legitimate service baselines
7. Generate threat hunting report with MITRE ATT&CK T1543.003 mapping

## Expected Output

- JSON report listing all new service installations with risk scores, suspicious indicators, and remediation recommendations
- Timeline of service installation events with binary path analysis

