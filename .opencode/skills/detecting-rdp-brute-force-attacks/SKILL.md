---
name: "detecting-rdp-brute-force-attacks"
description: "Detect RDP brute force attacks by analyzing Windows Security Event Logs"
---

# Detecting Rdp Brute Force Attacks

*Sourced from razor25000-cybersecurityskills*

# Detecting RDP Brute Force Attacks

## Overview

RDP brute force attacks target Windows Remote Desktop Protocol services by attempting rapid credential guessing against exposed RDP endpoints. Detection relies on analyzing Windows Security Event Logs for Event ID 4625 (failed logon with Logon Type 10 or 3) and correlating with Event ID 4624 (successful logon) to identify compromised accounts. This skill covers parsing EVTX files with python-evtx, identifying attack patterns through source IP frequency analysis, detecting NLA bypass attempts, and generating actionable detection reports.


## When to Use

- When a SIEM alert fires and you need a structured triage procedure to avoid false positive fatigue
- When building new detection content and need reference queries for this technique
- When security operations need to reduce mean-time-to-detect (MTTD) on a specific attack pattern
- When a new log source is onboarded and needs baseline correlation rules
- When reviewing SOC metrics and identifying detection gaps by ATT&CK tactic coverage
- When a purple team exercise reveals detection blind spots that require new rule development

## Prerequisites

- Python 3.9+ with `python-evtx`, `lxml` libraries
- Windows Security EVTX log files (exported from Event Viewer or collected via WEF)
- Understanding of Windows authentication Event IDs (4624, 4625, 4776)
- Familiarity with RDP Logon Types (Type 3 for NLA, Type 10 for RemoteInteractive)

## Steps

### Step 1: Export Security Event Logs
Export Windows Security logs to EVTX format using Event Viewer or wevtutil:
```
wevtutil epl Security C:\logs\security.evtx
```

### Step 2: Parse Failed Logon Events
Use python-evtx to parse Event ID 4625 entries, extracting source IP, target username, failure reason (Sub Status), and Logon Type fields.

### Step 3: Analyze Attack Patterns
Identify brute force patterns by:
- Counting failed logons per source IP within time windows
- Detecting username spray attacks (many usernames from one IP)
- Correlating 4625 failures with subsequent 4624 success from same IP

### Step 4: Generate Detection Report
Produce a JSON report with top attacking IPs, targeted accounts, time-based analysis, and compromise indicators.

## Expected Output

JSON report containing:
- Total failed logon events and unique source IPs
- Top attacking IPs ranked by failure count
- Targeted usernames and failure sub-status codes
- Successful logons following brute force attempts (potential compromises)
- Time-series analysis of attack intensity

