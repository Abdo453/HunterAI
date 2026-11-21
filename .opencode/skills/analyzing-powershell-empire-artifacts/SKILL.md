---
name: "analyzing-powershell-empire-artifacts"
description: "Detect PowerShell Empire framework artifacts in Windows event logs by"
---

# Analyzing Powershell Empire Artifacts

*Sourced from razor25000-cybersecurityskills*

# Analyzing PowerShell Empire Artifacts

## Overview

PowerShell Empire is a post-exploitation framework consisting of listeners, stagers, and agents. Its artifacts leave detectable traces in Windows event logs, particularly PowerShell Script Block Logging (Event ID 4104) and Module Logging (Event ID 4103). This skill analyzes event logs for Empire's default launcher string (`powershell -noP -sta -w 1 -enc`), Base64 encoded payloads containing `System.Net.WebClient` and `FromBase64String`, known module invocations (Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation), and staging URL patterns.


## When to Use

- When an incident is declared and forensic evidence needs to be acquired and preserved immediately
- When legal or HR requests a forensic investigation of an endpoint or user account
- When malware is suspected on a system and disk or memory artifacts need to be collected
- When building a timeline of attacker activity during post-incident analysis
- When chain-of-custody documentation is required for potential legal proceedings
- When a live system cannot be immediately taken offline and volatile data must be captured first

## Prerequisites

- Python 3.9+ with access to Windows Event Log or exported EVTX files
- PowerShell Script Block Logging (Event ID 4104) enabled via Group Policy
- Module Logging (Event ID 4103) enabled for comprehensive coverage

## Key Detection Patterns

1. **Default launcher** — `powershell -noP -sta -w 1 -enc` followed by Base64 blob
2. **Stager indicators** — `System.Net.WebClient`, `DownloadData`, `DownloadString`, `FromBase64String`
3. **Module signatures** — Invoke-Mimikatz, Invoke-Kerberoast, Invoke-TokenManipulation, Invoke-PSInject, Invoke-DCOM
4. **User agent strings** — default Empire user agents in HTTP listener configuration
5. **Staging URLs** — `/login/process.php`, `/admin/get.php` and similar default URI patterns

## Output

JSON report with matched IOCs, decoded Base64 payloads, timeline of suspicious events, MITRE ATT&CK technique mappings, and severity scores.

