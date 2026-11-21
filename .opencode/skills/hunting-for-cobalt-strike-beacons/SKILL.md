---
name: "hunting-for-cobalt-strike-beacons"
description: "Detect Cobalt Strike beacon network activity using default TLS certificate"
---

# Hunting For Cobalt Strike Beacons

*Sourced from razor25000-cybersecurityskills*

# Hunting for Cobalt Strike Beacons

## Overview

Cobalt Strike is the most prevalent command-and-control framework used by both red teams and threat actors. Beacon, its primary payload, communicates with team servers using configurable HTTP/HTTPS/DNS profiles that can mimic legitimate traffic. However, default configurations and behavioral patterns remain detectable through TLS certificate analysis (default serial 8BB00EE), JA3/JA3S fingerprinting, beacon interval jitter analysis, and HTTP malleable profile pattern matching. This skill covers building detection capabilities using Zeek network logs, Suricata IDS rules, and Python-based PCAP analysis to identify beacon callbacks in network traffic.


## When to Use

- When new threat intelligence describes TTPs not yet covered by existing detections
- When a hypothesis-driven hunt is initiated after a peer organization reports a breach
- When ATT&CK coverage analysis reveals a gap that needs proactive hunting before alerting is built
- When crown-jewel assets (domain controllers, backup servers) need targeted behavioral monitoring
- When MSSP or MDR service requires documented hunt procedures for client reporting
- When a red team exercise concludes and blue team needs to verify detection of TTPs used

## Prerequisites

- Zeek 6.0+ with JA3 and HASSH packages installed
- Suricata 7.0+ with Emerging Threats ruleset
- Python 3.9+ with scapy and dpkt libraries
- Network traffic captures (PCAP) or live Zeek logs
- RITA (Real Intelligence Threat Analytics) for beacon scoring
- Threat intelligence feeds with known Cobalt Strike IOCs

## Steps

### Step 1: TLS Certificate Analysis
Detect default Cobalt Strike certificates using JA3S fingerprints, certificate serial numbers, and JARM fingerprints in Zeek ssl.log.

### Step 2: Beacon Interval Analysis
Analyze connection timing patterns to identify regular callback intervals with configurable jitter, characteristic of beacon behavior.

### Step 3: HTTP Profile Detection
Match HTTP request patterns (URI paths, headers, user-agents) against known malleable C2 profiles.

### Step 4: Correlate and Score
Combine multiple indicators (TLS + timing + HTTP profile) into a composite beacon confidence score.

## Expected Output

JSON report containing detected beacon candidates with confidence scores, TLS fingerprints, timing analysis, HTTP profile matches, and recommended response actions.

