---
name: "analyzing-threat-landscape-with-misp"
description: "Analyze the threat landscape using MISP (Malware Information Sharing"
---

# Analyzing Threat Landscape With Misp

*Sourced from razor25000-cybersecurityskills*

# Analyzing Threat Landscape with MISP


## When to Use

- When a new threat actor or campaign is reported and you need rapid intelligence profiling
- When mapping your detection coverage against a specific APT group's TTPs in ATT&CK Navigator
- When a CISO requests a briefing on emerging threats targeting your sector
- When IOCs from an active incident need to be correlated with known threat actor infrastructure
- When building a threat model for a new system or business unit acquisition
- When updating your ATT&CK layer after a detection gap is identified during a purple team exercise

## Prerequisites

- Familiarity with threat intelligence concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install pymisp`
2. Configure MISP URL and API key.
3. Run the agent to generate threat landscape analysis:
   - Pull event statistics by threat level and date range
   - Analyze attribute type distributions (IP, domain, hash, URL)
   - Identify top MITRE ATT&CK techniques from event tags
   - Track threat actor activity via galaxy clusters
   - Generate temporal trend analysis of IOC submissions

```bash
python scripts/agent.py --misp-url https://misp.local --api-key YOUR_KEY --days 90 --output landscape_report.json
```

## Examples

### Threat Landscape Summary
```
Period: Last 90 days
Events analyzed: 1,247
Top threat level: High (43%)
Top attribute type: ip-dst (31%), domain (22%), sha256 (18%)
Top MITRE technique: T1566 Phishing (89 events)
Top threat actor: APT28 (34 events)
```

