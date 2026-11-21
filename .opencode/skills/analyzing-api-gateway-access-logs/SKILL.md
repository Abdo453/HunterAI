---
name: "analyzing-api-gateway-access-logs"
description: "Parses API Gateway access logs (AWS API Gateway, Kong, Nginx) to detect"
---

# Analyzing Api Gateway Access Logs

*Sourced from razor25000-cybersecurityskills*

# Analyzing API Gateway Access Logs


## When to Use

- When a SIEM alert fires and you need a structured triage procedure to avoid false positive fatigue
- When building new detection content and need reference queries for this technique
- When security operations need to reduce mean-time-to-detect (MTTD) on a specific attack pattern
- When a new log source is onboarded and needs baseline correlation rules
- When reviewing SOC metrics and identifying detection gaps by ATT&CK tactic coverage
- When a purple team exercise reveals detection blind spots that require new rule development

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Parse API gateway access logs to identify attack patterns including broken object
level authorization (BOLA), excessive data exposure, and injection attempts.

```python
import pandas as pd

df = pd.read_json("api_gateway_logs.json", lines=True)
# Detect BOLA: same user accessing many different resource IDs
bola = df.groupby(["user_id", "endpoint"]).agg(
    unique_ids=("resource_id", "nunique")).reset_index()
suspicious = bola[bola["unique_ids"] > 50]
```

Key detection patterns:
1. BOLA/IDOR: sequential resource ID enumeration
2. Rate limit bypass via header manipulation
3. Credential scanning (401 surges from single source)
4. SQL/NoSQL injection in query parameters
5. Unusual HTTP methods (DELETE, PATCH) on read-only endpoints

## Examples

```python
# Detect 401 surges indicating credential scanning
auth_failures = df[df["status_code"] == 401]
scanner_ips = auth_failures.groupby("source_ip").size()
scanners = scanner_ips[scanner_ips > 100]
```

