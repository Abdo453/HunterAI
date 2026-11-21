---
name: "analyzing-network-flow-data-with-netflow"
description: "Parse NetFlow v9 and IPFIX records to detect volumetric anomalies, port"
---

# Analyzing Network Flow Data With Netflow

*Sourced from razor25000-cybersecurityskills*

# Analyzing Network Flow Data with Netflow


## When to Use

- When anomalous traffic patterns are detected and need structured packet-level investigation
- When a new network segment is deployed and needs security monitoring baseline configuration
- When an IDS or IPS alert fires and manual traffic analysis is required to confirm or dismiss
- When building firewall rules or network segmentation policies for a new environment
- When C2 beaconing or DNS tunneling suspicion needs validation against captured traffic
- When performing network forensics as part of a broader incident investigation

## Prerequisites

- Familiarity with network security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install netflow`
2. Collect NetFlow/IPFIX data from routers or use the built-in collector: `python -m netflow.collector -p 9995`
3. Parse captured flow data using `netflow.parse_packet()`.
4. Analyze flows for:
   - Port scanning: single source to many destinations on same port
   - Data exfiltration: high byte-count outbound flows to unusual destinations
   - C2 beaconing: periodic connections with consistent intervals
   - Volumetric anomalies: traffic spikes beyond baseline thresholds
5. Generate a prioritized findings report.

```bash
python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json
```

## Examples

### Parse NetFlow v9 Packet
```python
import netflow
data, _ = netflow.parse_packet(raw_bytes, templates={})
for flow in data.flows:
    print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR, flow.IN_BYTES)
```

