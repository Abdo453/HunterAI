---
name: "analyzing-kubernetes-audit-logs"
description: "Parses Kubernetes API server audit logs (JSON lines) to detect exec-into-pod,"
---

# Analyzing Kubernetes Audit Logs

*Sourced from razor25000-cybersecurityskills*

# Analyzing Kubernetes Audit Logs


## When to Use

- When a container image is about to be deployed to production and needs security scanning
- When a Kubernetes cluster audit is requested before a compliance review
- When a runtime alert from Falco or Sysdig indicates suspicious container behavior
- When investigating a compromised container and needing to scope the blast radius
- When setting up RBAC policies for a new cluster namespace or service account
- When a supply chain security review requires validating container image provenance

## Prerequisites

- Familiarity with container security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Parse Kubernetes audit log files (JSON lines format) to detect security-relevant
events including unauthorized access, privilege escalation, and data exfiltration.

```python
import json

with open("/var/log/kubernetes/audit.log") as f:
    for line in f:
        event = json.loads(line)
        verb = event.get("verb")
        resource = event.get("objectRef", {}).get("resource")
        user = event.get("user", {}).get("username")
        if verb == "create" and resource == "pods/exec":
            print(f"Pod exec by {user}")
```

Key events to detect:
1. pods/exec and pods/attach (shell into containers)
2. secrets access (get/list/watch)
3. clusterrolebindings creation (RBAC escalation)
4. Privileged pod creation
5. Anonymous or system:unauthenticated access

## Examples

```python
# Detect secret enumeration
if verb in ("get", "list") and resource == "secrets":
    print(f"Secret access: {user} -> {event['objectRef'].get('name')}")
```

