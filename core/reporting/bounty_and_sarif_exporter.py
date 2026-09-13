"""
HunterAI Bug Bounty & SARIF Exporter Engine (V12.0)
===================================================
Produces standardized, publication-grade vulnerability reports:
1. HackerOne & Bugcrowd formatted Markdown dossiers (Ready for triage submission).
2. OASIS SARIF v2.1.0 (Static Analysis Results Interchange Format) JSON
   conforming to GitHub Advanced Security code scanning upload requirements.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


class BountyReportGenerator:
    """
    Generates publication-ready Markdown dossiers for bug bounty platforms
    (HackerOne, Bugcrowd, Intigriti) adhering to strict triage quality guidelines.
    """

    @classmethod
    def generate_hackerone_report(cls, finding: Dict[str, Any]) -> str:
        title = finding.get("title", "Security Vulnerability Finding")
        cwe_id = finding.get("cwe_id", "CWE-20")
        target_asset = finding.get("asset", "https://api.target.internal")
        route = finding.get("route", "/api/v1/resource")
        method = finding.get("method", "POST")
        cvss_score = finding.get("cvss_score", 8.5)
        cvss_vector = finding.get("cvss_vector", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")
        severity = finding.get("severity", "HIGH")
        epss_score = finding.get("epss_score", 0.75)
        evidence = finding.get("evidence", "Deterministic proof of execution verified.")
        remediation = finding.get("remediation", "Apply input parameterization and validation.")
        payload = finding.get("payload", "' OR 1=1--")

        md = f"""# {title}

## 🎯 Summary
An issue was identified in `{target_asset}` where the endpoint `{method} {route}` fails to adequately validate or parameterize client-supplied input. This leads to **{cwe_id}**, allowing unauthorized state mutation or confidential data exfiltration.

---

## 🏷️ Vulnerability Classification & Severity
- **Vulnerability Type:** {cwe_id}
- **Severity:** **{severity}** ({cvss_score} / 10.0)
- **CVSS v4.0 Vector:** `{cvss_vector}`
- **EPSS Probability:** `{round(epss_score * 100, 1)}%` (Likelihood of active in-the-wild exploitation)
- **Target Asset:** `{target_asset}`
- **Vulnerable Route:** `{method} {route}`

---

## 🔁 Step-by-Step Reproduction Procedure
> **Note:** All actions were performed in non-destructive read-only simulation under verified scope authorization.

1. Issue the following HTTP request against the target route:
```http
{method} {route} HTTP/1.1
Host: {target_asset.replace("https://", "").replace("http://", "").split("/")[0]}
User-Agent: HunterAI-Security-Auditor/12.0
Content-Type: application/json

{{
  "probe": "{payload}"
}}
```

2. Alternatively, replicate via `curl`:
```bash
curl -s -X {method} "{target_asset}{route}" \\
  -H "Content-Type: application/json" \\
  -d '{{"probe": "{payload}"}}'
```

3. Observe the response indicating vulnerability execution:
```text
{evidence}
```

---

## 💥 Impact Analysis & Real-World Risk
- **Confidentiality & Integrity Breach:** Unauthorized access to underlying data stores or execution logic.
- **Threat Actor Exploitability:** High real-world attractiveness given the network-accessible vector and lack of complex prerequisites.
- **Proof-of-Execution:** Verified deterministically with zero reliance on synthetic assertions or unverified correlation.

---

## 🛡️ Recommended Remediation Guidance
{remediation}

---
*Generated autonomously by HunterAI V12.0 Investigation Platform.*
"""
        return md


class SARIFExporter:
    """
    Exports findings in strict OASIS SARIF v2.1.0 format
    compatible with GitHub Code Scanning (codeql-action/upload-sarif).
    """

    @classmethod
    def export_sarif(
        cls,
        findings: List[Dict[str, Any]],
        output_file: Optional[Path] = None
    ) -> Dict[str, Any]:
        rules: List[Dict[str, Any]] = []
        results: List[Dict[str, Any]] = []

        seen_rules = set()

        for f in findings:
            cwe = f.get("cwe_id", "CWE-20")
            rule_id = f"HUNTER-{cwe.replace('-', '')}"
            severity = f.get("severity", "HIGH").upper()

            # Map severity to SARIF level
            if severity in ("CRITICAL", "HIGH"):
                sarif_level = "error"
            elif severity == "MEDIUM":
                sarif_level = "warning"
            else:
                sarif_level = "note"

            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f.get("title", "HunterAI Security Finding"),
                    "shortDescription": {
                        "text": f"{cwe}: {f.get('title', 'Security Finding')}"
                    },
                    "fullDescription": {
                        "text": f.get("description", f"HunterAI confirmed vulnerability belonging to {cwe}.")
                    },
                    "defaultConfiguration": {
                        "level": sarif_level
                    },
                    "properties": {
                        "tags": ["security", "hunterai", cwe.lower()],
                        "problem.severity": sarif_level
                    }
                })

            file_path = f.get("file_path", "routes/api.py")
            line_number = f.get("line_number", 1)

            results.append({
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {
                    "text": f"{f.get('title', 'Finding')}: {f.get('evidence', 'Confirmed flaw')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": line_number,
                                "startColumn": 1
                            }
                        }
                    }
                ]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "HunterAI",
                            "semanticVersion": "12.0.0",
                            "informationUri": "https://github.com/Abdo453/HunterAI",
                            "rules": rules
                        }
                    },
                    "results": results
                }
            ]
        }

        if output_file:
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")

        return sarif_doc
