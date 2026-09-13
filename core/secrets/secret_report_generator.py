"""
HunterAI Secret Artifact Storage & Markdown Report Generator
=============================================================
Manages structured artifact persistence for discovered secret leaks:
artifacts/secrets/
├── discovered.jsonl
├── candidates/
├── confirmed/
├── false_positives/
└── reports/
    └── SECRET-XXXXX.md
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.secrets.secret_hunter_agent import SecretCandidate, SecretLifecycleState


class SecretReportGenerator:
    """Exports structured JSONL and individual Markdown audit reports for leaked secrets"""

    def __init__(self, base_output_dir: Optional[Path] = None):
        self.base_dir = base_output_dir or Path("artifacts/secrets")
        self.candidates_dir = self.base_dir / "candidates"
        self.confirmed_dir = self.base_dir / "confirmed"
        self.false_positives_dir = self.base_dir / "false_positives"
        self.reports_dir = self.base_dir / "reports"
        self.jsonl_path = self.base_dir / "discovered.jsonl"
        self._ensure_directories()

    def _ensure_directories(self):
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.candidates_dir.mkdir(parents=True, exist_ok=True)
        self.confirmed_dir.mkdir(parents=True, exist_ok=True)
        self.false_positives_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def persist_candidate(self, candidate: SecretCandidate) -> Path:
        """Saves candidate JSON record into appropriate lifecycle folder and appends to discovered.jsonl"""
        # Append to discovered.jsonl
        with open(self.jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(candidate.to_dict()) + "\n")

        # Select folder based on state
        if candidate.lifecycle_state == SecretLifecycleState.CONFIRMED:
            target_folder = self.confirmed_dir
        elif candidate.lifecycle_state == SecretLifecycleState.FALSE_POSITIVE:
            target_folder = self.false_positives_dir
        else:
            target_folder = self.candidates_dir

        json_file = target_folder / f"{candidate.candidate_id}.json"
        json_file.write_text(json.dumps(candidate.to_dict(), indent=2), encoding="utf-8")

        # Generate companion Markdown report
        self.generate_markdown_report(candidate)
        return json_file

    def generate_markdown_report(self, candidate: SecretCandidate) -> Path:
        """Generates comprehensive developer/auditor Markdown report"""
        report_file = self.reports_dir / f"{candidate.candidate_id}.md"

        evidence_md = "\n".join(f"- {ev}" for ev in candidate.evidence_chain)
        endpoints_md = "\n".join(f"- `{ep}`" for ep in candidate.related_endpoints) if candidate.related_endpoints else "- *No associated endpoints directly extracted.*"

        # Impact assessment formulation
        impact_narrative = (
            f"Unauthorized exposure of {candidate.provider} credential `{candidate.masked_value}` enables "
            f"privilege escalation, data exfiltration, and lateral movement against associated cloud and API assets."
        )

        md_content = f"""# {candidate.candidate_id}

**Type:** {candidate.secret_type}  
**Source:** `{candidate.source_origin}`  
**Location:** `{candidate.location}`  
**Masked Secret:** `{candidate.masked_value}`  
**Provider:** {candidate.provider}  
**Confidence:** {int(candidate.confidence_score * 100)}% ({candidate.lifecycle_state.value})  
**SHA-256 Fingerprint:** `{candidate.raw_fingerprint}`

---

## 🔍 Evidence Chain
{evidence_md}

---

## 📜 Code Context
```text
{candidate.surrounding_context}
```

---

## 🌐 Related Endpoints
{endpoints_md}

---

## ⚖️ Validation Status
**{candidate.lifecycle_state.value}**  
*Safety Invariant Notice:* Automated live credential spraying is prohibited by policy. Validation requires operator confirmation or offline format checking.

---

## 💥 Impact Assessment
{impact_narrative}

---

## 🛠️ Remediation Guidance
1. **Immediate Invalidation:** Revoke the exposed {candidate.provider} key in the provider console.
2. **Secrets Vault Migration:** Move credentials into AWS Secrets Manager, HashiCorp Vault, or encrypted environment variables.
3. **Audit Access Logs:** Review API access logs for anomalous activity using key fingerprint `{candidate.raw_fingerprint[:16]}...`.

---

## 🔬 Reproduction Evidence
- **Scanner:** HunterAI Secret Hunter Intelligence Pipeline
- **Entropy Score:** {candidate.entropy:.2f} (Shannon Entropy)
- **Placeholder Flag:** {candidate.is_example_value}
"""
        report_file.write_text(md_content, encoding="utf-8")
        return report_file
