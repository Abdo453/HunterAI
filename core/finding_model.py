"""
HunterAI Unified Finding Object Model (V1.0)
===========================================
Every Agent, Detector, Sensor, and Verifier in HunterAI returns this exact
standardized schema. Unifies XSS, SQLi, SSRF, BOLA, and all vulnerability
types under a single, deterministic, audit-ready data contract.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class HttpExchangeRecord:
    """Represents a concrete HTTP request/response exchange"""
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    status_code: Optional[int] = None
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body_snippet: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_curl(self) -> str:
        parts = ["curl", "-i", "-s"]
        if self.method != "GET":
            parts.extend(["-X", self.method])
        for k, v in self.headers.items():
            parts.extend(["-H", f"'{k}: {v}'"])
        if self.body:
            parts.extend(["--data", f"'{self.body}'"])
        parts.append(f"'{self.url}'")
        return " ".join(parts)


@dataclass
class VerificationRecord:
    """Records the independent verification criteria and evidence"""
    verified: bool = False
    verifier_name: str = ""
    methodology: str = ""
    proof_token: Optional[str] = None
    reproduced_count: int = 0
    notes: str = ""


@dataclass
class ReproducibilityRecord:
    """Details reproducible execution steps and artifacts"""
    is_reproducible: bool = False
    reproduction_steps: List[str] = field(default_factory=list)
    reproduction_curl: str = ""
    preconditions: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """
    The Single Unified Finding Object Contract for HunterAI.
    """
    id: str = field(default_factory=lambda: f"FND-{uuid.uuid4().hex[:8].upper()}")
    vulnerability_type: str = ""  # e.g., "xss", "sqli", "ssrf", "bola"
    title: str = ""
    severity: str = "MEDIUM"
    confidence: float = 0.5
    target: str = ""
    endpoint: str = ""
    parameter: str = ""
    original_request: Optional[HttpExchangeRecord] = None
    tested_request: Optional[HttpExchangeRecord] = None
    baseline_response: Optional[HttpExchangeRecord] = None
    test_response: Optional[HttpExchangeRecord] = None
    evidence: str = ""
    verification: VerificationRecord = field(default_factory=VerificationRecord)
    reproducibility: ReproducibilityRecord = field(default_factory=ReproducibilityRecord)
    impact: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    timestamps: Dict[str, float] = field(default_factory=lambda: {"discovered_at": time.time()})

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_reproduction_guide(self) -> str:
        """Generates an immediate, copy-pasteable reproduction guide"""
        steps_text = "\n".join(
            f"{i+1}. {s}" for i, s in enumerate(self.reproducibility.reproduction_steps)
        )
        curl_cmd = self.reproducibility.reproduction_curl or (
            self.tested_request.to_curl() if self.tested_request else "N/A"
        )
        return (
            f"### Steps to Reproduce ({self.title})\n\n"
            f"{steps_text}\n\n"
            f"#### Exact Curl Command:\n"
            f"```bash\n{curl_cmd}\n```\n"
        )

    def to_hackerone_markdown(self) -> str:
        """Outputs an industry-standard Bug Bounty Markdown report"""
        curl_cmd = self.reproducibility.reproduction_curl or (
            self.tested_request.to_curl() if self.tested_request else "N/A"
        )
        steps_text = "\n".join(
            f"{i+1}. {s}" for i, s in enumerate(self.reproducibility.reproduction_steps)
        )
        base_status = self.baseline_response.status_code if self.baseline_response else "N/A"
        base_body = self.baseline_response.response_body_snippet if self.baseline_response else "No baseline recorded."
        test_status = self.test_response.status_code if self.test_response else "N/A"
        test_body = self.test_response.response_body_snippet if self.test_response else "No test response recorded."

        return f"""# [{self.severity}] {self.title}

## Summary
A **{self.vulnerability_type.upper()}** vulnerability was confirmed on target `{self.target}` at endpoint `{self.endpoint}` affecting parameter `{self.parameter}`.

- **Vulnerability Type:** `{self.vulnerability_type}`
- **Severity:** `{self.severity}`
- **Confidence Score:** `{self.confidence:.2f}` (Court Verified: `{self.verification.verified}`)
- **CWE:** `{self.cwe}`
- **OWASP:** `{self.owasp}`

---

## Steps to Reproduce
{steps_text}

### Proof of Concept (cURL)
```bash
{curl_cmd}
```

---

## Technical Evidence & Response Comparison
- **Evidence Summary:** {self.evidence}
- **Proof Token / Indicator:** `{self.verification.proof_token or 'N/A'}`

### Baseline Response (Status {base_status}):
```http
{base_body}
```

### Test Response with Payload (Status {test_status}):
```http
{test_body}
```

---

## Business & Security Impact
{self.impact}

## Remediation Guidance
{self.remediation}
"""