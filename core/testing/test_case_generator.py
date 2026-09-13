"""
HunterAI Finding Fingerprints & Test Case Generator
===================================================
1. Fingerprints findings canonicalizing vulnerability class, root cause, and path patterns.
2. Converts confirmed findings into permanent executable security test cases (TC-AUTH-0042)
   ready for direct embedding into CI/CD regression pipelines.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional


@dataclass
class SecurityTestCase:
    test_case_id: str
    finding_id: str
    vulnerability_class: str
    title: str
    preconditions: str
    test_input: str
    expected_safe_behavior: str
    observed_vulnerable_behavior: str
    reproduce_command: str
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class FindingFingerprinter:
    """Generates canonical structural fingerprints independent of query parameter values"""

    @classmethod
    def compute_fingerprint(
        cls,
        vulnerability_class: str,
        root_cause: str,
        endpoint: str,
        parameter: str
    ) -> str:
        # Normalize endpoint (replace numeric IDs with {id})
        normalized_ep = re.sub(r"/\d+(?=/|$)", "/{id}", endpoint.lower())
        seed = f"{vulnerability_class.upper()}:{root_cause.strip().lower()}:{normalized_ep}:{parameter.lower()}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


class TestCaseGenerator:
    """Transforms confirmed findings into permanent regression test cases"""

    @classmethod
    def generate_test_case(
        cls,
        finding_id: str,
        vulnerability_class: str,
        title: str,
        endpoint: str,
        parameter: str,
        payload: str,
        expected_status: int = 403
    ) -> SecurityTestCase:
        tc_id = f"TC-{vulnerability_class.upper()[:4]}-{finding_id.replace('-', '')[:4].upper()}"
        reproduce_cmd = f"curl -s -X POST '{endpoint}' -d '{parameter}={payload}'"

        return SecurityTestCase(
            test_case_id=tc_id,
            finding_id=finding_id,
            vulnerability_class=vulnerability_class,
            title=title,
            preconditions="Target staging environment online and authentication credentials valid.",
            test_input=f"Parameter '{parameter}' payload: {payload}",
            expected_safe_behavior=f"Server returns HTTP {expected_status} or sanitizes input without execution.",
            observed_vulnerable_behavior="Server executed unauthorized action with status 200.",
            reproduce_command=reproduce_cmd
        )
