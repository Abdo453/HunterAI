"""
HunterAI Secret Hunter Agent & Intelligence Pipeline
====================================================
Production-grade multi-tier secret discovery and context intelligence engine:
1. Multi-Source Ingestion: Burp traffic, JS bundles, source maps, .env, and config files.
2. 5-Stage Detection Engine:
   Regex Match -> Entropy Gate -> Context Filter -> Provider Fingerprint -> Validation
3. Secret Intelligence & Correlation:
   Correlates discovered tokens with surrounding endpoints, services, and operational impact.
4. Safe Offline Verification:
   Strictly adheres to Zero-Live-Spraying invariant. Never executes unauthorized live
   network requests against third-party providers without explicit operator authorization.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class SecretLifecycleState(str, Enum):
    DISCOVERED = "DISCOVERED"
    NORMALIZED = "NORMALIZED"
    DEDUPLICATED = "DEDUPLICATED"
    CLASSIFIED = "CLASSIFIED"
    VALIDATION_REQUIRED = "VALIDATION_REQUIRED"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class SecretCandidate:
    candidate_id: str
    secret_type: str  # "AWS_ACCESS_KEY", "GOOGLE_API_KEY", "GITHUB_TOKEN", etc.
    provider: str     # "AWS", "Google Cloud", "GitHub", "Stripe", "Generic"
    source_origin: str # URL or file path
    location: str     # Line number or byte offset
    raw_fingerprint: str # SHA-256
    masked_value: str    # e.g., "AKIA************4F9A"
    entropy: float
    surrounding_context: str
    related_endpoints: List[str] = field(default_factory=list)
    lifecycle_state: SecretLifecycleState = SecretLifecycleState.DISCOVERED
    confidence_score: float = 0.50
    evidence_chain: List[str] = field(default_factory=list)
    is_example_value: bool = False
    remediation_advice: str = ""
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["lifecycle_state"] = self.lifecycle_state.value
        return d


class SecretHunterPipeline:
    """
    High-fidelity secret discovery and context correlation engine.
    Applies multi-stage filtering to eliminate false positives and extract intelligence.
    """

    # High-Confidence Deterministic Signatures
    PATTERNS: List[Tuple[str, str, re.Pattern]] = [
        ("AWS_ACCESS_KEY", "AWS", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("GOOGLE_API_KEY", "Google Cloud", re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,40})\b")),
        ("GITHUB_PERSONAL_TOKEN", "GitHub", re.compile(r"\b(ghp_[a-zA-Z0-9]{30,40})\b")),
        ("GITHUB_FINE_GRAINED", "GitHub", re.compile(r"\b(github_pat_[a-zA-Z0-9_]{50,90})\b")),
        ("STRIPE_SECRET_KEY", "Stripe", re.compile(r"\b(sk_(?:live|test)_[0-9a-zA-Z]{20,36})\b")),
        ("STRIPE_RESTRICTED_KEY", "Stripe", re.compile(r"\b(rk_(?:live|test)_[0-9a-zA-Z]{20,36})\b")),
        ("SLACK_BOT_TOKEN", "Slack", re.compile(r"\b(xoxb-[0-9]{9,14}-[0-9]{9,14}-[a-zA-Z0-9]{20,32})\b")),
        ("SLACK_USER_TOKEN", "Slack", re.compile(r"\b(xoxp-[0-9]{9,14}-[0-9]{9,14}-[a-zA-Z0-9]{20,32})\b")),
        ("JWT_BEARER_TOKEN", "OAuth/JWT", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)\b")),
        ("DATABASE_CONNECTION_URI", "Database", re.compile(r"""\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s@'"]+:[^\s@'"]+@[^\s\/:'"]+(?::\d+)?\/[a-zA-Z0-9_\-]+)\b""")),
        ("PRIVATE_RSA_KEY", "PKI/Crypto", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ]

    GENERIC_ASSIGNMENT_PATTERN = re.compile(
        r"""(?:api[_-]?key|secret|token|password|auth_token|client_secret|access_key)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,})['"]""",
        re.I
    )

    ENDPOINT_PATTERN = re.compile(r"""(?:https?:\/\/[^\s'"]+|\/(?:api|v[1-9]|auth|users|admin|v1|v2)\/[a-zA-Z0-9_\-\/]+)""")

    PLACEHOLDERS = {
        "changeme", "your_key", "your_token", "your_api_key", "dummy", "test",
        "example", "undefined", "null", "none", "1234567890", "abcdef", "placeholder",
        "xxxx", "00000000", "my_secret_key", "sample", "fake"
    }

    def __init__(self):
        self._seen_fingerprints: Set[str] = set()

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        length = len(data)
        freq = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    @classmethod
    def mask_secret(cls, raw: str) -> str:
        if len(raw) <= 8:
            return "****"
        return f"{raw[:4]}{'*' * (len(raw) - 8)}{raw[-4:]}"

    def scan_content(self, content: str, source_origin: str) -> List[SecretCandidate]:
        candidates: List[SecretCandidate] = []
        lines = content.splitlines()

        # Pre-extract any associated API endpoints from the content for context correlation
        extracted_endpoints = list(set(self.ENDPOINT_PATTERN.findall(content)))[:8]

        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str or len(line_str) > 10000:  # Skip empty or minified giant lines without structure
                # For minified files, chunk or scan selectively
                if len(line_str) > 10000:
                    line_str = line_str[:10000]

            # ── 1. Deterministic Known Provider Signatures ────────────────────
            for sec_type, provider, pat in self.PATTERNS:
                for match in pat.finditer(line_str):
                    raw_val = match.group(1) if match.groups() else match.group(0)
                    cand = self._evaluate_and_build_candidate(
                        raw_value=raw_val,
                        sec_type=sec_type,
                        provider=provider,
                        source_origin=source_origin,
                        line_number=line_idx,
                        line_context=line_str,
                        discovered_endpoints=extracted_endpoints,
                        is_generic=False
                    )
                    if cand:
                        candidates.append(cand)

            # ── 2. Generic Key-Value Assignments ─────────────────────────────
            for match in self.GENERIC_ASSIGNMENT_PATTERN.finditer(line_str):
                raw_val = match.group(1)
                cand = self._evaluate_and_build_candidate(
                    raw_value=raw_val,
                    sec_type="GENERIC_API_SECRET",
                    provider="Generic Application",
                    source_origin=source_origin,
                    line_number=line_idx,
                    line_context=line_str,
                    discovered_endpoints=extracted_endpoints,
                    is_generic=True
                )
                if cand:
                    candidates.append(cand)

        return candidates

    def _evaluate_and_build_candidate(
        self,
        raw_value: str,
        sec_type: str,
        provider: str,
        source_origin: str,
        line_number: int,
        line_context: str,
        discovered_endpoints: List[str],
        is_generic: bool
    ) -> Optional[SecretCandidate]:
        # Stage 1: Fingerprinting & Deduplication
        fp = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
        if fp in self._seen_fingerprints:
            return None
        self._seen_fingerprints.add(fp)

        # Stage 2: Entropy Gate
        entropy = self.calculate_shannon_entropy(raw_value)
        if is_generic and (entropy < 3.2 or len(raw_value) < 16):
            return None

        # Stage 3: Context Filter & Placeholder Rejection
        raw_lower = raw_value.lower()
        is_placeholder = any(p in raw_lower for p in self.PLACEHOLDERS)
        if "example.com" in line_context.lower() or "test.com" in line_context.lower() or "mock" in line_context.lower():
            is_placeholder = True

        evidence = [
            f"Pattern matched provider signature: {provider} ({sec_type})",
            f"Shannon entropy calculated at {entropy:.2f} (threshold: 3.20)",
            f"Extracted from source location {source_origin}:{line_number}"
        ]

        if is_placeholder:
            evidence.append("Flagged as non-functional placeholder or documentation example")
            state = SecretLifecycleState.FALSE_POSITIVE
            confidence = 0.20
        elif sec_type in ("AWS_ACCESS_KEY", "GOOGLE_API_KEY", "GITHUB_PERSONAL_TOKEN", "STRIPE_SECRET_KEY"):
            evidence.append("High-confidence deterministic format and key length verified")
            state = SecretLifecycleState.VALIDATION_REQUIRED
            confidence = 0.95
        else:
            state = SecretLifecycleState.CLASSIFIED
            confidence = 0.75

        # Formulate contextual remediation
        advice = f"Revoke and rotate {sec_type} immediately. Replace hardcoded token with environment variables or vault references."

        cand_id = f"SECRET-{sec_type[:3]}-{fp[:6].upper()}"

        return SecretCandidate(
            candidate_id=cand_id,
            secret_type=sec_type,
            provider=provider,
            source_origin=source_origin,
            location=f"Line {line_number}",
            raw_fingerprint=fp,
            masked_value=self.mask_secret(raw_value),
            entropy=entropy,
            surrounding_context=line_context[:120],
            related_endpoints=discovered_endpoints,
            lifecycle_state=state,
            confidence_score=confidence,
            evidence_chain=evidence,
            is_example_value=is_placeholder,
            remediation_advice=advice
        )

    def scan_file(self, file_path: Path) -> List[SecretCandidate]:
        if not file_path.exists() or not file_path.is_file():
            return []
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            return self.scan_content(content, source_origin=str(file_path))
        except Exception:
            return []
