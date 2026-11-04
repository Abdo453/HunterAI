"""
JavaScript Secret Mining & Intelligence Engine (JSSecretMiner)
==============================================================
High-speed, entropy-aware secret miner inspired by mantra, trufflehog,
SecretFinder, and jsluice.

Detects:
- AWS Access Keys & Secrets (AKIA..., AWS_SECRET_ACCESS_KEY)
- Google Cloud & Firebase API Keys (AIza...)
- Slack Webhook URLs & OAuth Tokens (xoxb, xoxp, xoxa)
- GitHub Personal Access Tokens (ghp_..., github_pat_...)
- Stripe Live API Keys (sk_live_..., rk_live_...)
- JSON Web Tokens (JWT)
- Private Cryptographic Keys (RSA, EC, OPENSSH)
- Twilio & SendGrid API Credentials
- Generic High-Entropy API Keys & Bearer Tokens
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies: Dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def mask_secret(secret: str) -> str:
    """Masks secret to prevent sensitive disclosure in logs while keeping forensic proof."""
    if len(secret) <= 8:
        return secret[:2] + "****" + secret[-2:] if len(secret) >= 4 else "****"
    return secret[:4] + "****" + secret[-4:]


@dataclass
class DiscoveredSecret:
    secret_type: str
    raw_value: str
    masked_value: str
    entropy: float
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    source: str
    line_number: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class JSSecretMiner:
    """Extracts credentials, cloud tokens, and sensitive keys from JavaScript sources."""

    SECRET_RULES: List[Dict[str, Any]] = [
        {
            "type": "AWS_ACCESS_KEY",
            "regex": re.compile(r"(?:^|[^A-Z0-9])(AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)", re.M),
            "confidence": "HIGH",
            "min_entropy": 3.0,
        },
        {
            "type": "GOOGLE_API_KEY",
            "regex": re.compile(r"(?:^|[^A-Za-z0-9_\-])(AIza[0-9A-Za-z\-_]{35,45})(?:[^A-Za-z0-9_\-]|$)", re.M),
            "confidence": "HIGH",
            "min_entropy": 3.5,
        },
        {
            "type": "SLACK_WEBHOOK",
            "regex": re.compile(r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24})", re.M),
            "confidence": "HIGH",
            "min_entropy": 2.5,
        },
        {
            "type": "SLACK_TOKEN",
            "regex": re.compile(r"(xox[baprs]-[0-9a-zA-Z]{10,48})", re.M),
            "confidence": "HIGH",
            "min_entropy": 3.2,
        },
        {
            "type": "GITHUB_PAT",
            "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})(?:[^a-zA-Z0-9_]|$)", re.M),
            "confidence": "HIGH",
            "min_entropy": 3.5,
        },
        {
            "type": "STRIPE_KEY",
            "regex": re.compile(r"(?:^|[^a-zA-Z0-9_])((?:sk|rk)_live_[0-9a-zA-Z]{24,34})(?:[^a-zA-Z0-9_]|$)", re.M),
            "confidence": "HIGH",
            "min_entropy": 3.5,
        },
        {
            "type": "JWT_TOKEN",
            "regex": re.compile(r"(?:^|[^a-zA-Z0-9_\-])(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?:[^a-zA-Z0-9_\-]|$)", re.M),
            "confidence": "HIGH",
            "min_entropy": 4.0,
        },
        {
            "type": "PRIVATE_KEY",
            "regex": re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{30,2000}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)", re.M),
            "confidence": "HIGH",
            "min_entropy": 3.0,
        },
        {
            "type": "TWILIO_CREDENTIALS",
            "regex": re.compile(r"(?:^|[^a-zA-Z0-9])(AC[a-f0-9]{32})(?:[^a-zA-Z0-9]|$)", re.I),
            "confidence": "MEDIUM",
            "min_entropy": 3.2,
        },
        {
            "type": "SENDGRID_KEY",
            "regex": re.compile(r"(SG\.[a-zA-Z0-9_\-\.]{66})", re.M),
            "confidence": "HIGH",
            "min_entropy": 4.0,
        },
        {
            "type": "GENERIC_API_KEY",
            "regex": re.compile(
                r"""(?i)(?:api[_-]?key|secret[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,80})['"]""",
                re.M
            ),
            "confidence": "MEDIUM",
            "min_entropy": 3.8,
        },
    ]

    HIDDEN_ENDPOINT_REGEX = re.compile(
        r"""(?:['"`])(/\b(?:api|v[0-9]|graphql|admin|internal|user|account|auth|oauth|secret|webhook)\b[^'"`\s\)]*)(?:['"`])""",
        re.I
    )

    def __init__(self, entropy_threshold: float = 3.0):
        self.entropy_threshold = entropy_threshold

    def mine_text(self, content: str, source: str = "inline_script") -> List[DiscoveredSecret]:
        """Scans raw JS source code string and returns structured findings."""
        if not content:
            return []

        findings: List[DiscoveredSecret] = []
        seen_values: Set[str] = set()

        lines = content.splitlines()

        for rule in self.SECRET_RULES:
            rule_type = rule["type"]
            pattern = rule["regex"]
            base_confidence = rule["confidence"]
            min_entropy = rule.get("min_entropy", self.entropy_threshold)

            for line_idx, line in enumerate(lines, start=1):
                # Quick length check
                if len(line) > 5000:
                    # Strip very long bundled lines to avoid catastrophic backtracking
                    line = line[:5000]

                matches = pattern.finditer(line)
                for m in matches:
                    val = m.group(1).strip()
                    if not val or val in seen_values:
                        continue

                    # Filter out common false positives
                    if any(dummy in val.lower() for dummy in ("placeholder", "example", "xxx", "your_api_key", "undefined")):
                        continue

                    entropy = calculate_shannon_entropy(val)
                    if entropy < min_entropy:
                        continue

                    seen_values.add(val)
                    findings.append(DiscoveredSecret(
                        secret_type=rule_type,
                        raw_value=val,
                        masked_value=mask_secret(val),
                        entropy=entropy,
                        confidence=base_confidence,
                        source=source,
                        line_number=line_idx,
                    ))

        return findings

    def extract_hidden_endpoints(self, content: str) -> List[str]:
        """Extracts hidden API endpoints and routes declared within JavaScript code."""
        if not content:
            return []
        discovered: Set[str] = set()
        matches = self.HIDDEN_ENDPOINT_REGEX.finditer(content)
        for m in matches:
            endpoint = m.group(1).strip()
            # Clean trailing punctuation
            endpoint = endpoint.split("?")[0].rstrip("/.,;)")
            if len(endpoint) > 4 and " " not in endpoint:
                discovered.add(endpoint)
        return sorted(discovered)
