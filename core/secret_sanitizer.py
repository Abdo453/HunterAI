"""
Secret Sanitizer & Credential Masking Engine
Prevents leakage of sensitive credentials, API keys, JWTs, and passwords
in raw logs, reports, evidence, and tool outputs.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


class SecretSanitizer:
    """
    Scrubs and masks sensitive tokens across text, JSON structures, and reports.
    Preserves verifiable prefixes and suffixes while protecting confidential payloads.
    Example: sk_live_1234567890abcdef -> sk_live_••••••••cdef
    """

    MASK_BULLET = "••••••••"

    @classmethod
    def mask_string(cls, secret_str: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
        """Masks a generic sensitive string leaving only small prefix and suffix"""
        if not secret_str:
            return ""
        if len(secret_str) <= prefix_len + suffix_len:
            return cls.MASK_BULLET
        return f"{secret_str[:prefix_len]}{cls.MASK_BULLET}{secret_str[-suffix_len:]}"

    @classmethod
    def sanitize_text(cls, text: str) -> str:
        """Applies regex masking to sensitive tokens within a text string"""
        if not text or not isinstance(text, str):
            return text

        scrubbed = text

        # 1. AWS Access Keys
        scrubbed = re.sub(
            r"\b((?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{4})[A-Z0-9]{8}([A-Z0-9]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed
        )

        # 2. Stripe & payment keys
        scrubbed = re.sub(
            r"\b((?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{4})[a-zA-Z0-9]{12,}([a-zA-Z0-9]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed
        )

        # 3. GitHub personal access tokens
        scrubbed = re.sub(
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{4})[a-zA-Z0-9]{24,}([a-zA-Z0-9]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed
        )

        # 4. JWT Tokens
        scrubbed = re.sub(
            r"\b(ey[A-Za-z0-9_-]{8})[A-Za-z0-9_\-\.]+\.([A-Za-z0-9_-]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed
        )

        # 5. Slack Webhooks
        scrubbed = re.sub(
            r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+)/[a-zA-Z0-9_]{16,}",
            r"\1/" + cls.MASK_BULLET,
            scrubbed
        )

        # 6. Generic API params: api_key=..., token=...
        scrubbed = re.sub(
            r"(?i)((?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)[\"\'\s:=]+[\"\']?)([a-zA-Z0-9_\-]{3})[a-zA-Z0-9_\-]{10,}([a-zA-Z0-9_\-]{3})([\"\'\s&]|$)",
            r"\1\2" + cls.MASK_BULLET + r"\3\4",
            scrubbed
        )

        # 7. Password fields
        scrubbed = re.sub(
            r"(?i)((?:password|passwd|pwd)[\"\'\s:=]+[\"\']?)([^\"\'\s&]{2})[^\"\'\s&]{4,}([^\"\'\s&]{2})([\"\'\s&]|$)",
            r"\1\2" + cls.MASK_BULLET + r"\3\4",
            scrubbed
        )

        # 8. Database Connection URIs
        scrubbed = re.sub(
            r"((?:postgres|postgresql|mysql|mongodb|redis)://[^:]+:)([^@]+)(@.+)",
            r"\1" + cls.MASK_BULLET + r"\3",
            scrubbed
        )

        return scrubbed

    @classmethod
    def sanitize_data(cls, data: Any) -> Any:
        """Recursively scrubs sensitive data in dictionaries, lists, and strings"""
        if isinstance(data, str):
            return cls.sanitize_text(data)
        elif isinstance(data, dict):
            return {k: cls.sanitize_data(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls.sanitize_data(item) for item in data]
        elif isinstance(data, tuple):
            return tuple(cls.sanitize_data(item) for item in data)
        elif isinstance(data, set):
            return {cls.sanitize_data(item) for item in data}
        return data
