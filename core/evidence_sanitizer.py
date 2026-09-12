"""
Evidence & PII Sanitizer (Evidence Hygiene)
Sanitizes raw HTTP traces, logs, and evidence dumps by redacting live secrets, PII, and credentials.
Inspired by Claude-BugHunter's evidence-hygiene rules.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple

# Regex patterns for sensitive data redaction
REDACTION_RULES: List[Tuple[str, str]] = [
    # JWT / Bearer Tokens
    (r"(?i)(bearer\s+)ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*", r"\1[REDACTED_JWT_TOKEN]"),
    (r"ey[A-Za-z0-9-_=]{20,}\.ey[A-Za-z0-9-_=]{20,}\.[A-Za-z0-9-_.+/=]{20,}", "[REDACTED_JWT_TOKEN]"),
    
    # AWS Access Keys & Secrets
    (r"(?i)(aws_secret_access_key[\"']?\s*[:=]\s*[\"'])[A-Za-z0-9/+=]{40}([\"'])", r"\1[REDACTED_AWS_SECRET]\2"),
    (r"(?i)(AKIA[0-9A-Z]{16})", "[REDACTED_AWS_KEY_ID]"),
    
    # Generic API Keys & High-entropy tokens
    (r"(?i)(api[_-]?key[\"']?\s*[:=]\s*[\"'])[a-zA-Z0-9_\-\.]{16,}([\"'])", r"\1[REDACTED_API_KEY]\2"),
    (r"(?i)(authorization:\s*basic\s+)[A-Za-z0-9+/=]{10,}", r"\1[REDACTED_BASIC_AUTH]"),
    
    # Passwords in JSON / Headers / Query parameters
    (r"(?i)(password[\"']?\s*[:=]\s*[\"'])[^\"'\s]{4,}([\"'])", r"\1[REDACTED_PASSWORD]\2"),
    (r"(?i)(&password=)[^&\s]+", r"\1[REDACTED_PASSWORD]"),
    (r"(?i)(\"client_secret\":\s*\")[^\"]+(\")", r"\1[REDACTED_CLIENT_SECRET]\2"),
    
    # Email addresses (preserve domain if desired or redact user part)
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", "[REDACTED_EMAIL]"),
    
    # Credit card / PAN numbers (simple Luhn-like 16 digits)
    (r"\b(?:\d{4}[ -]?){3}\d{4}\b", "[REDACTED_CARD_NUMBER]"),
    
    # Private Key blocks
    (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY_BLOCK]"),
]


class EvidenceSanitizer:
    """
    يقوم بتنظيف وحجب البيانات الحساسة وأرقام الهويات وبيانات الجلسات الحية من ملفات ومرفقات الأدلة
    """

    @classmethod
    def sanitize(cls, text: str) -> str:
        """تطبيق قواعد الحجب والتنظيف على النص المدخل"""
        if not text:
            return ""

        cleaned = text
        for pattern, replacement in REDACTION_RULES:
            cleaned = re.sub(pattern, replacement, cleaned)

        return cleaned

    @classmethod
    def sanitize_dict(cls, data: Dict[str, str]) -> Dict[str, str]:
        """تنظيف قاموس من النصوص والأدلة"""
        return {k: cls.sanitize(str(v)) for k, v in data.items()}
