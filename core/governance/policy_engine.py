"""
Governance Policy Engine
Enforces authorization scope, rate limits, forbidden actions,
human-in-the-loop approval gates, and sensitive data / secrets redaction.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Standard forbidden test activities
FORBIDDEN_ACTIVITIES = {
    "dos",
    "denial_of_service",
    "credential_attack",
    "brute_force",
    "destructive_actions",
    "real_account_takeover",
    "sensitive_data_extraction",
    "data_deletion",
    "mass_account_creation",
    "phishing",
}

# High-risk activities requiring human-in-the-loop approval before active execution
HIGH_RISK_ACTIVITIES = {
    "ssrf",
    "ssti",
    "command_injection",
    "rce",
    "file_upload",
    "authorization_testing",
    "privilege_escalation",
}

# Regex patterns for stripping sensitive tokens and secrets before sending to online cloud models
SECRET_REDACTION_PATTERNS = [
    (re.compile(r"""(?i)(?:bearer\s+)[a-zA-Z0-9_\-\.]{12,}"""), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"""(?i)(?:api_?key|apikey|api_secret)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{12,}['"]?"""), "api_key=[REDACTED_SECRET]"),
    (re.compile(r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]?[^'"\s]{4,}['"]?"""), "password=[REDACTED_PASSWORD]"),
    (re.compile(r"""(?i)(?:cookie\s*:\s*)[^\r\n]+"""), "Cookie: [REDACTED_COOKIES]"),
    (re.compile(r"""(?i)eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"""), "[REDACTED_JWT_TOKEN]"),
]


@dataclass
class ProgramScopePolicy:
    program_name: str
    allowed_hosts: List[str]
    blocked_hosts: List[str] = field(default_factory=list)
    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    max_requests_per_second: float = 2.0
    forbidden_activities: Set[str] = field(default_factory=lambda: set(FORBIDDEN_ACTIVITIES))
    high_risk_activities: Set[str] = field(default_factory=lambda: set(HIGH_RISK_ACTIVITIES))


class GovernancePolicyEngine:
    """
    محرك سياسات الحوكمة والأمان (Governance Policy Engine):
    - يتحقق بدقة من الـ Scope (Allowed vs Blocked Hosts).
    - يمنع الأنشطة المحظورة (DoS, Data Extraction, Account Takeover).
    - يفرض الموافقة البشرية على الفحوصات عالية الخطورة (SSRF, RCE, File Upload).
    - ينقي الأسرار والتراخيص قبل مشاركة أي بيانات خارج البيئة المحلية.
    """

    def __init__(self, policy: ProgramScopePolicy):
        self.policy = policy

    def is_host_in_scope(self, url: str) -> bool:
        """التحقق من أن الرابط يقع ضمن النطاق المسموح به وليس محظوراً"""
        if not url:
            return False
        hostname = (urlparse(url).hostname or url).lower()

        # Check blocked hosts first
        for b_host in self.policy.blocked_hosts:
            clean_b = (urlparse(b_host).hostname or b_host).lower()
            if hostname == clean_b or hostname.endswith("." + clean_b):
                logger.warning(f"[PolicyEngine] Host '{hostname}' matches blocked host '{clean_b}'.")
                return False

        # Check allowed hosts
        for a_host in self.policy.allowed_hosts:
            clean_a = (urlparse(a_host).hostname or a_host).lower()
            if hostname == clean_a or hostname.endswith("." + clean_a):
                return True

        logger.warning(f"[PolicyEngine] Host '{hostname}' is not in allowed hosts list.")
        return False

    def is_forbidden_activity(self, activity_type: str) -> bool:
        """فحص ما إذا كان النشاط محظوراً وفق سياسة الحوكمة"""
        act = activity_type.lower().strip()
        return act in self.policy.forbidden_activities

    def requires_human_approval(self, activity_type: str, is_active_execution: bool = True) -> bool:
        """تحديد ما إذا كان النشاط يتطلب موافقة بشرية مسبقة"""
        if not is_active_execution:
            return False
        act = activity_type.lower().strip()
        return act in self.policy.high_risk_activities

    @classmethod
    def remove_secrets(cls, text_or_data: Any) -> Any:
        """تجريد الأسرار والتوكنات والكوكيز من أي نص أو بنية بيانات"""
        if isinstance(text_or_data, str):
            sanitized = text_or_data
            for pattern, repl in SECRET_REDACTION_PATTERNS:
                sanitized = pattern.sub(repl, sanitized)
            return sanitized
        elif isinstance(text_or_data, dict):
            return {k: cls.remove_secrets(v) for k, v in text_or_data.items()}
        elif isinstance(text_or_data, list):
            return [cls.remove_secrets(item) for item in text_or_data]
        return text_or_data
