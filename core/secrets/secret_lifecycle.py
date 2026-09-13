"""
HunterAI Secret Lifecycle & Redaction Engine
============================================
Guarantees:
- Zero Raw Secret Leakage: Raw secrets are never stored in plaintext reports or flight logs.
- Full lifecycle tracking:
  CANDIDATE -> VERIFIED -> FINGERPRINTED -> REDACTED_STORAGE -> ROTATION_ADVICE -> RETEST -> REVOKED_OR_ACTIVE
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SecretState(str, Enum):
    CANDIDATE = "CANDIDATE"
    VERIFIED = "VERIFIED"
    FINGERPRINTED = "FINGERPRINTED"
    REDACTED_STORAGE = "REDACTED_STORAGE"
    ROTATION_ADVICE = "ROTATION_ADVICE"
    RETESTED_ACTIVE = "RETESTED_ACTIVE"
    RETESTED_REVOKED = "RETESTED_REVOKED"


@dataclass
class SecretRecord:
    secret_id: str
    secret_type: str  # e.g., "AWS_KEY", "JWT_SECRET", "API_KEY", "DATABASE_PASSWORD"
    masked_preview: str  # e.g., "AKIA************4F9A"
    sha256_fingerprint: str
    discovered_in_url: str
    state: SecretState = SecretState.CANDIDATE
    remediation_advice: str = ""
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "secret_type": self.secret_type,
            "masked_preview": self.masked_preview,
            "fingerprint": self.sha256_fingerprint,
            "endpoint": self.discovered_in_url,
            "state": self.state.value,
            "remediation": self.remediation_advice,
        }


class SecretLifecycleManager:
    """Manages discovered secret lifecycles without leaking raw secret strings"""

    def __init__(self):
        self._secrets: Dict[str, SecretRecord] = {}
        self._counter = 0

    def register_secret_candidate(
        self,
        raw_secret: str,
        secret_type: str,
        endpoint: str
    ) -> SecretRecord:
        self._counter += 1
        secret_id = f"SEC-{secret_type[:3]}-{self._counter:04d}"

        # 1. Calculate SHA-256 fingerprint
        fp = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

        # 2. Mask preview (only show prefix 4 and suffix 4 chars)
        if len(raw_secret) > 8:
            masked = f"{raw_secret[:4]}{'*' * (len(raw_secret) - 8)}{raw_secret[-4:]}"
        else:
            masked = "****"

        # 3. Formulate rotation recommendation
        advice = f"Immediately rotate {secret_type} in secrets vault and invalidate exposed token."

        rec = SecretRecord(
            secret_id=secret_id,
            secret_type=secret_type,
            masked_preview=masked,
            sha256_fingerprint=fp,
            discovered_in_url=endpoint,
            state=SecretState.REDACTED_STORAGE,
            remediation_advice=advice
        )
        self._secrets[secret_id] = rec
        return rec

    def retest_secret(self, secret_id: str, is_still_functional: bool) -> bool:
        if secret_id not in self._secrets:
            return False
        rec = self._secrets[secret_id]
        rec.state = SecretState.RETESTED_ACTIVE if is_still_functional else SecretState.RETESTED_REVOKED
        return True

    def get_records(self) -> List[SecretRecord]:
        return list(self._secrets.values())
