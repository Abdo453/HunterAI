"""
HunterAI Cryptographic Report Signer & Tamper Verification
==========================================================
Generates canonical SHA-256 digests and optional HMAC signatures over
findings, coverage summaries, and evidence files. Guarantees that no
report or finding has been altered post-assessment.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional


class TamperDetectedError(ValueError):
    """Raised when an assessment report or evidence bundle fails cryptographic signature verification"""
    pass


@dataclass
class ReportSignature:
    algorithm: str = "HMAC-SHA256"
    digest: str = ""
    signed_at: float = 0.0
    item_count: int = 0
    signer_identity: str = "HunterAI-Evidence-Engine"


class ReportSigner:
    """Cryptographic signing and verification engine for HunterAI reports"""

    def __init__(self, signing_secret: str = "hunter_default_audit_key_v1"):
        self.secret = signing_secret.encode("utf-8")

    def _canonicalize(self, data: Any) -> bytes:
        """Converts arbitrary JSON-serializable structure to canonical UTF-8 bytes"""
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return serialized.encode("utf-8")

    def sign_report(self, report_data: Dict[str, Any], signer_identity: str = "HunterAI-Evidence-Engine") -> ReportSignature:
        """Signs a report dictionary and returns a ReportSignature seal"""
        canonical_bytes = self._canonicalize(report_data)
        h = hmac.new(self.secret, canonical_bytes, hashlib.sha256)
        digest_hex = h.hexdigest()
        items = len(report_data.get("findings", []))

        return ReportSignature(
            algorithm="HMAC-SHA256",
            digest=digest_hex,
            signed_at=time.time(),
            item_count=items,
            signer_identity=signer_identity
        )

    def verify_report(self, report_data: Dict[str, Any], signature: ReportSignature) -> bool:
        """Verifies report integrity against its ReportSignature; raises TamperDetectedError if invalid"""
        expected = self.sign_report(report_data, signer_identity=signature.signer_identity)
        if not hmac.compare_digest(expected.digest, signature.digest):
            raise TamperDetectedError(
                f"TAMPER DETECTED: Report contents do not match cryptographic digest! "
                f"Expected: {expected.digest[:16]}..., Received: {signature.digest[:16]}..."
            )
        return True
