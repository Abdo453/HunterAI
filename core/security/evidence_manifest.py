"""
HunterAI Cryptographic Evidence Manifest Engine
================================================
Generates immutable, tamper-evident cryptographic manifests for findings:
- Hash of Request bytes
- Hash of Response bytes
- Hash of Evidence / PoE indicator
- Timestamp, Engine Version, Policy Version
- HMAC-SHA256 Cryptographic Signature

Ensures that evidence, findings, and policies cannot be modified post-assessment.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional

DEFAULT_AUDIT_KEY = "hunter_audit_seal_secret_v18"


class ManifestTamperError(ValueError):
    """Raised when an evidence manifest fails cryptographic tamper verification"""
    pass


@dataclass
class FindingEvidenceManifest:
    finding_id: str
    target: str
    evidence_hash: str
    request_hash: str
    response_hash: str
    created_at: float = field(default_factory=time.time)
    engine_version: str = "HunterAI-v18.0"
    policy_version: str = "v2.0-airgap"
    signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EvidenceManifestSigner:
    """Signs and verifies tamper-evident finding manifests"""

    def __init__(self, secret: str = DEFAULT_AUDIT_KEY):
        self.secret = secret.encode("utf-8")

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    def _calculate_signature(
        self,
        finding_id: str,
        target: str,
        ev_hash: str,
        req_hash: str,
        resp_hash: str,
        created_at: float,
        engine_v: str,
        policy_v: str
    ) -> str:
        canonical_str = f"{finding_id}|{target}|{ev_hash}|{req_hash}|{resp_hash}|{created_at:.4f}|{engine_v}|{policy_v}"
        h = hmac.new(self.secret, canonical_str.encode("utf-8"), hashlib.sha256)
        return f"HMAC-SHA256:{h.hexdigest()}"

    def create_manifest(
        self,
        finding_id: str,
        target: str,
        raw_request: str,
        raw_response: str,
        evidence_snippet: str,
        engine_version: str = "HunterAI-v18.0",
        policy_version: str = "v2.0-airgap"
    ) -> FindingEvidenceManifest:
        ev_hash = self._hash(evidence_snippet)
        req_hash = self._hash(raw_request)
        resp_hash = self._hash(raw_response)
        now = time.time()

        sig = self._calculate_signature(
            finding_id=finding_id,
            target=target,
            ev_hash=ev_hash,
            req_hash=req_hash,
            resp_hash=resp_hash,
            created_at=now,
            engine_v=engine_version,
            policy_v=policy_version
        )

        return FindingEvidenceManifest(
            finding_id=finding_id,
            target=target,
            evidence_hash=ev_hash,
            request_hash=req_hash,
            response_hash=resp_hash,
            created_at=now,
            engine_version=engine_version,
            policy_version=policy_version,
            signature=sig
        )

    def verify_manifest(self, manifest: FindingEvidenceManifest) -> bool:
        expected_sig = self._calculate_signature(
            finding_id=manifest.finding_id,
            target=manifest.target,
            ev_hash=manifest.evidence_hash,
            req_hash=manifest.request_hash,
            resp_hash=manifest.response_hash,
            created_at=manifest.created_at,
            engine_v=manifest.engine_version,
            policy_v=manifest.policy_version
        )
        if not hmac.compare_digest(manifest.signature, expected_sig):
            raise ManifestTamperError(
                f"TAMPER DETECTED in Manifest for finding {manifest.finding_id}: "
                f"Signature verification failed!"
            )
        return True
