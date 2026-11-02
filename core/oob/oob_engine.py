"""
HunterAI Out-Of-Band (OOB) Autonomous Engine
============================================
Connects canary token generation with live polling and EvidenceCourt adjudication.
Supports:
  - Blind SSRF (Server-Side Request Forgery)
  - Blind RCE (Remote Code Execution via DNS/HTTP trigger)
  - Blind SQLi (Out-of-band DNS exfiltration)
  - Blind XXE (XML External Entity injection)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.contracts.task_contracts import EvidenceArtifact, EvidenceSignificance
from core.evidence_court import EvidenceCourt
from core.oob.oob_client import OOBInteraction, OOBInteractionClient, OOBProbeContext

logger = logging.getLogger("hunter_ai.oob_engine")


@dataclass
class OOBVerdictReport:
    is_confirmed: bool
    vulnerability_type: str
    target_endpoint: str
    parameter_name: str
    canary_token: str
    interaction_protocol: str = ""
    origin_ip: str = ""
    evidence_artifact: Optional[EvidenceArtifact] = None
    rationale: str = ""


class OOBEngine:
    """
    High-level Out-of-Band verification engine.
    Orchestrates probe generation, payload injection, polling, and EvidenceCourt submission.
    """

    def __init__(self, callback_domain: str = "oob.hunterai.internal"):
        self.client = OOBInteractionClient(base_callback_domain=callback_domain)
        self.court = EvidenceCourt()

    def create_probe(
        self,
        endpoint: str,
        param_name: str,
        vuln_type: str = "blind_ssrf",
    ) -> Tuple[OOBProbeContext, Dict[str, str]]:
        """
        Generates an OOB probe context and tailored injection payloads.
        """
        ctx = self.client.generate_probe_context(
            target_endpoint=endpoint,
            parameter_name=param_name,
            vulnerability_type=vuln_type,
        )
        payloads = self.client.craft_canary_payload(ctx)
        return ctx, payloads

    def verify_interaction(self, token: str) -> OOBVerdictReport:
        """
        Polls for interaction and produces a binding EvidenceCourt-compatible verdict.
        """
        confirmed, interaction = self.client.poll_for_verification(token)
        ctx = self.client.active_probes.get(token.lower().strip())

        if not confirmed or not interaction or not ctx:
            return OOBVerdictReport(
                is_confirmed=False,
                vulnerability_type=ctx.vulnerability_type if ctx else "UNKNOWN",
                target_endpoint=ctx.target_endpoint if ctx else "",
                parameter_name=ctx.parameter_name if ctx else "",
                canary_token=token,
                rationale="No out-of-band network interaction recorded for this canary token.",
            )

        # Build formal EvidenceArtifact
        artifact = EvidenceArtifact(
            evidence_id=f"OOB-EVID-{token.upper()}",
            significance=EvidenceSignificance.PROOF,
            source_tool="OOBEngine",
            target=ctx.target_endpoint,
            description=(
                f"Out-of-band {interaction.protocol} interaction from {interaction.remote_address} "
                f"triggered by probe on parameter '{ctx.parameter_name}'"
            ),
            diff_data={
                "protocol": interaction.protocol,
                "remote_ip": interaction.remote_address,
                "token": token,
                "timestamp": interaction.timestamp,
                "target_endpoint": ctx.target_endpoint,
            },
            poe_verified=True,
        )

        return OOBVerdictReport(
            is_confirmed=True,
            vulnerability_type=ctx.vulnerability_type,
            target_endpoint=ctx.target_endpoint,
            parameter_name=ctx.parameter_name,
            canary_token=token,
            interaction_protocol=interaction.protocol,
            origin_ip=interaction.remote_address,
            evidence_artifact=artifact,
            rationale=(
                f"Proof-of-Execution confirmed: Target initiated {interaction.protocol} connection "
                f"from {interaction.remote_address} back to canary {ctx.canary_domain}."
            ),
        )

    def simulate_mock_callback(
        self,
        token: str,
        protocol: str = "DNS",
        origin_ip: str = "198.51.100.42",
    ) -> Optional[OOBProbeContext]:
        """Helper for hermetic testing of OOB verification pipeline."""
        return self.client.record_incoming_interaction(
            token=token,
            protocol=protocol,
            remote_address=origin_ip,
            raw_query_or_path=f"canary_{token}",
        )
