"""Server-Side Request Forgery (SSRF) detector with a loopback canary.

The detector asks the target to fetch a unique loopback URL.  A callback on the
canary proves the server made the request.  The detector itself never contacts
an external host; the canary and the target are both loopback in the lab.
"""
from __future__ import annotations

import secrets

from core.detectors.canary import LoopbackCanary
from core.detectors.contract import (
    Detection,
    DetectionContext,
    build_url,
    to_exchange_record,
)
from core.detectors.transport import HttpTransport
from core.finding_model import (
    Finding,
    ReproducibilityRecord,
    VerificationRecord,
)


class SSRFDetector:
    name = "ssrf.canary"
    vuln_class = "ssrf"

    def detect(self, context: DetectionContext, transport: HttpTransport) -> Detection:
        if not context.parameter:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason="a parameter name is required for SSRF testing",
                detector=self.name,
            )

        extra = dict(context.extra_params)
        nonce = f"hnt{secrets.token_hex(4)}"
        canary = LoopbackCanary().start()
        try:
            payload = f"{canary.url}/{nonce}"
            baseline = transport.get(
                build_url(
                    context.base_url,
                    context.path,
                    {**extra, context.parameter: "not-a-url"},
                )
            )
            tested = transport.get(
                build_url(
                    context.base_url,
                    context.path,
                    {**extra, context.parameter: payload},
                )
            )
            hit = canary.wait_for(nonce, timeout_s=2.0)
        finally:
            canary.stop()

        exchanges = [baseline, tested]
        if hit is None:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.1,
                reason=(
                    "the loopback canary received no callback; the server did "
                    "not fetch the supplied URL"
                ),
                exchanges=exchanges,
                detector=self.name,
            )

        finding = Finding(
            vulnerability_type="ssrf",
            title=f"Server-Side Request Forgery in parameter '{context.parameter}'",
            severity="HIGH",
            confidence=0.95,
            target=context.base_url,
            endpoint=context.path,
            parameter=context.parameter,
            original_request=to_exchange_record(baseline),
            tested_request=to_exchange_record(tested),
            baseline_response=to_exchange_record(baseline),
            test_response=to_exchange_record(tested),
            evidence=(
                f"The server fetched the unique loopback URL {payload!r}; the "
                f"canary recorded a callback for path {hit.get('path')!r}. "
                "The callback proves server-side request execution."
            ),
            verification=VerificationRecord(
                verified=True,
                verifier_name="SSRFDetector",
                methodology="Loopback out-of-band canary callback",
                proof_token=nonce,
                reproduced_count=1,
            ),
            reproducibility=ReproducibilityRecord(
                is_reproducible=True,
                reproduction_steps=[
                    "1. Start a loopback listener on a known port",
                    f"2. Set '{context.parameter}' to the listener URL with a unique path",
                    "3. Observe the listener receive the server-side request",
                ],
                reproduction_curl=f"curl -i -s '{tested.probe.url}'",
            ),
            impact=(
                "The server can be coerced into making requests to arbitrary "
                "destinations, which can reach internal services, cloud "
                "metadata, or localhost-only administration interfaces."
            ),
            remediation=(
                "Allowlist destination schemes/hosts, resolve and reject "
                "private/link-local addresses after DNS resolution, disable "
                "unnecessary URL-fetch features, and enforce egress filtering."
            ),
            cwe="CWE-918",
            owasp="A10:2021-Server-Side Request Forgery",
        )
        return Detection(
            vuln_class=self.vuln_class,
            confirmed=True,
            confidence=0.95,
            reason=f"loopback canary received the server-side callback for {nonce}",
            finding=finding,
            exchanges=exchanges,
            detector=self.name,
        )
