"""Open redirect detector.

The detector sends an external URL in the candidate parameter and inspects the
``Location`` header.  Redirects are never followed by the transport, so the
external host is never contacted.  A finding requires a 3xx status and a
``Location`` whose host is the external canary host.
"""
from __future__ import annotations

import secrets
from typing import Dict, Optional
from urllib.parse import urlparse

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

REDIRECT_STATUSES = {301, 302, 303, 307, 308}
EXTERNAL_HOST = "evil.example"


def _header(headers: Dict[str, str], name: str) -> Optional[str]:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


class OpenRedirectDetector:
    name = "open_redirect.location"
    vuln_class = "open_redirect"

    def detect(self, context: DetectionContext, transport: HttpTransport) -> Detection:
        if not context.parameter:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason="a parameter name is required for open-redirect testing",
                detector=self.name,
            )

        extra = dict(context.extra_params)
        nonce = f"hnt{secrets.token_hex(4)}"
        payload = f"https://{EXTERNAL_HOST}/{nonce}"

        def probe(value: str):
            return transport.get(
                build_url(
                    context.base_url,
                    context.path,
                    {**extra, context.parameter: value},
                )
            )

        baseline = probe("/home")
        tested = probe(payload)
        exchanges = [baseline, tested]

        location = _header(tested.response_headers, "Location") or ""
        parsed = urlparse(location)
        is_redirect = tested.status_code in REDIRECT_STATUSES
        is_external = parsed.scheme in {"http", "https"} and (
            parsed.hostname or ""
        ).lower() == EXTERNAL_HOST

        if not (is_redirect and is_external):
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.1,
                reason=(
                    "the response was not a 3xx to the external host "
                    f"(status={tested.status_code}, location={location!r})"
                ),
                exchanges=exchanges,
                detector=self.name,
            )

        finding = Finding(
            vulnerability_type="open_redirect",
            title=f"Open redirect in parameter '{context.parameter}'",
            severity="MEDIUM",
            confidence=0.95,
            target=context.base_url,
            endpoint=context.path,
            parameter=context.parameter,
            original_request=to_exchange_record(baseline),
            tested_request=to_exchange_record(tested),
            baseline_response=to_exchange_record(baseline),
            test_response=to_exchange_record(tested),
            evidence=(
                f"The parameter accepted the external URL {payload!r} and the "
                f"server returned HTTP {tested.status_code} with "
                f"Location: {location!r}."
            ),
            verification=VerificationRecord(
                verified=True,
                verifier_name="OpenRedirectDetector",
                methodology="External Location header with a unique path",
                proof_token=nonce,
                reproduced_count=1,
            ),
            reproducibility=ReproducibilityRecord(
                is_reproducible=True,
                reproduction_steps=[
                    f"1. Request the baseline: {baseline.probe.url}",
                    f"2. Set '{context.parameter}' to {payload!r}",
                    "3. Observe the 3xx Location header pointing at the external host",
                ],
                reproduction_curl=f"curl -i -s '{tested.probe.url}'",
            ),
            impact=(
                "Attackers can craft trusted-domain links that redirect victims "
                "to attacker-controlled sites, enabling phishing and OAuth "
                "token or credential theft."
            ),
            remediation=(
                "Resolve redirect targets against an allowlist of relative paths "
                "or trusted hosts; reject absolute external URLs; never reflect "
                "the raw parameter into Location."
            ),
            cwe="CWE-601",
            owasp="A01:2021-Broken Access Control",
        )
        return Detection(
            vuln_class=self.vuln_class,
            confirmed=True,
            confidence=0.95,
            reason=f"HTTP {tested.status_code} redirects to external host {EXTERNAL_HOST}",
            finding=finding,
            exchanges=exchanges,
            detector=self.name,
        )
