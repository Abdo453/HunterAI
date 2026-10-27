"""Differential IDOR detector.

The detector needs two identities and a marker that only the owner should see.
It fetches the same resource as the owner, as a second user, and (optionally)
anonymously.  A finding requires the owner to read the marker and a different
identity to read the same marker from the same resource.
"""
from __future__ import annotations

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


class IDORDetector:
    name = "idor.differential"
    vuln_class = "idor"

    def detect(self, context: DetectionContext, transport: HttpTransport) -> Detection:
        if not context.owner_marker:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason=(
                    "owner_marker is required: without a canary that only the "
                    "owner should see, a 200 response cannot prove object-level "
                    "authorization is missing"
                ),
                detector=self.name,
            )
        if not context.owner_headers or not context.other_headers:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason="two identities (owner_headers and other_headers) are required",
                detector=self.name,
            )

        url = build_url(
            context.base_url,
            context.path,
            {**context.extra_params, context.id_parameter: context.resource_id},
        )
        owner = transport.get(url, context.owner_headers)
        other = transport.get(url, context.other_headers)
        exchanges = [owner, other]

        if owner.status_code != 200 or context.owner_marker not in owner.body:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.1,
                reason=(
                    "the owner could not read the canary (status "
                    f"{owner.status_code}); the resource is not proven private"
                ),
                exchanges=exchanges,
                detector=self.name,
            )

        anonymous = None
        if context.check_anonymous:
            anonymous = transport.get(url)
            exchanges.append(anonymous)

        other_can_read = other.status_code == 200 and context.owner_marker in other.body
        anon_can_read = bool(
            anonymous
            and anonymous.status_code == 200
            and context.owner_marker in anonymous.body
        )

        if not other_can_read and not anon_can_read:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.1,
                reason=(
                    "the second identity was denied (status "
                    f"{other.status_code}); object-level authorization held"
                ),
                exchanges=exchanges,
                detector=self.name,
            )

        severity = "CRITICAL" if anon_can_read else "HIGH"
        access_label = (
            "an unauthenticated client" if anon_can_read else "a second authenticated user"
        )
        finding = Finding(
            vulnerability_type="idor",
            title=(
                f"IDOR: {access_label} can read resource "
                f"{context.resource_id!r} via '{context.id_parameter}'"
            ),
            severity=severity,
            confidence=0.95,
            target=context.base_url,
            endpoint=context.path,
            parameter=context.id_parameter,
            original_request=to_exchange_record(owner),
            tested_request=to_exchange_record(anonymous if anon_can_read else other),
            baseline_response=to_exchange_record(owner),
            test_response=to_exchange_record(anonymous if anon_can_read else other),
            evidence=(
                "The owner response contained the private canary "
                f"{context.owner_marker!r}. {access_label.capitalize()} received "
                f"HTTP { (anonymous if anon_can_read else other).status_code } "
                "with the same canary for the same object id."
            ),
            verification=VerificationRecord(
                verified=True,
                verifier_name="IDORDetector",
                methodology="Two-identity differential with an owner-only canary",
                proof_token=context.owner_marker,
                reproduced_count=1,
            ),
            reproducibility=ReproducibilityRecord(
                is_reproducible=True,
                reproduction_steps=[
                    f"1. Read {url} as the owner; confirm the canary is present",
                    f"2. Read the same URL as {access_label}",
                    "3. Observe the same canary in the response",
                ],
                reproduction_curl=f"curl -i -s '{url}'",
            ),
            impact=(
                "A user can read another user's object by changing an "
                "identifier. This is a horizontal privilege escalation and can "
                "expose personal or business data at scale."
            ),
            remediation=(
                "Enforce object-level authorization on every request: resolve "
                "the object from the session identity, not from a client-supplied "
                "id. Use unguessable ids as defence in depth, not as the control."
            ),
            cwe="CWE-639",
            owasp="A01:2021-Broken Access Control",
        )
        return Detection(
            vuln_class=self.vuln_class,
            confirmed=True,
            confidence=0.95,
            reason=(
                f"{access_label} read the owner-only canary from resource "
                f"{context.resource_id!r}"
            ),
            finding=finding,
            exchanges=exchanges,
            detector=self.name,
        )
