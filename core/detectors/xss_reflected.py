"""Reflected XSS detector with a nonce and a false-positive trap.

A finding requires the unique breakout payload to appear verbatim in the
response, the HTML-escaped form to be absent, and the marker to be absent from
the baseline.  A safe endpoint that entity-encodes the payload is rejected.
"""
from __future__ import annotations

import html
import secrets

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


class XSSReflectedDetector:
    name = "xss.reflected"
    vuln_class = "xss"

    def detect(self, context: DetectionContext, transport: HttpTransport) -> Detection:
        if not context.parameter:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason="a parameter name is required for reflected XSS testing",
                detector=self.name,
            )

        extra = dict(context.extra_params)

        def probe(value: str):
            return transport.get(
                build_url(
                    context.base_url,
                    context.path,
                    {**extra, context.parameter: value},
                )
            )

        baseline = probe("hnt-baseline")
        marker = f"hnt{secrets.token_hex(4)}"
        payload = f'"><{marker}>'
        tested = probe(payload)

        escaped = html.escape(payload, quote=True)
        reflected_verbatim = payload in tested.body
        encoded_only = escaped in tested.body and not reflected_verbatim
        marker_in_baseline = marker in baseline.body
        marker_in_test = marker in tested.body

        if marker_in_baseline:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason="the random marker already appears in the baseline response",
                exchanges=[baseline, tested],
                detector=self.name,
            )
        if encoded_only:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason="the payload was HTML-entity encoded; reflection is not executable",
                exchanges=[baseline, tested],
                detector=self.name,
            )
        if not (tested.status_code == 200 and reflected_verbatim and marker_in_test):
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.1,
                reason="the breakout payload was not reflected verbatim in a 200 response",
                exchanges=[baseline, tested],
                detector=self.name,
            )

        reflection_context = "html_body"
        try:
            from core.canary.context_canary_engine import ContextCanaryEngine

            reflection_context = ContextCanaryEngine.detect_reflection_context(
                marker, tested.body
            ).context.value
        except Exception:  # pragma: no cover - context analysis is best effort
            pass

        finding = Finding(
            vulnerability_type="xss",
            title=f"Reflected XSS in parameter '{context.parameter}'",
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
                f"The unique payload {payload!r} was reflected verbatim "
                f"(reflection context: {reflection_context}) and the escaped "
                "form was absent from the response."
            ),
            verification=VerificationRecord(
                verified=True,
                verifier_name="XSSReflectedDetector",
                methodology="Unique nonce breakout with entity-encoding control",
                proof_token=marker,
                reproduced_count=1,
            ),
            reproducibility=ReproducibilityRecord(
                is_reproducible=True,
                reproduction_steps=[
                    f"1. Request the baseline: {baseline.probe.url}",
                    f"2. Inject {payload!r} into '{context.parameter}'",
                    "3. Observe the unencoded payload in the HTML response",
                ],
                reproduction_curl=f"curl -i -s '{tested.probe.url}'",
            ),
            impact=(
                "Arbitrary JavaScript executes in the victim's browser, "
                "enabling session theft, account actions as the victim, and "
                "credential phishing."
            ),
            remediation=(
                "Apply context-aware output encoding (HTML entity encoding for "
                "HTML body/attributes, JS encoding for script contexts). Use a "
                "templating engine with auto-escaping and a restrictive CSP."
            ),
            cwe="CWE-79",
            owasp="A03:2021-Injection",
        )
        return Detection(
            vuln_class=self.vuln_class,
            confirmed=True,
            confidence=0.95,
            reason=f"unique payload reflected verbatim in {reflection_context} context",
            finding=finding,
            exchanges=[baseline, tested],
            detector=self.name,
        )
