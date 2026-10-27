"""Boolean-based SQL injection detector (read-only).

The detector sends two independent true/false payload pairs.  A finding needs
both pairs to produce a stable differential, the control pair to produce none,
and the payloads not to be reflected verbatim.  It never sends ``UNION``,
``SLEEP``, ``INSERT``, ``UPDATE`` or ``DELETE``.
"""
from __future__ import annotations

from typing import List, Tuple

from core.detectors.contract import (
    Detection,
    DetectionContext,
    build_url,
    normalize_body,
    to_exchange_record,
)
from core.detectors.transport import HttpTransport
from core.finding_model import (
    Finding,
    ReproducibilityRecord,
    VerificationRecord,
)


class SQLiBooleanDetector:
    name = "sqli.boolean"
    vuln_class = "sqli"

    PAIRS: Tuple[Tuple[str, str], ...] = (
        ("' AND '1'='1", "' AND '1'='2"),
        ("' AND '2'='2", "' AND '2'='3"),
    )

    def detect(self, context: DetectionContext, transport: HttpTransport) -> Detection:
        if not context.parameter:
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason="a parameter name is required for boolean SQLi testing",
                detector=self.name,
            )

        exchanges = []
        extra = dict(context.extra_params)

        def probe(value: str):
            return transport.get(
                build_url(
                    context.base_url,
                    context.path,
                    {**extra, context.parameter: value},
                )
            )

        control_a = probe("hnt-control-a")
        control_b = probe("hnt-control-b")
        exchanges.extend([control_a, control_b])
        if normalize_body(control_a.body) != normalize_body(control_b.body):
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.0,
                reason=(
                    "control probes differ; the endpoint echoes input, so a "
                    "body differential cannot be attributed to SQL evaluation"
                ),
                exchanges=exchanges,
                detector=self.name,
            )

        signals: List[Tuple[str, str, object, object]] = []
        for true_payload, false_payload in self.PAIRS:
            true_exchange = probe(true_payload)
            false_exchange = probe(false_payload)
            exchanges.extend([true_exchange, false_exchange])
            if true_exchange.status_code != 200 or false_exchange.status_code != 200:
                continue
            if true_payload in true_exchange.body or false_payload in false_exchange.body:
                continue
            if normalize_body(true_exchange.body) == normalize_body(false_exchange.body):
                continue
            signals.append((true_payload, false_payload, true_exchange, false_exchange))

        if len(signals) < len(self.PAIRS):
            return Detection(
                vuln_class=self.vuln_class,
                confirmed=False,
                confidence=0.2,
                reason=(
                    f"only {len(signals)}/{len(self.PAIRS)} boolean pairs produced "
                    "a stable differential"
                ),
                exchanges=exchanges,
                detector=self.name,
            )

        true_payload, false_payload, true_exchange, false_exchange = signals[0]
        finding = Finding(
            vulnerability_type="sqli",
            title=f"Boolean-based SQL injection in parameter '{context.parameter}'",
            severity="HIGH",
            confidence=0.9,
            target=context.base_url,
            endpoint=context.path,
            parameter=context.parameter,
            original_request=to_exchange_record(control_a),
            tested_request=to_exchange_record(true_exchange),
            baseline_response=to_exchange_record(control_a),
            test_response=to_exchange_record(true_exchange),
            evidence=(
                "Two independent boolean pairs produced a stable response "
                f"differential. TRUE: {true_payload!r} -> "
                f"{normalize_body(true_exchange.body)[:120]!r}; FALSE: "
                f"{false_payload!r} -> {normalize_body(false_exchange.body)[:120]!r}. "
                "The control pair was identical, and neither payload was reflected."
            ),
            verification=VerificationRecord(
                verified=True,
                verifier_name="SQLiBooleanDetector",
                methodology="Two-pair read-only boolean differential with control",
                proof_token=f"{true_payload} != {false_payload}",
                reproduced_count=len(signals),
            ),
            reproducibility=ReproducibilityRecord(
                is_reproducible=True,
                reproduction_steps=[
                    f"1. Request the baseline: {control_a.probe.url}",
                    f"2. Send TRUE payload {true_payload!r} in '{context.parameter}'",
                    f"3. Send FALSE payload {false_payload!r} in '{context.parameter}'",
                    "4. Observe the same body differential in a second payload pair",
                ],
                reproduction_curl=f"curl -i -s '{true_exchange.probe.url}'",
            ),
            impact=(
                "The backend evaluates attacker-controlled SQL boolean "
                "expressions. An attacker can use this to read data the query "
                "was not intended to return."
            ),
            remediation=(
                "Use parameterized queries / prepared statements; never "
                "concatenate input into SQL. Add server-side input validation "
                "as defence in depth, not as the primary fix."
            ),
            cwe="CWE-89",
            owasp="A03:2021-Injection",
        )
        return Detection(
            vuln_class=self.vuln_class,
            confirmed=True,
            confidence=0.9,
            reason=(
                f"{len(signals)}/{len(self.PAIRS)} boolean pairs produced a "
                "stable differential with an identical control pair"
            ),
            finding=finding,
            exchanges=exchanges,
            detector=self.name,
        )
