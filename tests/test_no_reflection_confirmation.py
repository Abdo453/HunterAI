"""LEDGER-015 (M1c): reflection, free text and assumed signals never confirm.

Pins the fail-closed contracts for the four "empty confirmation" defects found in
the audit:
  * `IndependentVerifier` no longer proves XSS from a reflected payload
    (reflection != execution).
  * `SensorSignals` defaults to ABSENT, so an unprobed finding cannot reach
    agreement_ratio == 1.0 and be confirmed.
  * `ConfidenceFactors` defaults fail closed and yield a low score.
  * XSS has no deterministic Proof-of-Execution signature, so it can never be
    "derived" by the Evidence Court.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from core.evidence_court import ProofPayload
from core.independent_verifier import IndependentVerifier
from core.scoring.confidence_calculator import (
    ConfidenceFactors,
    MultidimensionalConfidenceCalculator,
)
from core.scoring.tool_agreement import SensorSignals, ToolAgreementEngine


def _make_resp(text: str, status_code: int = 200) -> httpx.Response:
    req = httpx.Request("GET", "http://test")
    return httpx.Response(status_code=status_code, text=text, headers={}, request=req)


@pytest.mark.asyncio
async def test_independent_verifier_rejects_xss_reflection():
    verifier = IndependentVerifier()
    mock_client = AsyncMock()
    # baseline, exploit probe (payload reflected verbatim), control
    mock_client.get.side_effect = [
        _make_resp("<html>baseline page</html>"),
        _make_resp("<html>here it is: test<tagxyz>123 in the body</html>"),
        _make_resp("<html>clean control page</html>"),
    ]
    with patch("httpx.AsyncClient") as mock_cls:
        mock_cls.return_value.__aenter__.return_value = mock_client
        res = await verifier.verify_endpoint_vulnerability(
            "https://target.local/api/search", "q", "xss"
        )
    assert res["is_proven"] is False
    assert res["status"] == "FALSE_POSITIVE_REJECTED"
    assert "reflection" in res["reason"].lower()


def test_sensor_signals_default_to_absent():
    sig = SensorSignals()
    assert sig.browser_dom_executed is False
    assert sig.http_diff_confirmed is False
    assert sig.poe_token_verified is False
    assert sig.waf_blocked is False

    res = ToolAgreementEngine.evaluate(sig)
    assert res["is_valid"] is False
    assert res["verdict"] != "CONFIRMED"


def test_confidence_factors_default_fail_closed():
    score = MultidimensionalConfidenceCalculator.calculate(ConfidenceFactors())
    assert score < 0.60


def test_xss_has_no_deterministic_proof_signature():
    assert ProofPayload.from_vuln_evidence("xss", "<script>alert(1)</script>") is None
