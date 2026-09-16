"""
Tests for Extensible Causal Invariants Framework
"""
import pytest
from core.reasoning.causal_invariants import (
    AuthorizationInvariant,
    BooleanDifferentialInvariant,
    CommandExecutionInvariant,
    DOMExecutionInvariant,
    OOBCorrelationInvariant,
    StateTransitionInvariant,
)
from core.reasoning.triad_verifier import TransactionSnapshot, TriadBundle


def test_command_execution_invariant():
    inv = CommandExecutionInvariant(expected_token="72", e1_expr="53+19", e2_expr="41+31")
    bundle = TriadBundle(
        hypothesis_id="h1",
        target_endpoint="/calc",
        baseline=TransactionSnapshot(body="Clean"),
        control=TransactionSnapshot(body="Param: 53"),
        experiment_1=TransactionSnapshot(body="Result: 72"),
        experiment_2=TransactionSnapshot(body="Result: 72"),
    )
    res = inv.evaluate(bundle)
    assert res.passed is True
    assert res.confidence > 0.95


def test_command_execution_invariant_literal_reflection():
    inv = CommandExecutionInvariant(expected_token="72", e1_expr="53+19", e2_expr="41+31")
    bundle = TriadBundle(
        hypothesis_id="h2",
        target_endpoint="/calc",
        baseline=TransactionSnapshot(body="Clean"),
        control=TransactionSnapshot(body="echo"),
        experiment_1=TransactionSnapshot(body='<script>var x = "$((53+19))";</script>'),
        experiment_2=TransactionSnapshot(body='<script>var x = "$((41+31))";</script>'),
    )
    res = inv.evaluate(bundle)
    assert res.passed is False
    assert res.invalidation_triggered is True
    assert "Literal reflection detected" in res.reason


def test_authorization_invariant():
    inv = AuthorizationInvariant(resource_id="doc_secret", owner_id="user_bob", actor_id="user_alice")
    bundle_denied = TriadBundle(
        hypothesis_id="h3",
        target_endpoint="/doc",
        baseline=TransactionSnapshot(status_code=200),
        control=TransactionSnapshot(status_code=404),
        experiment_1=TransactionSnapshot(status_code=403, body="Forbidden: Access Denied"),
        experiment_2=TransactionSnapshot(status_code=403, body="Forbidden: Access Denied"),
    )
    res_denied = inv.evaluate(bundle_denied)
    assert res_denied.passed is True
    assert "Authorization Invariant enforced" in res_denied.reason


def test_dom_execution_invariant():
    inv = DOMExecutionInvariant(canary="xss777")
    bundle_executed = TriadBundle(
        hypothesis_id="h4",
        target_endpoint="/search",
        baseline=TransactionSnapshot(),
        control=TransactionSnapshot(),
        experiment_1=TransactionSnapshot(body='<div><img src=x onerror=alert("xss777")></div>'),
        experiment_2=TransactionSnapshot(body='<div><svg onload=alert("xss777")></div>'),
    )
    res = inv.evaluate(bundle_executed)
    assert res.passed is True
    assert res.extracted_observables.get("dom_breakout_confirmed") is True
