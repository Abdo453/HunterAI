"""
Tests for Nuanced Negative Evidence & Boundary Scoping
"""
import pytest
from core.reasoning.negative_evidence import (
    BoundaryScope,
    NegativeObservation,
    NuancedNegativeEvidenceLedger,
)


def test_negative_evidence_scoped_boundary():
    ledger = NuancedNegativeEvidenceLedger()

    scope_42 = BoundaryScope(
        endpoint="/api/v1/orders/42",
        http_method="GET",
        actor_id="user_alice",
        target_resource_id="42",
        target_tenant_id="tenant_bob",
    )

    obs = ledger.record_defense(
        scope=scope_42,
        status_code=403,
        body_snippet="Access Denied",
        provenance_id="prov_001",
    )

    assert obs.conclusion == "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT"
    assert obs.unexplored_transitions_status == "UNKNOWN"

    assert ledger.is_exact_context_tested(scope_42) is True
    assert ledger.get_boundary_status(scope_42) == "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT"

    scope_43 = BoundaryScope(
        endpoint="/api/v1/orders/43",
        http_method="GET",
        actor_id="user_alice",
        target_resource_id="43",
        target_tenant_id="tenant_bob",
    )
    assert ledger.is_exact_context_tested(scope_43) is False
    assert ledger.get_boundary_status(scope_43) == "UNKNOWN"
