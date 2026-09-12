"""
Tests for CrossEndpointCorrelator and Developer Assumption Mapping
"""
import pytest

from hunter_ai.runtime import (
    CrossEndpointCorrelator, DataFlowLink, DeveloperAssumption,
    AssumptionKind, EndpointSignature
)


class TestCrossEndpointCorrelator:
    def test_cross_endpoint_dataflow_linkage(self):
        correlator = CrossEndpointCorrelator()

        # Endpoint 1: creates an invoice and produces invoice_id
        correlator.record_endpoint(
            endpoint="/api/invoices/create",
            method="POST",
            input_params=["client_name", "amount"],
            output_fields=["status", "invoice_id", "created_at"]
        )

        # Endpoint 2: consumes invoice_id to export PDF
        correlator.record_endpoint(
            endpoint="/api/invoices/export",
            method="GET",
            input_params=["invoice_id", "format"],
            output_fields=["file_stream"]
        )

        links = correlator.get_correlations()
        assert len(links) == 1
        link = links[0]
        assert link.source_endpoint == "/api/invoices/create"
        assert link.target_endpoint == "/api/invoices/export"
        assert link.shared_identifier == "invoice_id"

    def test_developer_assumption_mapping(self):
        correlator = CrossEndpointCorrelator()

        correlator.record_endpoint(
            endpoint="/api/user/profile",
            method="POST",
            input_params=["user_id", "role", "metadata_json"],
            output_fields=["success"]
        )

        assumptions = correlator.get_assumptions()
        kinds = [a.assumption_kind for a in assumptions]

        # Should detect numeric predictability on user_id
        assert AssumptionKind.NUMERIC_PREDICTABILITY in kinds

        # Should detect hidden privilege flag on role
        assert AssumptionKind.HIDDEN_PRIVILEGE_FLAG in kinds

        # Should detect type strictness confusion on metadata_json
        assert AssumptionKind.TYPE_STRICTNESS_CONFUSION in kinds

    def test_generate_cross_endpoint_hypotheses(self):
        correlator = CrossEndpointCorrelator()

        correlator.record_endpoint(
            endpoint="/api/orders/new",
            method="POST",
            output_fields=["order_id"]
        )
        correlator.record_endpoint(
            endpoint="/api/orders/view",
            method="GET",
            input_params=["order_id"]
        )

        hypotheses = correlator.generate_cross_endpoint_hypotheses()
        assert len(hypotheses) == 1
        h = hypotheses[0]
        assert h["category"] == "IDOR"
        assert "/api/orders/new" in h["source_endpoint"]
        assert "/api/orders/view" in h["target_endpoint"]
        assert h["shared_identifier"] == "order_id"
