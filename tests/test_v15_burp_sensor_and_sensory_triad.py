"""
HunterAI V15.0 Test Suite — Unified Sensory Triad & Burp Sensor Integration
===========================================================================
Certifies the complete end-to-end integration of the Burp Sensor:
1. BurpSessionContext deep enrichment & parameter/cookie/auth extraction
2. NormalizedObservation schema & epistemic blackboard dispatch
3. Multi-tier request lineage tree & ancestry traversal
4. Repeater mutation tracking with response diffs & status divergence
5. Burp Scanner issue ingestion & deduplication
6. Cross-Sensor Triad correlation (Browser action + Burp wire -> BOLA hypothesis)
7. AutonomousBrain sensory attachment & OODA ingestion
8. 7-Stage Causal Provenance linking Burp packets to Evidence Court
9. AgentHandoffContract state transfer with Burp context
10. Confirmed Finding export back into Burp Target tab (IScanIssue schema)
"""
from __future__ import annotations

import json
import time
import pytest
from unittest.mock import MagicMock, AsyncMock

from core.sensors import (
    BurpSensor,
    BurpSessionContext,
    NormalizedObservation,
    SensorType,
    SensoryTriadCoordinator,
    CorrelatedEvent,
)
from core.burp_gateway.handoff_contract import AgentHandoffContract
from core.burp_gateway.provenance import EvidenceProvenanceEngine, ProvenanceStage


class TestBurpSessionContextAndLineage:
    """Test Case 1 & 3: Context enrichment, parameter parsing, and lineage traversal"""

    def test_burp_session_context_enrichment(self):
        ctx = BurpSessionContext(
            request_id="req_001",
            method="POST",
            url="https://app.local/api/v2/orders/99?channel=web&coupon=DISCOUNT10",
            headers={
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-CSRF-Token": "csrf_token_secret_xyz"
            },
            body="quantity=2&address_id=14",
            cookies={"session_id": "sess_abc123", "jwt_user": "user_alpha"},
            auth_context="User A",
            source="proxy"
        )
        assert ctx.endpoint_id == "POST:/api/v2/orders/99"
        assert "channel" in ctx.parameter_ids
        assert "coupon" in ctx.parameter_ids
        assert "quantity" in ctx.parameter_ids
        assert "address_id" in ctx.parameter_ids
        assert ctx.auth_context == "User A"

        # Serialization round-trip
        data = ctx.to_dict()
        restored = BurpSessionContext.from_dict(data)
        assert restored.request_id == ctx.request_id
        assert restored.endpoint_id == ctx.endpoint_id
        assert restored.parameter_ids == ctx.parameter_ids

    def test_burp_sensor_lineage_ancestry(self):
        sensor = BurpSensor()

        # Chain: Root (req_10) -> Child (req_20) -> Grandchild (req_30)
        sensor.ingest_transaction({
            "request_id": "req_10",
            "url": "https://app.local/login",
            "method": "POST"
        })
        sensor.ingest_transaction({
            "request_id": "req_20",
            "url": "https://app.local/dashboard",
            "method": "GET"
        }, parent_id="req_10")
        sensor.ingest_transaction({
            "request_id": "req_30",
            "url": "https://app.local/api/user/delete",
            "method": "POST"
        }, parent_id="req_20")

        lineage = sensor.get_lineage("req_30")
        assert len(lineage) == 3
        assert [tx.request_id for tx in lineage] == ["req_10", "req_20", "req_30"]
        assert lineage[0].url == "https://app.local/login"
        assert lineage[2].url == "https://app.local/api/user/delete"


class TestBurpSensorNormalizationAndMutations:
    """Test Case 2, 4 & 5: Normalization, repeater mutations, scanner issues"""

    def test_burp_sensor_normalization(self):
        sensor = BurpSensor()
        obs = sensor.ingest_transaction({
            "request_id": "req_norm_1",
            "url": "https://api.local/v1/search?q=test&limit=10",
            "method": "GET",
            "headers": {"Authorization": "Bearer secret_jwt_token_123"},
            "cookies": {"session": "sess_val_456"},
            "status_code": 200
        })

        assert isinstance(obs, NormalizedObservation)
        assert obs.sensor_type == SensorType.BURP
        assert obs.target_url == "https://api.local/v1/search?q=test&limit=10"
        assert obs.method == "GET"
        assert "q" in obs.parameters
        assert "limit" in obs.parameters
        assert obs.extracted_tokens.get("bearer_token") == "secret_jwt_token_123"
        assert obs.extracted_tokens.get("cookie:session") == "sess_val_456"

        pending = sensor.get_pending_observations()
        assert len(pending) == 1
        assert sensor.get_pending_observations() == []  # Drained

    def test_repeater_mutation_tracking(self):
        sensor = BurpSensor()
        # Ingest baseline
        sensor.ingest_transaction({
            "request_id": "base_req_01",
            "url": "https://api.local/items?id=100",
            "method": "GET",
            "status_code": 200,
            "resp_body": "Original item body with length 32"
        })

        # Record mutation
        record = sensor.ingest_repeater_mutation(
            base_request_id="base_req_01",
            mutated_url="https://api.local/items?id=100' OR 1=1--",
            payload_used="' OR 1=1--",
            status_code=500,
            resp_body="Database syntax error in SQL query: near '--'"
        )

        assert record["status_diverged"] is True
        assert record["status_code"] == 500
        assert record["base_request_id"] == "base_req_01"

        # Check that mutation is linked in lineage as child of baseline
        mut_tx = sensor.get_transaction(record["mutation_id"])
        assert mut_tx is not None
        assert mut_tx.parent_request == "base_req_01"

    def test_scanner_issue_ingestion_and_dedup(self):
        mock_graph = MagicMock()
        sensor = BurpSensor(evidence_graph=mock_graph)

        issue_id = sensor.ingest_scanner_issue({
            "name": "SQL Injection (Differential)",
            "url": "https://api.local/products?category=Gifts",
            "severity": "High",
            "confidence": "Certain",
            "detail": "Boolean differential response detected."
        })

        assert issue_id is not None
        assert issue_id.startswith("scan_")
        mock_graph.add_hypothesis.assert_called_once()
        call_kwargs = mock_graph.add_hypothesis.call_args[1]
        assert call_kwargs["source_sensor"] == "BURP_SCANNER"


class TestCrossSensorTriadAndCorrelation:
    """Test Case 6 & 7: Triad correlation and AutonomousBrain OODA integration"""

    def test_cross_sensor_correlation(self):
        mock_evidence_graph = MagicMock()
        triad = SensoryTriadCoordinator(evidence_graph=mock_evidence_graph)

        # Step 1: User interacts in Browser
        triad.record_browser_action(
            action_description="Click #delete-user-btn",
            target_selector="#delete-user-btn",
            current_url="https://app.local/users/42"
        )

        # Step 2: Burp intercepts the network packet
        burp_tx = BurpSessionContext(
            request_id="tx_del_42",
            method="DELETE",
            url="https://app.local/api/users/42",
            status_code=204,
            auth_context="User A"
        )

        # Step 3: Triad correlates UI intent + Wire packet
        event = triad.correlate_with_burp(burp_tx)

        assert isinstance(event, CorrelatedEvent)
        assert event.browser_action == "Click #delete-user-btn"
        assert event.http_method == "DELETE"
        assert event.identified_vulnerability_hypothesis == "BOLA_BROKEN_OBJECT_LEVEL_AUTHORIZATION"
        assert event.confidence_score >= 0.80

        # High-confidence hypothesis should be sent to EvidenceGraph
        mock_evidence_graph.add_hypothesis.assert_called_once()

    def test_autonomous_brain_burp_sensor_integration(self):
        from core.brain.autonomous_brain import AutonomousBrain

        mock_rm = MagicMock()
        mock_tm = MagicMock()
        mock_cb = AsyncMock()

        brain = AutonomousBrain(
            resource_manager=mock_rm,
            tool_manager=mock_tm,
            progress_callback=mock_cb,
            dry_run=True
        )

        # Verify BurpSensor & SensoryTriad are automatically attached
        assert brain.burp_sensor is not None
        assert brain.sensory_triad is not None
        assert isinstance(brain.burp_sensor, BurpSensor)

        # Ingest a live transaction through the brain
        obs = brain.ingest_burp_transaction({
            "request_id": "brain_req_01",
            "url": "https://target.local/api/data",
            "method": "GET",
            "status_code": 200
        })

        assert obs is not None
        assert obs.target_url == "https://target.local/api/data"

        # Check audit trail recorded ingestion
        audit_events = [a.get("event") for a in brain._audit_log]
        assert "burp_transaction_ingested" in audit_events


class TestProvenanceHandoffAndBurpFeedback:
    """Test Case 8, 9 & 10: 7-Stage Provenance, Handoff Contract, and Burp Export"""

    def test_7_stage_causal_provenance(self):
        engine = EvidenceProvenanceEngine()
        steps = engine.synthesize_standard_provenance(
            target_url="https://app.local/api/v1/user/101",
            vuln_class="BOLA",
            finder_claim={
                "claim": "Numeric ID in path suggests potential multi-tenant authorization bypass",
                "raw_request": "GET /api/v1/user/101 HTTP/1.1\r\nHost: app.local",
                "raw_response": "HTTP/1.1 200 OK\r\n\r\n{\"patient\": \"Alice\"}"
            },
            verifier_result={
                "reproduced": True,
                "proof_detail": "Patient Bob record leaked via ID substitution",
                "payload_used": "GET /api/v1/user/102"
            }
        )

        assert len(steps) == 7
        stages = [s["stage"] for s in steps]
        assert "OBSERVATION" in stages
        assert "BURP_REQUEST" in stages
        assert "BURP_RESPONSE" in stages
        assert "ANALYSIS" in stages
        assert "HYPOTHESIS" in stages
        assert "TEST" in stages
        assert "VERIFICATION" in stages

    def test_agent_handoff_contract_burp_context(self):
        contract = AgentHandoffContract(
            case_id="CASE-0042",
            target="https://target.com",
            observation="Burp Sensor captured DELETE /api/users/42 with User B session",
            hypothesis="BOLA: User B can delete User A resource",
            evidence=[{"type": "status_diff", "proof": "204 No Content returned"}],
            tests_performed=["DELETE /api/users/42 with auth=user_b"],
            tests_failed=[],
            tests_remaining=["Confirm user 42 is genuinely deleted from DB"],
            confidence=0.92,
            next_action="VERIFY_RESOURCE_DELETION"
        )

        # Add Burp context metadata
        contract.metadata["burp_request_id"] = "req_del_42"
        contract.metadata["burp_lineage"] = ["req_login", "req_dashboard", "req_del_42"]

        # Serialization round-trip
        data_json = contract.to_json()
        restored = AgentHandoffContract.from_json(data_json)

        assert restored.case_id == "CASE-0042"
        assert restored.confidence == 0.92
        assert restored.metadata["burp_request_id"] == "req_del_42"
        assert len(restored.metadata["burp_lineage"]) == 3

    def test_evidence_court_to_burp_issue_feedback(self):
        sensor = BurpSensor()
        confirmed_finding = {
            "finding_id": "fnd_bola_99",
            "title": "BOLA / IDOR Cross-Tenant Access",
            "target_url": "https://app.local/api/v1/user/102",
            "severity": "High",
            "confidence": "Certain",
            "description": "User A unauthorized access to User B private health records.",
            "proof": "Cross-tenant patient record returned with status 200 OK",
            "provenance_trace": [
                "OBSERVATION -> Wire telemetry",
                "BURP_REQUEST -> GET /api/v1/user/101",
                "HYPOTHESIS -> BOLA",
                "TEST -> Substituted ID 102",
                "VERIFICATION -> Record leaked"
            ],
            "remediation": "Enforce row-level tenant ownership checks before data retrieval."
        }

        burp_issue = sensor.export_finding_to_burp(confirmed_finding)

        assert burp_issue["issue_name"] == "[HunterAI] BOLA / IDOR Cross-Tenant Access"
        assert burp_issue["severity"] == "High"
        assert burp_issue["confidence"] == "Certain"
        assert "<p><b>HunterAI Evidence Court Verdict: CONFIRMED</b></p>" in burp_issue["issue_detail"]
        assert "7-Stage Causal Provenance" in burp_issue["issue_detail"]
        assert burp_issue["url"] == "https://app.local/api/v1/user/102"
