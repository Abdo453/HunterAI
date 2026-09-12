"""
Unit Tests for Evidence Engine
Tests: EvidenceCollector (SHA256 fingerprinting), EvidenceCorrelator (Differential matching), and EvidenceValidator
"""
import pytest
from core.evidence.collector import EvidenceCollector
from core.evidence.correlator import EvidenceCorrelator
from core.evidence.validator import EvidenceValidator
from agents.security_intelligence.schemas import EvidenceItem, EvidenceType


class TestEvidenceEngine:
    def test_evidence_collector_hashes_and_structures(self):
        collector = EvidenceCollector()
        item = collector.collect_http_evidence(
            target_url="https://api.target.local/invoices",
            method="GET",
            request_headers={"Authorization": "Bearer token123"},
            request_body="",
            status_code=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"invoice_id": 100, "amount": 500}',
            duration=0.15
        )

        assert item.type == EvidenceType.RESPONSE
        assert item.data["status_code"] == 200
        assert "sha256_fingerprint" in item.data
        assert len(item.data["sha256_fingerprint"]) == 64
        assert item.verified is True

    def test_evidence_correlator_detects_differential(self):
        collector = EvidenceCollector()
        correlator = EvidenceCorrelator()

        ev_alice = collector.collect_http_evidence(
            target_url="https://api.target.local/invoices/100",
            method="GET",
            request_headers={"X-User": "Alice"},
            request_body="",
            status_code=200,
            response_headers={},
            response_body='{"owner": "Alice", "data": "private_alice"}',
            duration=0.10
        )

        ev_bob = collector.collect_http_evidence(
            target_url="https://api.target.local/invoices/100",
            method="GET",
            request_headers={"X-User": "Bob"},
            request_body="",
            status_code=200,
            response_headers={},
            response_body='{"owner": "Bob", "data": "private_bob"}',
            duration=0.12
        )

        diff_item = correlator.correlate_differential(
            baseline_evidence=ev_alice,
            probe_evidence=ev_bob,
            context_description="BOLA check on invoice 100"
        )

        assert diff_item.type == EvidenceType.BEHAVIOR_DIFF
        assert diff_item.data["is_both_200"] is True
        assert diff_item.data["has_content_diff"] is True
        assert diff_item.verified is True
        assert diff_item.weight >= 0.90

    def test_evidence_validator_accepts_conclusive_evidence(self):
        validator = EvidenceValidator()

        valid_items = [
            EvidenceItem(type=EvidenceType.BEHAVIOR_DIFF, source="correlator", description="diff", weight=0.90),
            EvidenceItem(type=EvidenceType.STATUS_CODE, source="probe", description="status", weight=0.60)
        ]
        is_valid, msg = validator.validate_evidence_chain(valid_items)
        assert is_valid is True
        assert "Evidence chain verified" in msg

    def test_evidence_validator_rejects_weak_evidence(self):
        validator = EvidenceValidator()

        weak_items = [
            EvidenceItem(type=EvidenceType.STATUS_CODE, source="probe", description="status only", weight=0.50),
            EvidenceItem(type=EvidenceType.RESPONSE, source="probe", description="response only", weight=0.50)
        ]
        is_valid, reject_msg = validator.validate_evidence_chain(weak_items)
        assert is_valid is False
        assert "lacks conclusive differential" in reject_msg
