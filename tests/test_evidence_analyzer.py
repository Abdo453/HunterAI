"""
Unit Tests for EvidenceAnalyzer — Evidence Structuring, Weighting & Chain Evaluation
Tests: build_evidence_item, evaluate_evidence_chain (empty, single, mixed, conclusive)
"""
import pytest
from agents.security_intelligence.evidence_analyzer import EvidenceAnalyzer
from agents.security_intelligence.schemas import EvidenceItem, EvidenceType


class TestBuildEvidenceItem:
    """build_evidence_item should construct correctly typed and weighted items"""

    def test_behavior_diff_gets_high_weight(self):
        analyzer = EvidenceAnalyzer()
        item = analyzer.build_evidence_item(
            evidence_type=EvidenceType.BEHAVIOR_DIFF,
            source="burp_agent",
            description="User A got 200, User B got 200 with different data",
            data={"user_a_status": 200, "user_b_status": 200}
        )
        assert item.type == EvidenceType.BEHAVIOR_DIFF
        assert item.weight == 0.90
        assert item.verified is True
        assert item.source == "burp_agent"

    def test_status_code_gets_medium_weight(self):
        analyzer = EvidenceAnalyzer()
        item = analyzer.build_evidence_item(
            evidence_type=EvidenceType.STATUS_CODE,
            source="proxy",
            description="Got 200 OK",
            data={"status": 200}
        )
        assert item.weight == 0.60

    def test_custom_weight_overrides_default(self):
        analyzer = EvidenceAnalyzer()
        item = analyzer.build_evidence_item(
            evidence_type=EvidenceType.STATUS_CODE,
            source="manual",
            description="Custom weighted",
            data={},
            custom_weight=0.95
        )
        assert item.weight == 0.95

    def test_auth_anomaly_weight(self):
        analyzer = EvidenceAnalyzer()
        item = analyzer.build_evidence_item(
            evidence_type=EvidenceType.AUTH_ANOMALY,
            source="auth_analyzer",
            description="Token valid for wrong user",
            data={"detail": "horizontal bypass"}
        )
        assert item.weight == 0.85

    def test_cve_match_weight(self):
        analyzer = EvidenceAnalyzer()
        item = analyzer.build_evidence_item(
            evidence_type=EvidenceType.CVE_MATCH,
            source="cve_db",
            description="CVE-2024-1234 matched",
            data={"cve": "CVE-2024-1234"}
        )
        assert item.weight == 0.85


class TestEvaluateEvidenceChain:
    """evaluate_evidence_chain should calculate cumulative weight and conclusiveness"""

    def test_empty_chain(self):
        analyzer = EvidenceAnalyzer()
        result = analyzer.evaluate_evidence_chain([])
        assert result["total_weight"] == 0.0
        assert result["is_conclusive"] is False
        assert result["has_behavioral_diff"] is False

    def test_single_behavior_diff_conclusive(self):
        analyzer = EvidenceAnalyzer()
        items = [EvidenceItem(
            type=EvidenceType.BEHAVIOR_DIFF,
            source="test",
            description="Cross-user confirmed",
            data={},
            weight=0.90
        )]
        result = analyzer.evaluate_evidence_chain(items)
        assert result["has_behavioral_diff"] is True
        assert result["total_weight"] > 0.75
        assert result["is_conclusive"] is True
        assert result["evidence_count"] == 1

    def test_single_status_code_not_conclusive(self):
        analyzer = EvidenceAnalyzer()
        items = [EvidenceItem(
            type=EvidenceType.STATUS_CODE,
            source="test",
            description="200 OK",
            data={},
            weight=0.60
        )]
        result = analyzer.evaluate_evidence_chain(items)
        assert result["is_conclusive"] is False
        assert result["has_behavioral_diff"] is False

    def test_mixed_evidence_with_diff_is_conclusive(self):
        analyzer = EvidenceAnalyzer()
        items = [
            EvidenceItem(type=EvidenceType.BEHAVIOR_DIFF, source="a", description="diff found",
                         data={}, weight=0.90),
            EvidenceItem(type=EvidenceType.AUTH_ANOMALY, source="b", description="token reuse",
                         data={}, weight=0.85),
            EvidenceItem(type=EvidenceType.STATUS_CODE, source="c", description="200 OK",
                         data={}, weight=0.60),
        ]
        result = analyzer.evaluate_evidence_chain(items)
        assert result["is_conclusive"] is True
        assert result["has_behavioral_diff"] is True
        assert result["evidence_count"] == 3
        assert result["total_weight"] > 0.70

    def test_multiple_weak_evidence_not_conclusive(self):
        analyzer = EvidenceAnalyzer()
        items = [
            EvidenceItem(type=EvidenceType.REQUEST, source="a", description="request captured",
                         data={}, weight=0.40),
            EvidenceItem(type=EvidenceType.RESPONSE, source="b", description="response captured",
                         data={}, weight=0.50),
        ]
        result = analyzer.evaluate_evidence_chain(items)
        assert result["is_conclusive"] is False
        assert result["has_behavioral_diff"] is False

    def test_summary_contains_count(self):
        analyzer = EvidenceAnalyzer()
        items = [
            EvidenceItem(type=EvidenceType.STATUS_CODE, source="x", description="ok",
                         data={}, weight=0.60)
        ]
        result = analyzer.evaluate_evidence_chain(items)
        assert "1 evidence items" in result["summary"]
