"""
Unit and Integration Tests for Safe SQL Injection Assessment Skill (v2.0)
========================================================================
Covers ScopeGate, ResponseNormalizer, ParameterClassifier, ContextInference,
DifferentialSQLiEngine, SecondOrderTracker, CodeORMAuditor, and ReportGenerator.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from agents.skills.safe_sqli_assessment import (
    ScopePolicy, ScopeGate, ResponseNormalizer,
    BaselineProfile, ParameterProfile, ParameterClassifier, ParameterType, ParameterLocation,
    SQLiContextType, DifferentialSQLiEngine, DifferentialResult,
    SecondOrderTracker, CodeORMAuditor, ReportGenerator,
    ConfidenceLevel, FindingClassification, SafeSQLiFinding,
    SafeSQLiAssessmentSkill, statistics_median
)


# ─── 1. Scope Gate Tests ──────────────────────────────────────────────────────

class TestScopeGate:
    def test_in_scope_domain(self):
        policy = ScopePolicy(allowed_domains=["example.com", "api.target.net"])
        gate = ScopeGate(policy)

        res1 = gate.evaluate("https://example.com/products?id=1", "GET")
        assert res1["allowed"] is True

        res2 = gate.evaluate("https://sub.api.target.net/search", "GET")
        assert res2["allowed"] is True

    def test_out_of_scope_domain(self):
        policy = ScopePolicy(allowed_domains=["example.com"])
        gate = ScopeGate(policy)

        res = gate.evaluate("https://malicious-other-site.com/test", "GET")
        assert res["allowed"] is False
        assert "OUT OF SCOPE" in res["reason"]

    def test_forbidden_method_blocked(self):
        policy = ScopePolicy(allowed_domains=["*"], forbidden_methods=["DELETE", "PUT"])
        gate = ScopeGate(policy)

        res = gate.evaluate("https://target.net/api/user", "DELETE")
        assert res["allowed"] is False
        assert "FORBIDDEN" in res["reason"]

    def test_non_idempotent_method_requires_approval(self):
        policy = ScopePolicy(allowed_domains=["*"])
        gate = ScopeGate(policy)

        res = gate.evaluate("https://target.net/api/user", "POST")
        assert res["allowed"] is True
        assert res["requires_approval"] is True


# ─── 2. Response Normalizer Tests ─────────────────────────────────────────────

class TestResponseNormalizer:
    def test_sanitize_csrf_and_timestamps(self):
        raw_body = '<html><input name="csrf_token" value="abc123xyz4567890123" /> Time: 2026-09-09T14:30:00Z </html>'
        cleaned = ResponseNormalizer.sanitize_body(raw_body)
        assert "[DYNAMIC_TOKEN]" in cleaned
        assert "abc123xyz4567890123" not in cleaned
        assert "2026-09-09T14:30:00Z" not in cleaned

    def test_compute_similarity_identical(self):
        sim = ResponseNormalizer.compute_similarity("Hello World 123", "Hello World 123")
        assert sim == 1.0

    def test_compute_similarity_different(self):
        sim = ResponseNormalizer.compute_similarity("Products List: 50 items", "No items found in category")
        assert sim < 0.60

    def test_extract_json_structure(self):
        json_str = '{"status": "success", "data": [{"id": 1, "name": "Item A"}]}'
        schema = ResponseNormalizer.extract_json_structure(json_str)
        assert schema is not None
        assert "status" in schema
        assert "data" in schema
        assert isinstance(schema["data"], list)


# ─── 3. Parameter Classifier & Context Inference Tests ────────────────────────

class TestParameterClassifier:
    def test_classify_numeric(self):
        prof = ParameterClassifier.classify_parameter("id", "1337", ParameterLocation.QUERY)
        assert prof.observed_type == ParameterType.NUMERIC
        assert prof.inferred_context == SQLiContextType.SQL_WHERE_VALUE
        assert prof.priority > 0.5

    def test_classify_order_by_context(self):
        prof = ParameterClassifier.classify_parameter("sort", "name", ParameterLocation.QUERY)
        assert prof.inferred_context == SQLiContextType.SQL_ORDER_CLAUSE
        assert "probable_order_by_context" in prof.risk_factors

    def test_classify_like_search_context(self):
        prof = ParameterClassifier.classify_parameter("q", "laptop", ParameterLocation.QUERY)
        assert prof.inferred_context == SQLiContextType.SQL_LIKE_EXPRESSION
        assert prof.observed_type == ParameterType.STRING

    def test_classify_json_filter(self):
        prof = ParameterClassifier.classify_parameter("filter", '{"active": true}', ParameterLocation.BODY_JSON)
        assert prof.observed_type == ParameterType.JSON
        assert prof.inferred_context == SQLiContextType.JSON_TO_SQL_FILTER


# ─── 4. Differential SQLi Engine Tests ────────────────────────────────────────

class TestDifferentialSQLiEngine:
    def test_detect_db_error_mysql(self):
        engine = DifferentialSQLiEngine()
        text = "Database error: You have an error in your SQL syntax near '1' at line 1"
        res = engine.detect_db_error(text)
        assert res is not None
        assert res[0] == "MySQL"

    def test_detect_db_error_oracle(self):
        engine = DifferentialSQLiEngine()
        text = "Server responded: ORA-00933: SQL command not properly ended"
        res = engine.detect_db_error(text)
        assert res is not None
        assert res[0] == "Oracle"

    def test_detect_db_error_postgres(self):
        engine = DifferentialSQLiEngine()
        text = 'Internal error: ERROR: syntax error at or near "1"'
        res = engine.detect_db_error(text)
        assert res is not None
        assert res[0] == "PostgreSQL"

    def test_detect_no_error(self):
        engine = DifferentialSQLiEngine()
        text = "<html><body><h1>Welcome to our Store</h1></body></html>"
        res = engine.detect_db_error(text)
        assert res is None


# ─── 5. Second-Order Tracker Tests ────────────────────────────────────────────

class TestSecondOrderTracker:
    def test_register_and_correlate_sink(self):
        tracker = SecondOrderTracker()
        marker = tracker.register_seed("/api/profile/update", "bio")
        assert marker.startswith("pentest_marker_")

        sink_html = f"<html><body>User Bio: {marker} in admin review queue</body></html>"
        matches = tracker.correlate_sink("/admin/reviews", sink_html)
        assert len(matches) == 1
        assert matches[0]["sink_endpoint"] == "/admin/reviews"
        assert matches[0]["requires_approval"] is True


# ─── 6. Code & ORM Pattern Auditor Tests ──────────────────────────────────────

class TestCodeORMAuditor:
    def test_detects_unsafe_concatenation(self):
        code = 'def get_user(request):\n    user_id = request.GET.get("id")\n    query = "SELECT * FROM users WHERE id = " + user_id\n    cursor.execute(query)'
        res = CodeORMAuditor.audit_snippet(code)
        assert len(res["vulnerability_signals"]) > 0
        assert res["is_vulnerable"] is True

    def test_detects_safe_parameterized_query(self):
        code = 'PreparedStatement pstmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");\npstmt.setInt(1, userId);\nResultSet rs = pstmt.executeQuery();'
        res = CodeORMAuditor.audit_snippet(code)
        assert len(res["safe_defenses_detected"]) > 0
        assert res["is_vulnerable"] is False


# ─── 7. Report Generator & Deduplication Tests ────────────────────────────────

class TestReportGenerator:
    def test_generate_dedup_key(self):
        key1 = ReportGenerator.generate_dedup_key("target.com", "/products", "category", "sql_where_value")
        key2 = ReportGenerator.generate_dedup_key("TARGET.COM", "/products", "CATEGORY", "sql_where_value")
        assert key1 == key2

    def test_format_markdown_report(self):
        finding = SafeSQLiFinding(
            finding_id="SQLI-TEST001",
            title="Potential SQL Injection in 'search' parameter",
            endpoint="https://example.com/products?search=test",
            method="GET",
            parameter="search",
            location="query",
            inferred_context="sql_like_expression",
            confidence_score=0.91,
            confidence_level="strong_candidate",
            classification="confirmed_sqli_candidate",
            signals=["Reproducible Logical Differential", "HTTP Status Divergence"],
            evidence={"probe_pair": ("' AND 1=1--", "' AND 1=2--"), "true_status": 200, "false_status": 404},
            steps_to_reproduce=["Send baseline request", "Inject logical true", "Inject logical false"],
            remediation={"primary": "Use Prepared Statements with Parameterized Queries"},
            safety_statement="Tested with non-destructive differential probes.",
            requires_manual_review=False,
            dedup_key="abc123def456"
        )
        report = ReportGenerator.format_markdown_report(finding)
        assert "# SQL Injection Assessment Report" in report
        assert "Prepared Statements" in report
        assert "CWE-89" in report


# ─── 8. SafeSQLiAssessmentSkill Orchestrator Tests ────────────────────────────

class TestSafeSQLiAssessmentSkill:
    @pytest.mark.asyncio
    async def test_discards_out_of_scope_target(self):
        policy = ScopePolicy(allowed_domains=["target.corp"])
        skill = SafeSQLiAssessmentSkill(policy=policy)

        result = await skill.run("https://unauthorized-domain.com/items?id=1")
        assert result["decision"] == "discarded"
        assert result["confidence"] == 0.0
        assert "OUT OF SCOPE" in result["reason"]

    def test_statistics_median(self):
        assert statistics_median([10, 20, 30]) == 20.0
        assert statistics_median([10, 20, 30, 40]) == 25.0
        assert statistics_median([]) == 0.0
