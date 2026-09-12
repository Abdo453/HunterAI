"""
Tests for SQLiSkill — State Machine unit tests (no network calls)
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from agents.skills.sqli_skill import (
    SQLiState, DBMSType, SQLiContext,
    SQLiDetector, SQLiDBMSFingerprinter, SQLiColumnCounter,
    SQLiTextColumnFinder, SQLiUnionVerifier, SQLiExtractor,
    SQLiObjectiveChecker, SQLiSkill,
)


# ─── Helpers ─────────────────────────────────────────────────────────────────
def _make_mock_response(text: str, status_code: int = 200):
    m = MagicMock()
    m.text = text
    m.status_code = status_code
    return m


# ─── SQLiContext ──────────────────────────────────────────────────────────────
class TestSQLiContext:
    def test_defaults(self):
        ctx = SQLiContext(target_url="http://example.com/?id=1", param_name="id")
        assert ctx.state == SQLiState.DETECT
        assert ctx.dbms == DBMSType.UNKNOWN
        assert ctx.col_count == 0
        assert ctx.objective_met is False

    def test_log_appends(self):
        ctx = SQLiContext(target_url="http://example.com/?id=1", param_name="id")
        ctx.log("test message")
        assert "test message" in ctx.logs


# ─── SQLiObjectiveChecker ─────────────────────────────────────────────────────
class TestSQLiObjectiveChecker:
    def test_detects_congratulations(self):
        checker = SQLiObjectiveChecker()
        ctx = SQLiContext(target_url="http://x.com/", param_name="p",
                         objective="retrieve_db_version")
        html = "<html>Congratulations, you solved the lab!</html>"
        assert checker.check(ctx, html, "") is True

    def test_detects_oracle_version_string(self):
        checker = SQLiObjectiveChecker()
        ctx = SQLiContext(target_url="http://x.com/", param_name="p",
                         objective="retrieve_db_version")
        extracted = "Oracle Database 11g Express Edition Release 11.2.0.2.0"
        assert checker.check(ctx, "", extracted) is True

    def test_no_match(self):
        checker = SQLiObjectiveChecker()
        ctx = SQLiContext(target_url="http://x.com/", param_name="p",
                         objective="retrieve_db_version")
        assert checker.check(ctx, "<html>nothing</html>", "") is False

    def test_detects_mysql_version(self):
        checker = SQLiObjectiveChecker()
        ctx = SQLiContext(target_url="http://x.com/", param_name="p",
                         objective="retrieve_db_version")
        extracted = "8.0.35-MySQL Community Server"
        assert checker.check(ctx, "", extracted) is True


# ─── SQLiExtractor ────────────────────────────────────────────────────────────
class TestSQLiExtractor:
    def test_parse_oracle_banner(self):
        ex = SQLiExtractor()
        html = """<tr><td>Oracle Database 11g Express Edition Release 11.2.0.2.0 - Production</td></tr>"""
        result = ex._parse_extracted(html, DBMSType.ORACLE)
        assert "Oracle" in result

    def test_parse_mysql_version(self):
        ex = SQLiExtractor()
        html = "<td>8.0.35</td>"
        result = ex._parse_extracted(html, DBMSType.MYSQL)
        assert "8.0.35" in result

    def test_parse_empty(self):
        ex = SQLiExtractor()
        result = ex._parse_extracted("<html>nothing relevant</html>", DBMSType.UNKNOWN)
        assert result == ""

    def test_build_oracle_payload(self):
        ex = SQLiExtractor()
        ctx = SQLiContext(target_url="http://x.com/", param_name="p")
        ctx.dbms = DBMSType.ORACLE
        ctx.col_count = 2
        ctx.text_cols = [0]
        payload = ex._build_extract_payload("BANNER FROM v$version WHERE ROWNUM=1",
                                            2, [0], DBMSType.ORACLE)
        assert "UNION SELECT" in payload
        assert "BANNER" in payload
        assert "v$version" in payload

    def test_build_mysql_payload(self):
        ex = SQLiExtractor()
        payload = ex._build_extract_payload("@@version, NULL", 2, [0], DBMSType.MYSQL)
        assert "UNION SELECT" in payload
        assert "@@version" in payload


# ─── SQLiColumnCounter ────────────────────────────────────────────────────────
class TestSQLiColumnCounter:
    def test_null_payload_oracle(self):
        counter = SQLiColumnCounter()
        payload = counter._make_null_payload(2, DBMSType.ORACLE)
        assert "UNION SELECT" in payload
        assert "FROM dual" in payload
        assert "NULL,NULL" in payload

    def test_null_payload_mysql(self):
        counter = SQLiColumnCounter()
        payload = counter._make_null_payload(3, DBMSType.MYSQL)
        assert "UNION SELECT" in payload
        assert "NULL,NULL,NULL" in payload
        assert "dual" not in payload


# ─── SQLiUnionVerifier ────────────────────────────────────────────────────────
class TestSQLiUnionVerifier:
    def test_build_union_payload_oracle(self):
        v = SQLiUnionVerifier()
        payload = v.build_union_payload(2, [0], DBMSType.ORACLE)
        assert "FROM dual" in payload
        assert "UNION SELECT" in payload

    def test_build_union_payload_mysql(self):
        v = SQLiUnionVerifier()
        payload = v.build_union_payload(2, [1], DBMSType.MYSQL)
        assert "UNION SELECT" in payload
        assert "dual" not in payload

    def test_build_union_with_custom_values(self):
        v = SQLiUnionVerifier()
        payload = v.build_union_payload(2, [0, 1], DBMSType.MYSQL,
                                        values=["'hello'", "'world'"])
        assert "'hello'" in payload
        assert "'world'" in payload


# ─── Deduplication (module-level helper) ─────────────────────────────────────
def _deduplicate_findings_for_test(findings):
    """Test wrapper that calls the brain's dedup logic."""
    from core.brain.autonomous_brain import _deduplicate_findings
    return _deduplicate_findings(findings)


class TestDeduplication:
    def test_merges_same_param_same_type(self):
        findings = [
            {"param_name": "category", "type": "sqli", "tool": "SmartPoC",
             "severity": "High", "confidence": 0.8, "title": "SQLi"},
            {"param_name": "category", "type": "sqli", "tool": "sqlmap",
             "severity": "Critical", "confidence": 0.95, "title": "SQLi 2"},
        ]
        result = _deduplicate_findings_for_test(findings)
        assert len(result) == 1
        assert "sqlmap" in result[0].get("evidence_sources", [])
        assert result[0]["severity"] == "Critical"  # promoted

    def test_keeps_different_params(self):
        findings = [
            {"param_name": "category", "type": "sqli", "tool": "SmartPoC",
             "severity": "High", "confidence": 0.8},
            {"param_name": "id", "type": "sqli", "tool": "sqlmap",
             "severity": "High", "confidence": 0.9},
        ]
        result = _deduplicate_findings_for_test(findings)
        assert len(result) == 2

    def test_keeps_different_types(self):
        findings = [
            {"param_name": "q", "type": "sqli", "tool": "A", "severity": "High", "confidence": 0.8},
            {"param_name": "q", "type": "xss",  "tool": "B", "severity": "Medium", "confidence": 0.7},
        ]
        result = _deduplicate_findings_for_test(findings)
        assert len(result) == 2

    def test_normalizes_sql_injection_alias(self):
        findings = [
            {"param_name": "id", "type": "sql_injection", "tool": "A",
             "severity": "High", "confidence": 0.8},
            {"param_name": "id", "type": "sqli", "tool": "B",
             "severity": "Critical", "confidence": 0.95},
        ]
        result = _deduplicate_findings_for_test(findings)
        assert len(result) == 1


# ─── SQLiSkill integration (mocked network) ──────────────────────────────────
class TestSQLiSkillIntegration:
    @pytest.mark.asyncio
    async def test_skill_fails_gracefully_on_no_params(self):
        skill = SQLiSkill(proxy=None)
        result = await skill.run(
            target_url="http://example.com/page",  # no query params
            param_name="id"
        )
        # لا يرمي exception — يعيد نتيجة
        assert "state" in result
        assert "logs" in result

    @pytest.mark.asyncio
    async def test_state_machine_starts_at_detect(self):
        """تأكد أن الـState Machine يبدأ من DETECT"""
        ctx = SQLiContext(
            target_url="http://example.com/?category=Gifts",
            param_name="category"
        )
        assert ctx.state == SQLiState.DETECT

    def test_state_machine_has_all_states(self):
        states = [s.name for s in SQLiState]
        required = ["DETECT", "CLASSIFY", "FINGERPRINT", "COUNT_COLS",
                    "TEXT_COLS", "UNION_VERIFY", "EXTRACT", "CHECK_OBJ",
                    "COMPLETE", "FAILED"]
        for s in required:
            assert s in states, f"Missing state: {s}"

    def test_dbms_types(self):
        dbtypes = [d.value for d in DBMSType]
        assert "oracle" in dbtypes
        assert "mysql" in dbtypes
        assert "mssql" in dbtypes
        assert "postgres" in dbtypes

    @pytest.mark.asyncio
    async def test_portswigger_oracle_lab_simulation(self):
        """محاكاة كاملة لاستجابات PortSwigger Oracle SQLi Lab والتأكد من حل اللاب بنجاح"""
        skill = SQLiSkill(proxy=None, objective="retrieve_db_version")

        async def mock_get(url, params):
            payload = params.get("category", "")
            m = MagicMock()

            if "' OR 1=1--" in payload:
                m.status_code = 200
                m.text = "<div>Product 1</div><div>Product 2</div><div>Product 3</div>" * 50
            elif "' AND 1=2--" in payload or "1' AND '1'='2" in payload:
                m.status_code = 200
                m.text = "<div>No products found</div>"
            elif "(SELECT 1 FROM dual)=1" in payload or "ROWNUM=ROWNUM" in payload:
                m.status_code = 200
                m.text = "<div>Product 1</div><div>Product 2</div><div>Product 3</div>" * 50
            elif "ORDER BY 1" in payload or "ORDER BY 2" in payload:
                m.status_code = 200
                m.text = "<div>Product 1</div><div>Product 2</div><div>Product 3</div>" * 50
            elif "ORDER BY 3" in payload or "ORDER BY 4" in payload:
                m.status_code = 500
                m.text = "<h1>Internal Server Error</h1>"
            elif "UNION SELECT NULL,NULL FROM dual--" in payload:
                m.status_code = 200
                m.text = "<div>Product 1</div>"
            elif "UNION SELECT NULL FROM dual--" in payload:
                m.status_code = 500
                m.text = "<h1>Internal Server Error</h1>"
            elif "sqli_text_test_xXx" in payload and "FROM dual" in payload:
                m.status_code = 200
                m.text = "<div>sqli_text_test_xXx</div>"
            elif "BANNER" in payload and "v$version" in payload:
                m.status_code = 200
                m.text = """
                <div class="is-solved"><span>Congratulations, you solved the lab!</span></div>
                <table><tr><td>Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production</td></tr></table>
                """
            elif "UNION SELECT" in payload and "FROM dual" not in payload:
                # Oracle fails on generic UNION without FROM dual
                m.status_code = 500
                m.text = "<h1>Internal Server Error</h1>"
            else:
                m.status_code = 200
                m.text = "<div>Product 1</div><div>Product 2</div>"
            return m

        with patch("agents.skills.sqli_skill._HTTPProbe.get", side_effect=mock_get):
            result = await skill.run(
                target_url="https://lab.web-security-academy.net/filter?category=Gifts",
                param_name="category",
                objective="retrieve_db_version"
            )

            assert result["state"] == "COMPLETE"
            assert result["objective_met"] is True
            assert result["dbms"] == "oracle"
            assert result["col_count"] == 2
            assert "Oracle Database" in result["extracted_data"]


