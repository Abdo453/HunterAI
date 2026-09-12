"""
Unit Tests for MethodologyKB & PortSwigger 31 Web Security Topics
Verifies:
- Complete ingestion of all 31 PortSwigger vulnerability categories
- Robust searching across tools, commands, and security descriptions
- AI context formulation for autonomous planning
- API reflection on /api/methodology
"""
import pytest
from core.methodology_kb import MethodologyKB
from ui.web.app import app
import httpx


class TestMethodologyKB:
    @pytest.fixture
    def kb(self):
        return MethodologyKB()

    def test_all_portswigger_categories_loaded(self, kb):
        steps = kb.get_all_steps()
        matrix = kb.get_portswigger_matrix()

        # Check total steps: 4 recon steps + 31 PortSwigger classes = 35
        assert len(steps) >= 35
        assert len(matrix) == 31

    def test_required_portswigger_fields(self, kb):
        matrix = kb.get_portswigger_matrix()
        required_keys = [
            "id", "topic", "category", "name", "cwe", "owasp_category",
            "signals", "verification_strategy", "evidence_requirements",
            "tools", "remediation", "description"
        ]
        for entry in matrix:
            for key in required_keys:
                assert key in entry, f"Missing {key} in {entry.get('id')}"
            assert len(entry["signals"]) > 0
            assert len(entry["evidence_requirements"]) > 0
            assert len(entry["tools"]) > 0
            assert entry["cwe"].startswith("CWE-") or entry["cwe"] == "N/A"

    def test_search_portswigger_topics(self, kb):
        # Test core high-frequency vulnerability searches
        test_queries = [
            "sql injection", "xss", "csrf", "ssrf", "jwt",
            "prototype pollution", "graphql", "race condition",
            "nosql", "clickjacking", "cors", "xxe",
            "command injection", "ssti", "traversal", "oauth",
            "file upload", "business logic", "host header",
            "deserialization", "websocket", "cache poisoning",
            "cache deception", "api testing", "llm"
        ]
        for query in test_queries:
            results = kb.search(query)
            assert len(results) > 0, f"No search results for query: {query}"
            for res in results:
                assert "tool" in res
                assert "command" in res
                assert "description" in res

    def test_get_topic_methodology(self, kb):
        sqli = kb.get_topic_methodology("sqli")
        assert sqli is not None
        assert sqli["cwe"] == "CWE-89"
        assert "A03:2021" in sqli["owasp_category"]

        jwt_item = kb.get_topic_methodology("jwt")
        assert jwt_item is not None
        assert "jwt" in jwt_item["topic"]

        ssrf_item = kb.get_topic_methodology("ssrf")
        assert ssrf_item is not None
        assert ssrf_item["cwe"] == "CWE-918"

    def test_format_methodology_context_for_ai(self, kb):
        # General AI context
        general_prompt = kb.format_methodology_context_for_ai()
        assert "RECON" in general_prompt
        assert "SQL Injection" in general_prompt

        # Targeted AI context
        sqli_prompt = kb.format_methodology_context_for_ai(topic="sqli")
        assert "CWE-89" in sqli_prompt
        assert "Verification Strategy" in sqli_prompt
        assert "Remediation" in sqli_prompt

    @pytest.mark.asyncio
    async def test_api_methodology_endpoint(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/api/methodology")
            assert resp.status_code == 200
            data = resp.json()
            assert "steps" in data
            assert len(data["steps"]) >= 35
            assert "portswigger_matrix" in data
            assert len(data["portswigger_matrix"]) == 31

            # Test search query on API
            search_resp = await client.get("/api/methodology?q=jwt")
            assert search_resp.status_code == 200
            search_data = search_resp.json()
            assert "results" in search_data
            assert len(search_data["results"]) >= 1
