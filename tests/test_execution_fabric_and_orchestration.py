"""
Comprehensive Unit & Integration Tests for Execution Fabric & Tool Orchestration Layer
Tests:
- ToolRegistry (semantic contracts, category filtering, dispatching)
- BrowserController (navigation, proxy routing, DOM/form extraction)
- BurpController & Repeater Workspace (experiment creation, mutation execution)
- DifferentialAnalyzer (behavioral divergence, cryptographic diff evidence)
- SemanticInterpreter (translating HTTP into high-level cognitive facts)
- ToolOrchestrator (intent-to-tool coordination and semantic feedback)
- REST APIs (/api/orchestration/tools, /api/orchestration/execute, /api/repeater/experiment, /api/analyzer/diff)
"""
import pytest
import httpx

from core.orchestration.tool_registry import ToolRegistry, ToolDefinition, ToolCategory
from core.controllers.browser_controller import BrowserController
from core.controllers.burp_controller import BurpController
from core.evidence.differential_analyzer import DifferentialAnalyzer
from core.reasoning.semantic_interpreter import SemanticInterpreter
from core.orchestration.tool_orchestrator import ToolOrchestrator
from agents.burp_agent.normalization.request_normalizer import RequestNormalizer
from agents.burp_agent.normalization.response_normalizer import ResponseNormalizer
from ui.web.app import app


class TestExecutionFabricAndOrchestration:
    @pytest.mark.asyncio
    async def test_tool_registry_registration_and_execution(self):
        registry = ToolRegistry()

        async def dummy_handler(x: int, y: int):
            return x + y

        tool_def = ToolDefinition(
            name="math.add",
            category=ToolCategory.ANALYZER,
            description="Adds two numbers",
            parameters_schema={"x": "integer", "y": "integer"}
        )
        registry.register_tool(tool_def, dummy_handler)

        retrieved = registry.get_tool("math.add")
        assert retrieved is not None
        assert retrieved.category == ToolCategory.ANALYZER

        res = await registry.execute("math.add", x=5, y=7)
        assert res == 12

    @pytest.mark.asyncio
    async def test_browser_controller_navigation_and_dom_extraction(self):
        controller = BrowserController(proxy_url="http://127.0.0.1:8080")
        result = await controller.navigate("https://lab.internal/portal")

        assert result.status_code == 200
        assert "portal" in result.url
        assert controller.get_current_url() == "https://lab.internal/portal"
        assert len(controller.read_dom()) > 0
        assert result.proxied_via == "http://127.0.0.1:8080"

    @pytest.mark.asyncio
    async def test_burp_controller_repeater_experiment_lifecycle(self):
        controller = BurpController()

        # 1. Create Repeater Experiment
        exp = controller.create_repeater_experiment(
            base_tx_id="tx_orig_01",
            hypothesis="SQL_INJECTION",
            mutation_description="Inject boolean predicate 1=1",
            mutated_request={"method": "GET", "url": "https://lab.internal/items?id=1' AND 1=1--"}
        )

        assert exp.experiment_id.startswith("exp_")
        assert exp.base_tx_id == "tx_orig_01"

        # 2. Execute Repeater Experiment
        executed = await controller.execute_experiment(exp.experiment_id)
        assert executed.response_tx_id is not None
        assert executed.outcome_status == 200
        assert "Executed mutation" in executed.diff_summary

    def test_differential_analyzer_calculates_divergence(self, tmp_path):
        analyzer = DifferentialAnalyzer()

        base_body = "<html><body>Catalog items count: 15</body></html>"
        test_body = "<html><body>Database error: syntax error at or near '1'' (PostgreSQL error 42601)</body></html>"

        diff = analyzer.compare_responses(
            baseline_status=200,
            baseline_body=base_body,
            test_status=500,
            test_body=test_body,
            transaction_id="tx_diff_test"
        )

        assert diff.status_match is False
        assert diff.differential_score >= 0.70
        assert diff.is_statistically_significant is True
        assert diff.error_signature_observed == "PostgreSQL_Syntax"
        assert diff.evidence_id is not None

    def test_semantic_interpreter_translates_http_into_cognitive_facts(self):
        # 1. Database Error Interpretation
        norm_req = RequestNormalizer.normalize("GET", "https://lab.org/products?id=1'")
        norm_resp = ResponseNormalizer.normalize(500, {}, "PostgreSQL error: syntax error at or near")

        facts = SemanticInterpreter.interpret_transaction("tx_error", norm_req, norm_resp)
        assert len(facts) >= 1
        assert any(f.fact_kind == "DB_ERROR_DISCLOSURE" for f in facts)

        # 2. Auth State Transition Interpretation
        norm_req_auth = RequestNormalizer.normalize("POST", "https://lab.org/login")
        norm_resp_auth = ResponseNormalizer.normalize(302, {"Location": "/dashboard"}, "")
        facts_auth = SemanticInterpreter.interpret_transaction("tx_auth", norm_req_auth, norm_resp_auth)
        assert any(f.fact_kind == "AUTH_TRANSITION" for f in facts_auth)

    @pytest.mark.asyncio
    async def test_tool_orchestrator_coordinates_intents(self):
        orchestrator = ToolOrchestrator()

        # Intent 1: Recon Browse
        recon_result = await orchestrator.execute_investigative_intent(
            intent="RECON_EXPLORE",
            params={"url": "https://lab.local/store"}
        )
        assert recon_result.status == "SUCCESS"
        assert recon_result.tool_used == "browser.navigate"

        # Intent 2: Differential Experiment
        diff_result = await orchestrator.execute_investigative_intent(
            intent="DIFFERENTIAL_TEST",
            params={
                "base_tx_id": "tx_base_10",
                "hypothesis": "SQL_INJECTION",
                "mutated_request": {"method": "GET", "url": "https://lab.local/search?q=test' OR 1=1--"},
                "baseline_body": "Normal search results",
                "test_body": "Extended full database dump results"
            }
        )
        assert diff_result.status == "SUCCESS"
        assert diff_result.tool_used == "burp.repeater_experiment"
        assert diff_result.evidence_id is not None

    @pytest.mark.asyncio
    async def test_rest_api_orchestration_and_repeater_endpoints(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. List tools
            res_tools = await client.get("/api/orchestration/tools")
            assert res_tools.status_code == 200
            assert res_tools.json()["total"] >= 4

            # 2. Execute Orchestrated Intent
            res_exec = await client.post("/api/orchestration/execute", json={
                "intent": "RECON_EXPLORE",
                "params": {"url": "https://shop.local"}
            })
            assert res_exec.status_code == 200
            data_exec = res_exec.json()["orchestration_result"]
            assert data_exec["status"] == "SUCCESS"

            # 3. Run Repeater Experiment
            res_rep = await client.post("/api/repeater/experiment", json={
                "base_tx_id": "tx_api_01",
                "hypothesis": "BOLA",
                "mutated_request": {"method": "GET", "url": "https://shop.local/api/orders/2"}
            })
            assert res_rep.status_code == 200
            assert "experiment_id" in res_rep.json()["experiment"]

            # 4. Compare Diff
            res_diff = await client.post("/api/analyzer/diff", json={
                "baseline_status": 200,
                "baseline_body": "User Profile A",
                "test_status": 200,
                "test_body": "User Profile B - Victim Account Data"
            })
            assert res_diff.status_code == 200
            assert res_diff.json()["differential"]["differential_score"] >= 0.30
