"""
Tool Orchestrator & Autonomous Execution Fabric
Connects the HunterAI Brain to Browser, Burp, and Analyzer controllers.
Translates high-level investigative intents (e.g. EXPLORE, TEST_DIFFERENTIAL, VERIFY)
into coordinated tool executions and returns structured sensory feedback.
"""
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from core.orchestration.tool_registry import ToolRegistry, ToolDefinition, ToolCategory
from core.controllers.browser_controller import BrowserController, BrowserNavigationResult
from core.controllers.burp_controller import BurpController, RepeaterExperiment
from core.evidence.differential_analyzer import DifferentialAnalyzer, ResponseDifference
from core.reasoning.semantic_interpreter import SemanticInterpreter, SemanticFact
from agents.burp_agent.normalization.request_normalizer import RequestNormalizer
from agents.burp_agent.normalization.response_normalizer import ResponseNormalizer

log = logging.getLogger("core.orchestration.tool_orchestrator")


class OrchestrationPlanResult(BaseModel):
    intent: str
    tool_used: str
    status: str
    result_data: Dict[str, Any] = Field(default_factory=dict)
    semantic_facts: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_id: Optional[str] = None


class ToolOrchestrator:
    """
    منسق الأدوات الذكي (Tool Orchestrator):
    الطبقة التنفيذية التي تقود المتصفح والـ Burp ومحلل التفاضل بناءً على أوامر الـ Brain
    """

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        browser: Optional[BrowserController] = None,
        burp: Optional[BurpController] = None,
        analyzer: Optional[DifferentialAnalyzer] = None
    ):
        self.registry = registry or ToolRegistry()
        self.browser = browser or BrowserController()
        self.burp = burp or BurpController()
        self.analyzer = analyzer or DifferentialAnalyzer()

        self._register_default_tools()

    def _register_default_tools(self):
        # 1. Browser Navigate
        self.registry.register_tool(
            ToolDefinition(
                name="browser.navigate",
                category=ToolCategory.BROWSER,
                description="Navigates to URL through Burp proxy and captures DOM/links.",
                parameters_schema={"url": "string"}
            ),
            handler=self._handle_browser_navigate
        )
        # 2. Burp Send Request
        self.registry.register_tool(
            ToolDefinition(
                name="burp.send_request",
                category=ToolCategory.BURP,
                description="Sends an explicit HTTP request through Burp Suite.",
                parameters_schema={"method": "string", "url": "string"}
            ),
            handler=self._handle_burp_send
        )
        # 3. Burp Repeater Experiment
        self.registry.register_tool(
            ToolDefinition(
                name="burp.repeater_experiment",
                category=ToolCategory.BURP,
                description="Runs a controlled differential experiment in Repeater workspace.",
                parameters_schema={"base_tx_id": "string", "hypothesis": "string", "mutation": "dict"}
            ),
            handler=self._handle_repeater_experiment
        )
        # 4. Analyzer Diff
        self.registry.register_tool(
            ToolDefinition(
                name="analyzer.diff",
                category=ToolCategory.ANALYZER,
                description="Compares baseline and test responses and produces cryptographic differential evidence.",
                parameters_schema={"baseline_body": "string", "test_body": "string"}
            ),
            handler=self._handle_analyzer_diff
        )

    async def _handle_browser_navigate(self, url: str, **kwargs) -> Dict[str, Any]:
        res = await self.browser.navigate(url)
        return res.model_dump()

    async def _handle_burp_send(self, method: str, url: str, headers: Optional[Dict] = None, body: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        receipt = await self.burp.send_request(method, url, headers, body)
        return receipt.model_dump()

    async def _handle_repeater_experiment(self, base_tx_id: str, hypothesis: str, mutation: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        exp = self.burp.create_repeater_experiment(
            base_tx_id=base_tx_id,
            hypothesis=hypothesis,
            mutation_description=kwargs.get("mutation_description", "Custom mutation probe"),
            mutated_request=mutation
        )
        executed = await self.burp.execute_experiment(exp.experiment_id)
        return executed.model_dump()

    async def _handle_analyzer_diff(self, baseline_status: int, baseline_body: str, test_status: int, test_body: str, **kwargs) -> Dict[str, Any]:
        diff = self.analyzer.compare_responses(baseline_status, baseline_body, test_status, test_body)
        return diff.model_dump()

    async def execute_investigative_intent(
        self,
        intent: str,
        params: Dict[str, Any]
    ) -> OrchestrationPlanResult:
        """
        تنفيذ نية تحقيقية مركبة للـ Brain مع تفسير النتائج دلالياً
        """
        intent_upper = intent.upper()
        facts: List[SemanticFact] = []
        evidence_id = None

        if "EXPLORE" in intent_upper or "RECON" in intent_upper:
            url = params.get("url", "http://localhost")
            data = await self.registry.execute("browser.navigate", url=url)
            tool_used = "browser.navigate"

            # Interpret semantic facts from page structure
            if data.get("forms_found"):
                facts.append(SemanticFact(
                    fact_kind="INPUT_SURFACE_DISCOVERED",
                    confidence=0.90,
                    description_en=f"Discovered {len(data['forms_found'])} interactive input form(s) on {url}.",
                    description_ar=f"اكتشاف {len(data['forms_found'])} نموذج إدخال تفاعلي على الصفحة."
                ))

        elif "EXPERIMENT" in intent_upper or "DIFFERENTIAL" in intent_upper:
            base_tx = params.get("base_tx_id", "tx_base")
            hypothesis = params.get("hypothesis", "SQL_INJECTION")
            mutation = params.get("mutated_request", {"method": "GET", "url": "http://localhost"})

            exp_res = await self.registry.execute(
                "burp.repeater_experiment",
                base_tx_id=base_tx,
                hypothesis=hypothesis,
                mutation=mutation,
                mutation_description=params.get("mutation_description", "Differential boolean probe")
            )
            tool_used = "burp.repeater_experiment"
            data = exp_res

            # Run diff
            base_body = params.get("baseline_body", "Normal response body")
            test_body = params.get("test_body", "Mutated probe body")
            diff_res = self.analyzer.compare_responses(200, base_body, 200, test_body, transaction_id=exp_res.get("response_tx_id", "tx_test"))
            evidence_id = diff_res.evidence_id

            # Semantic interpretation
            norm_req = RequestNormalizer.normalize(mutation.get("method", "GET"), mutation.get("url", "http://localhost"))
            norm_resp = ResponseNormalizer.normalize(200, {}, test_body)
            facts = SemanticInterpreter.interpret_transaction(
                tx_id=exp_res.get("response_tx_id", "tx_res"),
                norm_req=norm_req,
                norm_resp=norm_resp,
                diff_score=diff_res.differential_score
            )

        else:
            # Fallback to direct burp send
            method = params.get("method", "GET")
            url = params.get("url", "http://localhost")
            data = await self.registry.execute("burp.send_request", method=method, url=url, body=params.get("body", ""))
            tool_used = "burp.send_request"

        return OrchestrationPlanResult(
            intent=intent,
            tool_used=tool_used,
            status="SUCCESS",
            result_data=data,
            semantic_facts=[f.to_dict() for f in facts],
            evidence_id=evidence_id
        )
