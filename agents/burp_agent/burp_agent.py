"""
HunterAI Burp Agent (Top-Level Orchestrator)
Implements BaseAgent and orchestrates the decoupled 3-tier architecture:
Level 1 Ingestion -> Level 2 Passive Triage & Mapping -> Level 3 AI Threat Reasoning & Attack Graph.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Callable

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from agents.burp_agent.storage.database import TrafficDatabase
from agents.burp_agent.storage.cache import TrafficCache
from agents.burp_agent.scope.scope_manager import ScopeManager
from agents.burp_agent.evidence.evidence_manager import EvidenceManager
from agents.burp_agent.pipeline.event_bus import EventBus, BurpEvent
from agents.burp_agent.pipeline.ingestion_pipeline import IngestionPipeline
from agents.burp_agent.pipeline.analysis_pipeline import AnalysisPipeline
from agents.burp_agent.pipeline.ai_pipeline import AIPipeline
from agents.burp_agent.core.listener import BurpTrafficListener
from agents.burp_agent.collectors.file_collector import FileCollector
from agents.burp_agent.collectors.websocket_collector import WebSocketCollector
from agents.burp_agent.analyzers.endpoint_analyzer import EndpointAnalyzer
from agents.burp_agent.analyzers.auth_analyzer import AuthAnalyzer
from agents.burp_agent.analyzers.vulnerability_analyzer import VulnerabilityAnalyzer
from agents.burp_agent.memory.application_memory import ApplicationMemory
from agents.burp_agent.intelligence.attack_graph import AttackGraphEngine
from agents.burp_agent.intelligence.ai_reasoner import AIReasoner

log = logging.getLogger("agents.burp_agent")


class BurpAgent(BaseAgent):
    """الوكيل الذكي المتقدم للتقاط ترافيك Burp Suite وتحليله وبناء شجرة الهجوم"""

    def __init__(
        self,
        tool_manager=None,
        progress_callback: Optional[Callable] = None,
        db_path: str = "data/traffic.db",
        port: int = 8085,
        ollama_client=None,
        scope_includes: Optional[List[str]] = None,
        scope_excludes: Optional[List[str]] = None
    ):
        super().__init__(
            name="BurpAgent",
            description="Enterprise Burp Suite Traffic Ingestion, Context Memory & AI Threat Reasoning Engine",
            tool_manager=tool_manager or None,
            progress_callback=progress_callback
        )
        self.db = TrafficDatabase(db_path=db_path)
        self.cache = TrafficCache()
        self.scope = ScopeManager(include_rules=scope_includes, exclude_rules=scope_excludes)
        self.evidence_mgr = EvidenceManager(self.db)
        self.bus = EventBus()
        self.memory = ApplicationMemory()
        self.attack_graph = AttackGraphEngine(self.db)

        # Analyzers (Level 2)
        self.file_collector = FileCollector(self.db)
        self.ws_collector = WebSocketCollector(self.db)
        self.endpoint_analyzer = EndpointAnalyzer(self.db)
        self.auth_analyzer = AuthAnalyzer(self.evidence_mgr)
        self.vuln_analyzer = VulnerabilityAnalyzer(self.evidence_mgr)

        self.analyzers = [
            self.endpoint_analyzer,
            self.auth_analyzer,
            self.vuln_analyzer,
            self.file_collector
        ]

        # Pipelines
        self.ingestion_pipe = IngestionPipeline(self.db, self.cache, self.scope, self.bus)
        self.analysis_pipe = AnalysisPipeline(self.db, self.bus, self.analyzers)

        # Level 3 AI Pipeline
        self.ai_reasoner = AIReasoner(ollama_client=ollama_client, memory=self.memory)
        self.ai_pipe = AIPipeline(self.db, self.bus, self.ai_reasoner)

        # Live Traffic Listener
        self.listener = BurpTrafficListener(
            host="127.0.0.1",
            port=port,
            on_traffic_cb=self.ingest_raw_traffic
        )

        # Level 3.5 Security Intelligence Layer Integration
        self.security_intelligence = None
        self.intelligence_adapter = None
        try:
            from core.integration.security_intelligence_adapter import SecurityIntelligenceAdapter
            from agents.security_intelligence.brain import SecurityIntelligence
            self.security_intelligence = SecurityIntelligence()
            self.intelligence_adapter = SecurityIntelligenceAdapter(
                security_intelligence=self.security_intelligence,
                event_bus=self.bus
            )
            log.info("[BurpAgent] SecurityIntelligenceAdapter attached to EventBus.")
        except Exception as e:
            log.warning(f"[BurpAgent] SecurityIntelligenceAdapter could not be attached: {e}")

        self._wire_events()


    def _wire_events(self):
        """ربط خطوط الأنابيب عبر ناقل الأحداث (Event Bus) لضمان عدم الحجب"""
        # When traffic is stored -> run level 2 passive analysis
        self.bus.subscribe(BurpEvent.TRAFFIC_STORED, self.analysis_pipe.on_traffic_stored)
        # When interesting traffic flagged -> queue for AI and update attack graph
        self.bus.subscribe(BurpEvent.INTERESTING_TRAFFIC, self.ai_pipe.enqueue_interesting_traffic)
        self.bus.subscribe(BurpEvent.INTERESTING_TRAFFIC, self._on_interesting_for_graph)
        self.bus.subscribe(BurpEvent.FINDING_CREATED, self._on_finding_created)

    async def _on_interesting_for_graph(self, data: Dict[str, Any]):
        req = data.get("request")
        if req:
            self.attack_graph.update_from_request(req)

    async def _on_finding_created(self, finding_data: Dict[str, Any]):
        await self.emit("finding", finding_data)

    async def ingest_raw_traffic(self, payload: Dict[str, Any]):
        """نقطة دخول الترافيك المباشرة من Burp Suite"""
        await self.ingestion_pipe.process_raw_traffic(payload)

    async def start_background_workers(self):
        """تشغيل معالجات الخلفية للـ AI وسيرفر الاستقبال"""
        asyncio.create_task(self.ai_pipe.start_worker())
        asyncio.create_task(self.listener.start())
        log.info("[BurpAgent] Background AI worker & HTTP listener started successfully.")

    def get_stats(self) -> Dict[str, Any]:
        return self.db.get_stats()

    async def run(self, task: AgentTask) -> AgentResult:
        """تشغيل فحص أو مراقبة الترافيك على هدف معين"""
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        await self.emit("status", {"message": f"BurpAgent active on {task.target}"})

        if task.target:
            self.scope.add_include(f"*{task.target}*")

        stats = self.get_stats()
        findings = self.db.list_findings()

        result = AgentResult(
            agent_name=self.agent_name,
            target=task.target,
            findings=findings,
            raw_output=f"Intercepted {stats.get('total_requests', 0)} requests, {stats.get('endpoints_mapped', 0)} endpoints mapped.",
            duration=round(loop.time() - t0, 2),
            metadata=stats
        )
        return result
