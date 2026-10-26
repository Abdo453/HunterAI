"""
HunterAI Master Pipeline Orchestrator
Executes the Autonomous Bug Bounty Workflow following the Finite State Machine:
SCOPE_CHECK -> DISCOVER -> ENUMERATE (with AI Preflight + ENV_READINESS local gate before DISCOVER) -> NORMALIZE -> MAP -> CLASSIFY -> SURFACE -> TRIAGE -> HYPOTHESIZE -> TEST -> VERIFY -> CORRELATE -> ASSESS_IMPACT -> REPORT -> COMPLETE

Guarantees:
1. Scope adherence (ScopeGuard) & Active Authorization Gate
2. Dynamic Tool Registry with automatic fallbacks and per-tool specifications
3. Tool execution persistence (.txt files in data/tool_outputs/)
4. Correlation Engine, Deduplication Engine, and Priority Engine (P0 - P5)
5. Zero false positives through Multi-layer Verification (Reflection != Execution)
6. Intermediate artifacts saved per stage
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin, parse_qs

import httpx

from core.console import configure_stdio, safe_print
from core.scope_guard import ScopeGuard
from core.security_mode import unrestricted_mode
from tools.tool_manager import ToolManager, ToolResult
from tools.network_tools import NetworkTools
from tools.web_tools import WebTools
from hunter_ai.pipeline.state_machine import HunterState, HunterStateMachine, IllegalStateTransitionError
from hunter_ai.pipeline.tool_specs import MasterToolRegistry
from hunter_ai.pipeline.correlation import CorrelationEngine, DeduplicationEngine, PriorityEngine
from core.scope_engine import StrictScopeEngine, ScopePolicy
from core.rate_limiter import AdaptiveRateLimiter
from core.secret_sanitizer import SecretSanitizer
from hunter_ai.pipeline.diff_engine import EngagementDiffEngine
from hunter_ai.pipeline.schemas import (
    ScopeConfig,
    SubdomainRecord,
    LiveAssetRecord,
    EndpointRecord,
    ParameterRecord,
    SecretFindingRecord,
    HunterFinding,
    AssetCategory,
    FindingStatus,
    FindingTier,
    ProfileMode,
    ProgramType,
    ProgramPlatform,
    ProgramVisibility,
    ProgramMetadata,
)
from core.evidence_graph import EvidenceGraph, DeterministicEvidenceValidator, NodeStatus, StageManifest
from hunter_ai.protocol.context_compressor import ContextCompressor, CompressedKnowledgePackage
from hunter_ai.pipeline.engagement_manager import EngagementManager
from core.playbooks.dorking_and_osint_knowledge import DorkingAndOSINTKnowledge
from core.control_plane.policy_gate import PolicyGate
from core.control_plane.computer_control import ComputerControl
from core.browser.traffic_bridge import TrafficBridge
from core.auth_context import AuthContextManager
from core.memory.failure_memory import FailureMemory
from core.tool_registry import ToolRegistry, CapabilityMatrix
from core.decision_core import DecisionCore
from core.control_plane.action_loop import AutonomousActionLoop
from core.wordlist_manager import WordlistManager
from core.readiness.gate import run_mission_gate
from core.readiness.checker import ReadinessGateError
from hunter_ai.pipeline.investigation_controller import InvestigationController
from hunter_ai.pipeline.url_canonicalizer import URLCanonicalizer, CanonicalEndpointFamily
from hunter_ai.pipeline.parameter_intelligence import (
    ParameterIntelligenceEngine,
    ParameterClassification,
    ParameterRole,
    inject_url_parameter,
)
from hunter_ai.brain.ai_preflight import AIPreflightGate, AIPreflightResult
from hunter_ai.brain.cognitive_council import CognitiveCouncil, CouncilRole
from hunter_ai.pipeline.desktop_exporter import DesktopExportManager
from core.wordlist_intelligence import WordlistIntelligenceAgent, WordlistCategory, AttackPhase
from core.coverage.coverage_ledger import (
    AssetType,
    CoverageLedger,
    UntestableReason,
)

logger = logging.getLogger("hunter_ai.pipeline")


class HunterPipelineOrchestrator:
    """
    Master Bug Bounty & Vulnerability Research Pipeline Orchestrator.
    Drives the pipeline across all 21 stages with persistent artifacts and verification.
    """

    def __init__(
        self,
        target: str,
        session_id: Optional[str] = None,
        progress_cb: Optional[Callable[[Dict[str, Any]], Any]] = None,
        tool_manager: Optional[ToolManager] = None,
        in_scope: Optional[List[str]] = None,
        out_of_scope: Optional[List[str]] = None,
        scope_file: Optional[str] = None,
        profile: str = "safe",
        rate_limit_rps: float = 2.0,
        require_human_approval: bool = False,
        no_destructive_tests: bool = True,
        dry_run: bool = False,
        proxy: Optional[str] = None,
        authorized: bool = False,
        workflow: str = "full",
        mode: str = "web",
        use_triad: bool = False,
        allow_private_ips: bool = False,
        timeout_multiplier: float = 1.0,
        allow_no_ai: bool = False,
        ollama_host: Optional[str] = None,
        skip_ai_probe: bool = False,
        inference_timeout: Optional[float] = None,
        browser_type: str = "firefox",
        require_burp_browser: bool = False,
        require_ready: bool = False,
    ):
        self.raw_target = target.strip()
        self.session_id = session_id or f"hunter_{int(time.time())}"
        self.cb = progress_cb
        self.tm = tool_manager or ToolManager()
        self.net = NetworkTools(self.tm)
        self.web = WebTools(self.tm)
        self.master_tools = MasterToolRegistry(self.tm)
        # Phase 2: توصيل السجل الموحد لكل تنفيذ أداة (line الأدلة الكامل)
        try:
            from core.evidence_store import EvidenceStore
            self.master_tools.evidence_store = EvidenceStore()
            self.master_tools.run_id = self.session_id
        except Exception:
            self.master_tools.evidence_store = None
        self.proxy = proxy
        self.authorized = authorized
        self.browser_type = browser_type or os.getenv("BROWSER_TYPE", "firefox")
        # Opt-in fail-closed mode: do not touch the target unless the local
        # Burp proxy, HunterAI gateway, and a proxied Playwright browser are
        # all verified first.
        self.require_burp_browser = require_burp_browser
        self.integration_preflight: Dict[str, Any] = {}
        # Phase 1: بوابة جاهزية البيئة المحلية (أدوات/عقل AI) قبل بدء المهمة.
        # HUNTERAI_REQUIRE_READY=1 يفعّلها خارجيًا (CLI/بيئة التشغيل).
        self.require_ready = bool(require_ready or os.getenv("HUNTERAI_REQUIRE_READY") in ("1", "true", "True"))
        self.readiness_report: Dict[str, Any] = {}
        self.workflow = workflow
        self.mode = mode
        self.scope_file = scope_file
        self.profile = profile.lower() if profile else "safe"
        if self.profile in ("deep", "patient", "full") and timeout_multiplier == 1.0:
            timeout_multiplier = 5.0
        self.timeout_multiplier = max(0.5, float(timeout_multiplier))
        self.master_tools.timeout_multiplier = self.timeout_multiplier
        os.environ["TOOL_TIMEOUT_MULTIPLIER"] = str(self.timeout_multiplier)
        self.rate_limit_rps = max(0.1, rate_limit_rps)
        self.require_human_approval = require_human_approval
        self.no_destructive_tests = no_destructive_tests
        self.dry_run = dry_run
        self.use_triad = use_triad
        self.allow_private_ips = allow_private_ips
        self.allow_no_ai = allow_no_ai
        self.ollama_host = ollama_host
        self.skip_ai_probe = skip_ai_probe
        if unrestricted_mode():
            # Owner full-permissions mode: active testing and destructive
            # actions are always allowed, no human approval is required, and a
            # missing/offline model server never hard-aborts the run (it falls
            # back to deterministic heuristics; result-integrity gates such as
            # the Evidence Court still apply).
            self.authorized = True
            self.no_destructive_tests = False
            self.require_human_approval = False
            self.allow_no_ai = True
        self.inference_timeout = inference_timeout
        self.ai_preflight_result: Optional[AIPreflightResult] = None
        self.ai_degraded: bool = False
        self.ai_backend: str = "ollama"   # "ollama" | "cloud" (set by stage_ai_preflight)
        self.program_metadata: Optional[ProgramMetadata] = None

        # Target normalization
        parsed = urlparse(self.raw_target)
        self.domain = parsed.hostname or self.raw_target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        self.base_url = f"{parsed.scheme or 'https'}://{self.domain}" if "://" not in self.raw_target else self.raw_target.split("?")[0].rstrip("/")
        self.evidence_graph = EvidenceGraph(self.domain)

        # Initialize State Machine
        self.fsm = HunterStateMachine(target=self.raw_target, session_id=self.session_id)

        # Artifact-Based Engagement & Storage Setup
        self.engagement_mgr = EngagementManager(
            target=self.raw_target,
            domain=self.domain,
            session_id=self.session_id,
            workflow=self.workflow
        )
        self.engagement_mgr.manifest.profile = self.profile
        self.engagement_mgr.manifest.scope_file = self.scope_file
        self.engagement_mgr._save_manifest()
        self.artifact_root = self.engagement_mgr.run_dir

        # Initialize Strict Scope Engine & Safety Invariants
        self.scope_file_loaded: bool = False
        if self.scope_file:
            self.strict_scope_engine = StrictScopeEngine.from_file(self.scope_file)
            self.scope_file_loaded = True
            # A scope file is authoritative: adopt its rate limit when the
            # operator did not override the CLI default explicitly.
            declared_rps = getattr(self.strict_scope_engine.policy, "rate_limit_rps", None)
            if declared_rps and self.rate_limit_rps == 2.0:
                self.rate_limit_rps = float(declared_rps)
        else:
            policy = ScopePolicy(
                allowed_targets=in_scope or [self.domain, f"*.{self.domain}"],
                excluded_targets=out_of_scope or [],
                rate_limit_rps=self.rate_limit_rps,
                allow_private_ips_override=self.allow_private_ips,
            )
            self.strict_scope_engine = StrictScopeEngine(policy)

        # In-scope setup for legacy ScopeGuard
        scope_targets = in_scope or [self.domain, f"*.{self.domain}"]
        self.scope_guard = ScopeGuard(in_scope=scope_targets, out_of_scope=out_of_scope or [])

        # Initialize Adaptive Rate Limiter & Secret Sanitizer
        self.rate_limiter = AdaptiveRateLimiter(default_rate_limit_rps=self.rate_limit_rps)
        self.secret_sanitizer = SecretSanitizer()

        # Control Plane & Computer Security Agent Infrastructure
        self.policy_gate = PolicyGate(
            scope_policy=self.strict_scope_engine.policy,
            authorized=self.authorized,
            allow_destructive=not self.no_destructive_tests
        )
        # Every tool execution must pass the same authoritative gate. This closes
        # the S1 gap where ToolManager ran shell commands with no policy check.
        if hasattr(self.tm, "attach_policy_gate"):
            self.tm.attach_policy_gate(self.policy_gate, project_id=self.session_id)
        self.computer_control = ComputerControl(
            workspace_dir=str(self.artifact_root),
            policy_gate=self.policy_gate,
            audit_log_path=str(Path(self.artifact_root) / "terminal_history.jsonl")
        )
        self.failure_memory = FailureMemory(
            storage_file=str(Path(self.artifact_root) / "failure_memory.json")
        )
        self.auth_context_mgr = AuthContextManager(
            storage_dir=str(Path(self.artifact_root) / "auth_context")
        )
        self.wordlist_mgr = WordlistManager()
        self.wordlist_agent = WordlistIntelligenceAgent(target=self.domain, auto_index=False)
        self.wordlist_mgr.intelligence = self.wordlist_agent
        self.council = CognitiveCouncil(target_domain=self.domain, ollama_host=self.ollama_host)
        self.tool_registry = ToolRegistry(
            capability_matrix=CapabilityMatrix(authorized=self.authorized)
        )
        self.decision_core = DecisionCore(
            tool_registry=self.tool_registry,
            failure_memory=self.failure_memory
        )
        self.traffic_bridge = TrafficBridge(
            db_path=str(Path("data") / "traffic.db"),
            evidence_graph=self.evidence_graph,
            evidence_store=self.master_tools.evidence_store,
            run_id=self.session_id,
        )
        self.action_loop = AutonomousActionLoop(
            target_domain=self.domain,
            policy_gate=self.policy_gate,
            computer_control=self.computer_control,
            evidence_graph=self.evidence_graph,
            decision_core=self.decision_core,
            failure_memory=self.failure_memory,
            progress_cb=self._emit
        )

        # Coverage & Negative-Space Ledger (single accounting point for what was
        # actually executed, what failed, and what was never testable).
        self.coverage_ledger = CoverageLedger(
            target_scope=self.domain,
            persistence_file=str(Path(self.artifact_root) / "coverage_ledger.json"),
        )
        self.tool_failures: List[Dict[str, Any]] = []
        self.master_tools.set_result_observer(self._observe_tool_result)

        # Stage Storage
        self.scope_config: Optional[ScopeConfig] = None
        self.subdomains: List[SubdomainRecord] = []
        self.live_assets: List[LiveAssetRecord] = []
        self.endpoints: List[EndpointRecord] = []
        self.parameters: List[ParameterRecord] = []
        self.secrets: List[SecretFindingRecord] = []
        self.findings: List[HunterFinding] = []
        # Scanner signals that could not be re-evaluated into proof are NOT
        # confirmed; they are recorded here as hypotheses for follow-up instead
        # of being silently dropped or falsely confirmed.
        self.deferred_hypotheses: List[Dict[str, Any]] = []
        self.tool_logs: List[str] = []

        # Burp Suite Sensory & Control Subsystem
        self.burp_detected: bool = False
        self._burp_agent: Optional[Any] = None
        self.burp_controller: Optional[Any] = None
        self.burp_research_controller: Optional[Any] = None
        self.burp_transactions: List[Dict[str, Any]] = []
        self.burp_repeater_experiments: List[Dict[str, Any]] = []
        self._triad_instance: Optional[Any] = None

    async def _init_burp_agent_subsystem(self):
        """
        Auto-detects active Burp Suite proxy (127.0.0.1:8080) and initializes
        BurpAgent & BurpGateway on port 8085 with bidirectional event wiring.
        """
        import socket
        burp_proxy_host = "127.0.0.1"
        burp_proxy_port = 8080

        # 1. Auto-detect Burp Proxy if self.proxy is not explicitly provided
        if not self.proxy:
            try:
                with socket.create_connection((burp_proxy_host, burp_proxy_port), timeout=0.3):
                    self.proxy = f"http://{burp_proxy_host}:{burp_proxy_port}"
                    self.burp_detected = True
                    logger.info(f"[BURP] Auto-detected active Burp Suite proxy on {self.proxy}")
                    print(f"\n[+] [BURP SUITE] Auto-detected active Burp Suite proxy on {self.proxy}")
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        # 2. Initialize BurpAgent, BurpController, and BurpResearchController
        try:
            from agents.burp_agent.burp_agent import BurpAgent
            from core.controllers.burp_controller import BurpController

            burp_gw_port = 8085
            self._burp_agent = BurpAgent(
                db_path=str(Path(self.artifact_root) / "burp_traffic.db"),
                port=burp_gw_port,
                scope_includes=[self.domain, f"*.{self.domain}"],
            )
            self.burp_controller = BurpController()
            self.burp_research_controller = getattr(self._burp_agent.gateway, "research_controller", None)

            # Hook real-time traffic ingestion into Orchestrator endpoints, parameters & Council
            async def _on_burp_traffic(payload: Dict[str, Any]):
                await self._process_burp_traffic_event(payload)

            orig_cb = self._burp_agent.gateway.on_traffic_cb
            async def _chained_traffic_cb(p: Dict[str, Any]):
                if orig_cb:
                    try:
                        await orig_cb(p)
                    except Exception:
                        pass
                await _on_burp_traffic(p)

            self._burp_agent.gateway.on_traffic_cb = _chained_traffic_cb

            # Start background AI pipeline and HTTP REST listener
            await self._burp_agent.start_background_workers()

            print(f"[+] [BURP SUITE] Gateway listener active on port {burp_gw_port}")
            print(f"[+] [BURP SUITE] Extension endpoint: http://127.0.0.1:{burp_gw_port}")
            if self.proxy:
                print(f"[+] [BURP SUITE] All Playwright browser & HTTP client traffic routing via: {self.proxy}\n")
            await self._emit("burp_started", message=f"Burp Suite Agent active on :{burp_gw_port} (Proxy: {self.proxy or 'None'})")

        except Exception as be:
            logger.warning(f"[BURP] BurpAgent startup notice: {be}")

    async def stage_integration_preflight(self) -> bool:
        """Verify the local Agent → Browser → Burp path without contacting a target."""
        import socket

        checks: Dict[str, Any] = {
            "strict": self.require_burp_browser,
            "proxy": {"configured": self.proxy, "reachable": False},
            "gateway": {"ready": self._burp_agent is not None},
            "browser": {"available": False, "launched": False, "proxy_configured": False},
        }

        if self.proxy:
            parsed = urlparse(self.proxy if "://" in self.proxy else f"http://{self.proxy}")
            host, port = parsed.hostname, parsed.port or 8080
            if host:
                try:
                    with socket.create_connection((host, port), timeout=1.0):
                        checks["proxy"]["reachable"] = True
                except OSError as exc:
                    checks["proxy"]["error"] = str(exc)

        try:
            from core.browser.playwright_controller import PlaywrightBrowserController, PLAYWRIGHT_AVAILABLE
            checks["browser"]["available"] = PLAYWRIGHT_AVAILABLE
            # Browser launch can provision a missing engine.  Only perform that
            # potentially slow local action when the operator explicitly asked
            # for a strict Agent → Browser → Burp preflight.
            prerequisites_ready = checks["proxy"]["reachable"] and checks["gateway"]["ready"]
            if PLAYWRIGHT_AVAILABLE and self.require_burp_browser and prerequisites_ready:
                controller = PlaywrightBrowserController(
                    output_dir=Path(self.artifact_root) / "00_integration" / "browser_preflight",
                    policy_gate=self.policy_gate,
                    headless=True,
                    proxy=self.proxy,
                )
                try:
                    checks["browser"]["launched"] = await controller.launch(self.browser_type)
                    checks["browser"]["proxy_configured"] = bool(controller.proxy) and checks["browser"]["launched"]
                finally:
                    await controller.close()
        except Exception as exc:
            checks["browser"]["error"] = str(exc)

        checks["ready"] = bool(
            checks["proxy"]["reachable"]
            and checks["gateway"]["ready"]
            and checks["browser"]["launched"]
            and checks["browser"]["proxy_configured"]
        )
        self.integration_preflight = checks
        self._save_stage_artifact("00_integration", "agent_burp_browser.json", checks)
        message = "Agent/Burp/browser integration verified" if checks["ready"] else "Agent/Burp/browser integration is incomplete"
        await self._emit("integration_preflight", message=message, details=checks)
        return checks["ready"] or not self.require_burp_browser

    async def _process_burp_traffic_event(self, payload: Dict[str, Any]):
        """
        Parses incoming Burp traffic, dynamically extracting endpoints,
        query/body parameters, and feeding AgentEvidence to the Council & Triad.
        """
        try:
            req_str = payload.get("request", "")
            host = payload.get("host", self.domain)
            port = int(payload.get("port", 80))
            proto = payload.get("protocol", "http")

            if not req_str:
                return

            first_line = req_str.split("\n", 1)[0].strip()
            parts = first_line.split()
            method = parts[0] if parts else "GET"
            raw_path = parts[1] if len(parts) > 1 else "/"
            full_url = f"{proto}://{host}:{port}{raw_path}" if port not in (80, 443) else f"{proto}://{host}{raw_path}"

            # Scope validation
            is_valid, _ = self.strict_scope_engine.validate_url(full_url)
            if not is_valid:
                return

            tx_record = {
                "method": method,
                "url": full_url,
                "host": host,
                "tool_source": payload.get("tool", "proxy"),
                "status_code": payload.get("status_code", 200),
                "timestamp": time.time(),
            }
            self.burp_transactions.append(tx_record)

            # Discover endpoint
            clean_url = full_url.split("?")[0]
            clean_path = urlparse(clean_url).path or "/"
            if not any(e.url == clean_url for e in self.endpoints):
                ep = EndpointRecord(
                    url=clean_url,
                    path=clean_path,
                    method=method,
                    source="burp_proxy",
                    status_code=200,
                    category="BURP_INGESTION"
                )
                self.endpoints.append(ep)

            # Discover query parameters
            parsed_u = urlparse(full_url)
            if parsed_u.query:
                q_params = parse_qs(parsed_u.query)
                for qk, qvals in q_params.items():
                    if not any(p.endpoint == clean_url and p.parameter == qk for p in self.parameters):
                        pr = ParameterRecord(
                            parameter=qk,
                            endpoint=clean_url,
                            method=method,
                            source="burp_proxy",
                            potential_classes=["IDOR", "Injection", "SSRF"],
                            sample_value=qvals[0] if qvals else "",
                            context={"role": "input", "risk_level": "MEDIUM", "is_active_candidate": True}
                        )
                        self.parameters.append(pr)

            # Feed to Cognitive Council State
            if hasattr(self, "council") and self.council and hasattr(self.council, "state"):
                self.council.state.update_traffic([tx_record])

            # Feed to Triad EvidenceBus if active
            if hasattr(self, "_triad_instance") and self._triad_instance and hasattr(self._triad_instance, "bus"):
                from hunter_ai.brain.local_triad_agent import AgentEvidence
                self._triad_instance.bus.publish_evidence(
                    AgentEvidence(
                        source="burp_proxy",
                        category="traffic",
                        observation=f"Intercepted {method} {clean_url} with params {list(q_params.keys()) if parsed_u.query else []}",
                        evidence_data=tx_record,
                    )
                )

            await self._emit("burp_traffic_ingested", method=method, url=clean_url)
        except Exception as e:
            logger.debug(f"[BurpTraffic] Processing error: {e}")

    def _build_proof_payload(self, vuln_type: str, evidence: str) -> Optional[Dict[str, Any]]:
        """Builds a re-evaluable ProofPayload from scanner/collector evidence.

        Delegates to the shared builder so the PoE signature rules live in one
        place. Returns None when no deterministic PoE signature applies to this
        class, which leaves the candidate honestly UNVERIFIED rather than
        fabricating a proof.
        """
        from core.evidence_court import ProofPayload
        payload = ProofPayload.from_vuln_evidence(vuln_type, evidence)
        return payload.to_dict() if payload else None

    @staticmethod
    def _court_verifier_result(
        proof_payload: Optional[Dict[str, Any]],
        *,
        directly_observed: bool = False,
    ) -> Dict[str, Any]:
        """Builds a TRUTHFUL ``verifier_result`` for the Evidence Court.

        ``reproduced`` is claimed only when we hold re-evaluable proof captured
        first-hand (a ProofPayload the engine can re-check) AND we observed the
        effect ourselves. A scanner's output line is a signal, not a
        reproduction, so it never sets ``reproduced`` — the Court then honestly
        returns UNVERIFIED instead of trusting a caller flag.
        """
        return {
            "reproduced": bool(directly_observed and proof_payload),
            "is_reflection": False,
        }

    def _defer_hypothesis(
        self,
        title: str,
        endpoint: str,
        vuln_type: str,
        source_tool: str,
        rationale: str,
        raw_evidence: str = "",
    ) -> None:
        """Records a non-confirmed scanner signal as a follow-up hypothesis.

        This replaces the previous behaviour of submitting scanner lines to the
        Court as if they were reproduced proof. The signal is preserved (with the
        Court's rejection rationale) so it seeds the InvestigationController
        instead of vanishing or being falsely promoted.
        """
        self.deferred_hypotheses.append({
            "title": title,
            "endpoint": endpoint,
            "vuln_type": vuln_type,
            "source_tool": source_tool,
            "rationale": rationale,
            "raw_evidence": (raw_evidence or "")[:300],
            "timestamp": time.time(),
        })

    def _record_reasoning(self, *, kind: str, model: str, prompt_frame: str,
                          output: Any, latency_ms: Optional[float] = None) -> None:
        """
        Phase 4: كل استدلال AI يترك سجلًا موحدًا (RSN-) في EvidenceStore.
        - إطار الطلب يُلخَّص بـ sha256 digest (بلا أسرار).
        - المخرجات تُقتطع وتُنقّى من الأسرار.
        القاعدة المعمارية: العقل لا يُنشئ نتائج مباشرة — النتائج تعبر
        FindingQualificationGate ثم FINAL COURT فقط. فشل التسجيل لا يسقط
        الفحص (telemetry فقط).
        """
        store = getattr(self.master_tools, "evidence_store", None)
        if store is None:
            return
        try:
            from core.evidence_store import _redact_secrets
            digest = hashlib.sha256(
                str(prompt_frame).encode("utf-8", "replace")
            ).hexdigest()
            store.record_reasoning(
                run_id=self.session_id,
                kind=kind, model=model,
                prompt_digest=digest,
                output_excerpt=_redact_secrets(str(output))[:500],
                latency_ms=latency_ms,
            )
            logger.info("[Reasoning] recorded RSN: %s (%s)", kind, model)
        except Exception as e:  # noqa: BLE001
            logger.debug("[Reasoning] ledger notice: %s", e)

    def _observe_tool_result(self, payload: Dict[str, Any]) -> None:
        """Records every tool outcome in the coverage ledger.

        A missing tool, a non-zero exit, a timeout, an empty fallback or an
        unparsable output is a *coverage gap* and must be reported as such.
        Previously these were swallowed by ``except Exception: logger.debug``
        and never reached the report.
        """
        try:
            status = str(payload.get("status") or "unknown")
            tool = str(payload.get("tool_name") or "unknown")
            stage = str(payload.get("stage") or "unknown")
            target = str(payload.get("target") or self.domain)
            items = int(payload.get("item_count") or 0)
            err = payload.get("error")

            failed = status in ("failed", "error", "fallback_empty") or bool(err)
            if not failed:
                return

            entry = {
                "tool": tool,
                "stage": stage,
                "target": target,
                "status": status,
                "error": err,
                "item_count": items,
                "timestamp": time.time(),
            }
            self.tool_failures.append(entry)

            reason_map = {
                "failed": UntestableReason.ENVIRONMENT_LIMIT,
                "error": UntestableReason.ENVIRONMENT_LIMIT,
                "fallback_empty": UntestableReason.ENVIRONMENT_LIMIT,
            }
            self.coverage_ledger.record_blindspot(
                category=f"TOOL_{status.upper()}",
                description=(
                    f"{tool} did not produce usable observations at stage {stage} "
                    f"for {target}: {err or status}"
                ),
                impact="HIGH" if items == 0 else "MEDIUM",
                recommended_mitigation=(
                    f"Install/repair '{tool}' or provide an equivalent adapter, "
                    f"then re-run stage {stage}."
                ),
            )
            if target:
                self.coverage_ledger.record_discovery(
                    AssetType.HOST, target, discovered_by="tool_observer"
                )
                self.coverage_ledger.record_untestable(
                    AssetType.HOST,
                    target,
                    reason_map.get(status, UntestableReason.ENVIRONMENT_LIMIT),
                    detail=f"{tool}: {err or status}",
                )
            logger.warning(
                "[CoverageGap] tool=%s stage=%s status=%s items=%d error=%s",
                tool, stage, status, items, err,
            )
        except Exception as e:
            logger.warning("Failed to record tool outcome in coverage ledger: %s", e)

    async def _emit(self, event: str, **data):
        payload = {"event": event, "session_id": self.session_id, "state": self.fsm.current_state.value, **data}
        if self.cb:
            try:
                if asyncio.iscoroutinefunction(self.cb):
                    await self.cb(payload)
                else:
                    self.cb(payload)
            except Exception:
                pass
        logger.info(f"[{event.upper()}] {data.get('message', '')}")

    def _save_stage_artifact(self, folder_name: str, filename: str, content: Any) -> str:
        """Helper to save structured artifacts in the scan session folder and register in manifest"""
        stage_dir = os.path.join(self.artifact_root, folder_name)
        os.makedirs(stage_dir, exist_ok=True)
        file_path = os.path.join(stage_dir, filename)
        try:
            if hasattr(self, "secret_sanitizer") and self.secret_sanitizer:
                content = self.secret_sanitizer.sanitize_data(content)
            with open(file_path, "w", encoding="utf-8", errors="replace") as f:
                if isinstance(content, (dict, list)):
                    json.dump(content, f, indent=2, default=str)
                else:
                    f.write(str(content))
            # Also register in engagement manager if available
            if hasattr(self, "engagement_mgr") and self.engagement_mgr:
                try:
                    self.engagement_mgr.save_stage_file(folder_name, filename, content)
                except Exception:
                    pass
            return file_path
        except Exception as e:
            logger.error(f"Failed to save artifact {filename}: {e}")
            return file_path

    async def _resolve_cloud_backend(self) -> Optional[str]:
        """Return ``"<provider>:<model>"`` for the preferred cloud provider.

        Consults the unified router so the pipeline honours the same
        cloud-first policy (``HUNTER_LLM_POLICY``) as the rest of the platform.
        Returns ``None`` when no cloud key is configured.
        """
        try:
            from core.llm_router import get_llm_router

            specs = get_llm_router().cloud_specs(only_available=True)
            if specs:
                return f"{specs[0].id}:{specs[0].default_model}"
        except Exception as e:  # noqa: BLE001 - probe failures are non-fatal
            logger.debug(f"[preflight] cloud backend probe failed: {e}")
        return None

    # ── STAGE 00: AI PREFLIGHT GATE ────────────────────────────────────────────
    async def stage_ai_preflight(self) -> bool:
        self.engagement_mgr.start_stage("00_preflight")
        self.fsm.transition_to(HunterState.PREFLIGHT, "Initiating AI Preflight Gate")
        await self._emit("preflight_start", message="Probing Local AI Model Server & Cognitive Triad Readiness")

        self.fsm.transition_to(HunterState.AI_CONNECTING, f"Checking connectivity to {self.ollama_host or 'default host'}")

        # Compute dynamic inference timeout with cold-start tolerance
        inf_timeout = self.inference_timeout or max(45.0, min(120.0, 15.0 * self.timeout_multiplier))

        # Cloud-first fallback: if a cloud provider key is configured the
        # cognitive layer is available even when local Ollama is down.
        cloud_backend = await self._resolve_cloud_backend()

        # Run 3-tier preflight check asynchronously
        result = await AIPreflightGate.run_preflight_async(
            host=self.ollama_host,
            allow_degraded=self.allow_no_ai,
            timeout_sec=5.0,
            inference_timeout_sec=inf_timeout,
            skip_inference_test=self.skip_ai_probe,
            cloud_backend=cloud_backend,
        )
        self.ai_preflight_result = result
        self.ai_degraded = result.degraded
        self.ai_backend = getattr(result, "backend", "ollama")

        # Advance state machine based on result
        if self.ai_backend == "cloud":
            # Local triad is offline but the unified cloud router is ready.
            self.fsm.transition_to(
                HunterState.MODEL_VERIFYING,
                f"Resolving cloud model ({result.backend_detail})",
            )
            self.fsm.transition_to(
                HunterState.INFERENCE_VERIFYING,
                "Certifying cloud cognitive endpoint",
            )
            self.fsm.transition_to(
                HunterState.AI_READY,
                f"Cloud cognitive layer ready ({result.backend_detail})",
            )
        elif not result.online:
            self.fsm.transition_to(HunterState.AI_UNAVAILABLE, result.error_message or "Ollama host unreachable")
            if self.allow_no_ai:
                self.fsm.transition_to(HunterState.DEGRADED_MODE, "Continuing in deterministic heuristic mode (--allow-no-ai)")
            else:
                self.fsm.transition_to(HunterState.ABORTED, "Scan aborted due to AI Preflight failure")
        else:
            self.fsm.transition_to(HunterState.MODEL_VERIFYING, "Verifying local model catalog")
            any_model = any(m.available for m in result.models.values())
            if not any_model:
                self.fsm.transition_to(HunterState.MODEL_MISSING, "No Triad models found in Ollama")
                if self.allow_no_ai:
                    self.fsm.transition_to(HunterState.DEGRADED_MODE, "Continuing in deterministic heuristic mode (--allow-no-ai)")
                else:
                    self.fsm.transition_to(HunterState.ABORTED, "Scan aborted: required models missing")
            else:
                self.fsm.transition_to(HunterState.INFERENCE_VERIFYING, "Executing live inference probe")
                if result.inference_ok:
                    self.fsm.transition_to(HunterState.AI_READY, "All preflight checks certified")
                else:
                    self.fsm.transition_to(HunterState.INFERENCE_FAILED, result.error_message or "Inference probe failed")
                    if self.allow_no_ai:
                        self.fsm.transition_to(HunterState.DEGRADED_MODE, "Continuing in deterministic heuristic mode (--allow-no-ai)")
                    else:
                        self.fsm.transition_to(HunterState.ABORTED, "Scan aborted: live inference failed")

        banner = AIPreflightGate.format_status_banner(result)
        safe_print(f"\n{banner}\n")

        # Save artifacts
        self._save_stage_artifact("00_preflight", "ai_status.json", result.to_dict())
        self._save_stage_artifact("00_preflight", "preflight_banner.txt", banner)
        self.engagement_mgr.complete_stage("00_preflight", item_count=len(result.models))

        if not result.allowed:
            await self._emit("preflight_failed", message=f"AI Preflight Gate FAILED ({result.error_message or 'Server down'}). Pipeline aborted.")
            return False

        if self.ai_backend == "cloud":
            await self._emit("preflight_cloud", message=f"Local triad offline — cognitive layer routed to {result.backend_detail}")
        elif result.degraded:
            await self._emit("preflight_degraded", message="AI Preflight Gate: Operating in DEGRADED_MODE (Deterministic Heuristics Only)")
        else:
            await self._emit("preflight_passed", message=f"AI Preflight Gate: AI_READY (Latency: {result.latency_ms:.1f}ms, Inference: {result.inference_latency_ms:.1f}ms)")

        return True

    # ── STAGE 00.5: ENVIRONMENT READINESS GATE (Phase 1) ──────────────────────
    async def stage_env_readiness(self) -> bool:
        """
        بوابة جاهزية البيئة — كشف الفحوص المحليّة فقط (--version/TCP/ملفات).
        لا يلمس أي هدف. strict والفحص لم يعدم → ABORTED/error (fail-closed).
        """
        from core.readiness import save_readiness_artifact

        self.engagement_mgr.start_stage("00_readiness")
        self.fsm.transition_to(
            HunterState.ENV_READINESS,
            "Local environment readiness gate (tools/AI/Burp/Playwright)",
        )
        await self._emit("readiness_start", message="Checking local environment readiness...")

        gate_data = {
            "require_ready": self.require_ready,
            "use_proxy": bool(self.proxy),
            "use_browser": bool(self.require_burp_browser),
            "require_burp_browser": self.require_burp_browser,
        }
        try:
            report = await run_mission_gate(
                gate_data, target="local-env", session_id=self.session_id,
            )
        except ReadinessGateError as gate_exc:
            blocked_report = getattr(gate_exc, "report", None)
            if blocked_report is not None:
                blocked_dict = blocked_report.to_dict()
            else:
                blocked_dict = {"error": str(gate_exc)}
            self.readiness_report = blocked_dict
            save_readiness_artifact(blocked_report) if blocked_report is not None else None
            self._save_stage_artifact("00_readiness", "readiness_report.json", blocked_dict)
            self.engagement_mgr.complete_stage("00_readiness", item_count=0)
            await self._emit(
                "readiness_blocked",
                blocked=[r.get("name") for r in blocked_dict.get("blocked", [])],
                message=f"Environment readiness gate FAILED (strict) — mission start denied locally: {gate_exc}",
            )
            self.fsm.transition_to(
                HunterState.ERROR,
                "Environment not ready in strict mode — fail-closed",
            )
            return False
        except Exception as exc:  # لا يُسقط المهمة إلا في strict — الافتراضي إنذار
            if self.require_ready:
                self.readiness_report = {"error": str(exc)}
                self._save_stage_artifact("00_readiness", "readiness_report.json", self.readiness_report)
                self.engagement_mgr.complete_stage("00_readiness", item_count=0)
                await self._emit("readiness_blocked", message=f"Readiness gate crashed in strict mode: {exc}")
                self.fsm.transition_to(HunterState.ERROR, f"Readiness gate crash: {exc}")
                return False
            await self._emit("readiness_degraded", message=f"Readiness gate crashed (advisory only): {exc}")
            self.engagement_mgr.complete_stage("00_readiness", item_count=0)
            return True

        # غير strict (علم وقت الأمر فقط) أو strict ناجح — نوثق ونعي آمن
        report_dict = report.to_dict()
        self.readiness_report = report_dict
        save_readiness_artifact(report)
        self._save_stage_artifact("00_readiness", "readiness_report.json", report_dict)
        counts = report_dict.get("counts", {})
        blocked_names = [r.get("name") for r in report_dict.get("blocked", [])]
        self.engagement_mgr.complete_stage("00_readiness", item_count=sum(counts.values()))

        if self.require_ready:
            await self._emit(
                "readiness_passed",
                message=(
                    f"Environment readiness gate PASSED (strict): "
                    f"READY={counts.get('READY', 0)} MISSING={counts.get('MISSING', 0)}"
                ),
            )
        else:
            await self._emit(
                "readiness_advisory",
                blocked=blocked_names,
                message=(
                    f"Environment readiness report (advisory, no gate): "
                    f"READY={counts.get('READY', 0)} MISSING={counts.get('MISSING', 0)}"
                    + (f" — missing: {', '.join(blocked_names[:10])}" if blocked_names else "")
                ),
            )
        return True

    # ── STAGE 00: SCOPE & SAFETY ───────────────────────────────────────────────
    async def stage_scope_check(self) -> bool:
        self.engagement_mgr.start_stage("00_scope")
        self.fsm.transition_to(HunterState.SCOPE_CHECK, "Verifying target scope authorization")
        await self._emit("scope_start", message=f"Evaluating scope for target: {self.domain}")

        # Record root target in lineage
        self.engagement_mgr.record_lineage(
            asset_id=self.domain,
            asset_value=self.domain,
            asset_type="domain",
            tool="scope_guard",
            stage="00_scope"
        )

        # 1. Evaluate StrictScopeEngine Invariants (RFC1918, loopback, cloud metadata)
        strict_allowed, strict_reason = self.strict_scope_engine.validate_target(self.domain)
        if not strict_allowed:
            allowed = False
            scope_reason = f"StrictScopeEngine Invariant Block: {strict_reason}"
        else:
            scope_eval = self.scope_guard.is_in_scope(self.domain)
            if isinstance(scope_eval, tuple):
                allowed, scope_reason = scope_eval
            else:
                allowed = bool(scope_eval)
                scope_reason = "In-scope" if allowed else "Out-of-scope"

        self.scope_config = ScopeConfig(
            target=self.raw_target,
            domain=self.domain,
            in_scope=self.scope_guard.in_scope,
            out_of_scope=self.scope_guard.out_of_scope,
            is_authorized=allowed,
            rejection_reason=None if allowed else scope_reason,
            authenticated=self.authorized
        )
        self._save_stage_artifact("00_scope", "scope.json", self.scope_config.model_dump())
        self._save_stage_artifact("00_scope", "scope_config.json", self.scope_config.model_dump())
        self._save_stage_artifact("00_scope", "scope_policy.json", self.strict_scope_engine.policy.model_dump())

        # ── HARD STOP: no network egress is permitted for an unauthorized target.
        # The scope decision above is purely local (pattern/subnet matching).
        # Everything below performs outbound requests, so it must be unreachable
        # when the target is out of scope.
        if not allowed:
            await self._emit(
                "scope_rejected",
                reason=scope_reason,
                message=f"Target {self.domain} is OUT OF SCOPE! Aborting before any outbound request.",
            )
            self.fsm.transition_to(HunterState.ABORTED, f"Out of scope: {scope_reason}")
            self.scope_config.program_metadata = None
            self._save_stage_artifact("00_scope", "scope_config.json", self.scope_config.model_dump())
            self.engagement_mgr.record_timeline_event(
                stage="00_scope",
                event="scope_rejected",
                message=f"Rejected before egress: {scope_reason}",
            )
            self.engagement_mgr.complete_stage("00_scope", item_count=0)
            return False

        # Discover Program Intelligence (BBP vs VDP, Platform vs Self-Hosted, security.txt)
        try:
            from core.program_intelligence import ProgramIntelligence
            self.program_metadata = await ProgramIntelligence.discover_program(self.domain, proxy=self.proxy)
            self.scope_config.program_type = self.program_metadata.program_type
            self.scope_config.program_platform = self.program_metadata.platform
            self.scope_config.program_visibility = self.program_metadata.visibility
            self.scope_config.program_metadata = self.program_metadata
            self._save_stage_artifact("00_scope", "program_metadata.json", self.program_metadata.model_dump())
            await self._emit(
                "program_classified",
                program_type=self.program_metadata.program_type.value,
                platform=self.program_metadata.platform.value,
                message=f"Program identified: {self.program_metadata.program_type.value} ({self.program_metadata.platform.value})"
            )
        except Exception as e:
            logger.warning(f"Program intelligence failed for in-scope target {self.domain}: {e}")

        # Generate target Google & GitHub Dorks and save in 01_osint
        try:
            dorks = DorkingAndOSINTKnowledge.generate_dorks_for_target(self.domain)
            dork_lines = []
            for cat, d_list in dorks.items():
                dork_lines.append(f"# === {cat.upper()} ===")
                dork_lines.extend(d_list)
                dork_lines.append("")
            self._save_stage_artifact("01_osint", "google_dorks.txt", "\n".join(dork_lines))
            self._save_stage_artifact("01_osint", "github_dorks.txt", f"site:github.com \"{self.domain}\" \"API_KEY\"\nsite:github.com \"{self.domain}\" \"Credentials\"\n")
        except Exception as e:
            logger.debug(f"Dork generation notice: {e}")

        self.engagement_mgr.complete_stage("00_scope", item_count=1)

        auth_msg = " | 🛡️ Active Testing: AUTHORIZED" if self.authorized else " | ⚠️ Active Testing: RESTRICTED (Detection-Only)"
        await self._emit("scope_approved", message=f"Target {self.domain} verified within scope policy{auth_msg}")
        return True

    # ── STAGE 01 - 04: PASSIVE + ACTIVE RECON & NORMALIZATION ───────────────────
    async def stage_recon(self) -> List[SubdomainRecord]:
        self.engagement_mgr.start_stage("01_osint")
        self.engagement_mgr.start_stage("02_subdomains")
        self.fsm.transition_to(HunterState.DISCOVER, "Passive & CT Reconnaissance")
        await self._emit("recon_start", message=f"Harvesting subdomains for {self.domain}...")

        raw_records: Dict[str, Set[str]] = {}

        # 1. crt.sh Certificate Transparency -> 01_osint
        try:
            subs_crt, meta_crt = await self.master_tools.execute_artifact(
                "crtsh", {"domain": self.domain}, self.engagement_mgr, "01_osint", input_source=f"domain: {self.domain}"
            )
            for s in subs_crt:
                raw_records.setdefault(s.lower(), set()).add("crt.sh")
                self.engagement_mgr.record_lineage(asset_id=s.lower(), asset_value=s.lower(), asset_type="domain", tool="crtsh", stage="01_osint", parent_id=self.domain)
            self._save_stage_artifact("01_osint", "crtsh.txt", "\n".join(subs_crt))
            self._save_stage_artifact("01_osint", "crtsh.json", subs_crt)
            self._save_stage_artifact("01_recon", "crtsh.txt", "\n".join(subs_crt))
            if meta_crt and meta_crt.raw_output_file:
                self.tool_logs.append(meta_crt.raw_output_file)
        except Exception as e:
            logger.debug(f"crt.sh error: {e}")

        # 2. subfinder -> 02_subdomains
        try:
            sf_tool = "subfinder_deep" if self.profile in ("full", "hunter", "deep") else "subfinder"
            subs_sf, meta_sf = await self.master_tools.execute_artifact(
                sf_tool, {"domain": self.domain}, self.engagement_mgr, "02_subdomains", input_source=f"domain: {self.domain}"
            )
            for s in subs_sf:
                raw_records.setdefault(s.lower(), set()).add("subfinder")
                self.engagement_mgr.record_lineage(asset_id=s.lower(), asset_value=s.lower(), asset_type="domain", tool="subfinder", stage="02_subdomains", parent_id=self.domain)
            self._save_stage_artifact("02_subdomains", "subfinder.txt", "\n".join(subs_sf))
            self._save_stage_artifact("01_recon", "subfinder.txt", "\n".join(subs_sf))
            if meta_sf and meta_sf.raw_output_file:
                self.tool_logs.append(meta_sf.raw_output_file)
        except Exception as e:
            logger.debug(f"subfinder error: {e}")

        # 2a. assetfinder (Passive archives scraping) -> 02_subdomains
        if self.profile in ("full", "hunter", "deep", "active"):
            try:
                subs_af, meta_af = await self.master_tools.execute_artifact(
                    "assetfinder", {"domain": self.domain}, self.engagement_mgr, "02_subdomains", input_source=f"domain: {self.domain}"
                )
                for s in subs_af:
                    raw_records.setdefault(s.lower(), set()).add("assetfinder")
                    self.engagement_mgr.record_lineage(asset_id=s.lower(), asset_value=s.lower(), asset_type="domain", tool="assetfinder", stage="02_subdomains", parent_id=self.domain)
                if meta_af and meta_af.raw_output_file:
                    self.tool_logs.append(meta_af.raw_output_file)
            except Exception as e:
                logger.debug(f"assetfinder error: {e}")

        # 2b. Active DNS Wordlist Brute-forcing (SecLists) -> 02_subdomains
        if self.profile in ("full", "hunter", "deep", "active"):
            try:
                dns_wl = self.wordlist_mgr.get_wordlist("dns", profile=self.profile)
                subs_dns, meta_dns = await self.master_tools.execute_artifact(
                    "gobuster_dns", {"domain": self.domain, "wordlist": dns_wl}, self.engagement_mgr, "02_subdomains", input_source=f"wordlist: {dns_wl}"
                )
                for s in subs_dns:
                    raw_records.setdefault(s.lower(), set()).add("gobuster_dns")
                    self.engagement_mgr.record_lineage(asset_id=s.lower(), asset_value=s.lower(), asset_type="domain", tool="gobuster_dns", stage="02_subdomains", parent_id=self.domain)
                if meta_dns and meta_dns.raw_output_file:
                    self.tool_logs.append(meta_dns.raw_output_file)
            except Exception as e:
                logger.debug(f"gobuster_dns error: {e}")

        # 2c. Amass — Deep Multi-source Intelligence
        if self.profile in ("full", "hunter", "deep"):
            try:
                subs_am, meta_am = await self.master_tools.execute_artifact(
                    "amass", {"domain": self.domain}, self.engagement_mgr, "02_subdomains", input_source=f"domain: {self.domain}"
                )
                for s in subs_am:
                    if isinstance(s, str) and self.domain in s:
                        raw_records.setdefault(s.lower(), set()).add("amass")
                        self.engagement_mgr.record_lineage(asset_id=s.lower(), asset_value=s.lower(), asset_type="domain", tool="amass", stage="02_subdomains", parent_id=self.domain)
                if meta_am and meta_am.raw_output_file:
                    self.tool_logs.append(meta_am.raw_output_file)
            except Exception as e:
                logger.debug(f"amass error: {e}")

        # 2d. theHarvester — Email, Host & VHost OSINT
        if self.profile in ("full", "hunter", "deep"):
            try:
                harv_results, meta_harv = await self.master_tools.execute_artifact(
                    "theharvester", {"domain": self.domain}, self.engagement_mgr, "01_osint", input_source=f"domain: {self.domain}"
                )
                for item in harv_results:
                    if isinstance(item, str) and self.domain in item and "." in item:
                        raw_records.setdefault(item.lower().strip(), set()).add("theharvester")
                if meta_harv and meta_harv.raw_output_file:
                    self.tool_logs.append(meta_harv.raw_output_file)
            except Exception as e:
                logger.debug(f"theHarvester error: {e}")

        # 2e. Subzy — Subdomain Takeover Detection
        if self.profile in ("full", "hunter", "deep") and raw_records:
            try:
                import tempfile
                sub_list = list(raw_records.keys())
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                    tf.write("\n".join(sub_list))
                    targets_file = tf.name
                subzy_res, meta_subzy = await self.master_tools.execute_artifact(
                    "subzy", {"targets_file": targets_file}, self.engagement_mgr, "04_attack_surface", input_source="02_subdomains/unique_subdomains.txt"
                )
                for line in subzy_res:
                    if isinstance(line, str) and ("VULNERABLE" in line.upper() or "[VUL" in line):
                        from hunter_ai.pipeline.qualification_gate import FindingQualificationGate
                        payload = self._build_proof_payload("SubdomainTakeover", line)
                        is_q, f_obj, rationale = FindingQualificationGate.evaluate_candidate(
                            title=f"Subdomain Takeover: {line[:80]}",
                            asset=self.domain,
                            endpoint=line.split()[0] if line.split() else self.domain,
                            vuln_type="SubdomainTakeover",
                            raw_evidence=line,
                            source_tool="subzy",
                            verifier_result=self._court_verifier_result(payload),
                            proof_payload=payload
                        )
                        if is_q and f_obj:
                            self.findings.append(f_obj)
                        else:
                            self._defer_hypothesis(
                                f"Subdomain Takeover: {line[:80]}",
                                line.split()[0] if line.split() else self.domain,
                                "SubdomainTakeover", "subzy", rationale, line,
                            )
                self._save_stage_artifact("04_attack_surface", "subdomain_takeover.txt", "\n".join(subzy_res))
                if meta_subzy and meta_subzy.raw_output_file:
                    self.tool_logs.append(meta_subzy.raw_output_file)
            except Exception as e:
                logger.debug(f"subzy error: {e}")

        # Always include target domain
        raw_records.setdefault(self.domain.lower(), set()).add("target_input")

        # 3. DNS resolution & Port scanning (nmap) -> 03_dns & 05_ports
        self.engagement_mgr.start_stage("03_dns")
        self.engagement_mgr.start_stage("05_ports")
        self.fsm.transition_to(HunterState.ENUMERATE, "Port Scanning & Network Service Enumeration")
        await self._emit("enumerate_start", message=f"Running service port scan on {self.domain}...")

        self._save_stage_artifact("03_dns", "resolved.txt", f"{self.domain}\n")
        self._save_stage_artifact("03_dns", "dns_records.json", [{"host": self.domain, "status": "resolved"}])
        self.engagement_mgr.complete_stage("03_dns", item_count=1)

        if self.profile == "passive":
            open_ports, meta_nmap = [], None
            self.engagement_mgr.record_timeline_event(
                stage="05_ports",
                event="skipped_passive_profile",
                message="Port scanning skipped under passive profile"
            )
        else:
            nmap_tool = "nmap_deep" if self.profile in ("full", "hunter", "deep") else "nmap"
            open_ports, meta_nmap = await self.master_tools.execute_artifact(
                nmap_tool, {"host": self.domain}, self.engagement_mgr, "05_ports", input_source="03_dns/resolved.txt"
            )
        self._save_stage_artifact("05_ports", "nmap.txt", "\n".join(open_ports))
        self._save_stage_artifact("05_ports", "open_ports.json", [{"port_line": p} for p in open_ports])
        self._save_stage_artifact("01_recon", "nmap.txt", "\n".join(open_ports))
        if meta_nmap and meta_nmap.raw_output_file:
            self.tool_logs.append(meta_nmap.raw_output_file)
        self.engagement_mgr.complete_stage("05_ports", item_count=len(open_ports))

        # Record open ports strictly as Attack Surface Observation (Never as a Vulnerability Finding)
        from hunter_ai.pipeline.qualification_gate import ObservationRecord, ObservationType
        for p in open_ports:
            obs = ObservationRecord(
                source_tool="nmap",
                obs_type=ObservationType.NETWORK_PORT,
                target=self.domain,
                evidence_snippet=p,
                confidence=1.0,
                metadata={"port_spec": p}
            )
            self.engagement_mgr.record_timeline_event(
                stage="05_ports",
                event="port_observed",
                message=f"Network service observed: {p}"
            )

        # 4. Normalization & Deduplication -> 02_subdomains
        self.fsm.transition_to(HunterState.NORMALIZE, "Deduplicating and normalizing asset origins")
        normalized: List[SubdomainRecord] = []
        for asset, sources in raw_records.items():
            conf = 1.0 if len(sources) > 1 else 0.85
            rec = SubdomainRecord(
                asset=asset,
                domain=self.domain,
                sources=sorted(list(sources)),
                confidence=conf
            )
            normalized.append(rec)

        self.subdomains = normalized
        all_subs_text = "\n".join([f"{r.asset}\t[sources: {', '.join(r.sources)}]" for r in self.subdomains])
        unique_subs_text = "\n".join([r.asset for r in self.subdomains])

        self._save_stage_artifact("02_subdomains", "all_subdomains.txt", all_subs_text)
        self._save_stage_artifact("02_subdomains", "unique_subdomains.txt", unique_subs_text)
        self._save_stage_artifact("02_subdomains", "assets_inventory.json", [r.model_dump() for r in self.subdomains])

        # Ingest subdomains into Wordlist Intelligence and generate domain mutations
        try:
            sub_names = [r.asset for r in self.subdomains]
            mutated_subs = self.wordlist_agent.ingest_discovery("subdomain", sub_names)
            if mutated_subs:
                self._save_stage_artifact("02_subdomains", "mutated_subdomains.txt", "\n".join(mutated_subs))
        except Exception as e:
            logger.debug(f"Wordlist intelligence subdomains ingestion notice: {e}")

        # Backwards compatibility
        self._save_stage_artifact("01_recon", "all_subdomains.txt", all_subs_text)
        self._save_stage_artifact("02_normalized_assets", "assets_inventory.json", [r.model_dump() for r in self.subdomains])

        if self.use_triad:
            try:
                from hunter_ai.brain.local_triad_agent import triad_agent
                subs_list = [r.asset for r in self.subdomains]
                tri_triage = await triad_agent.triage_recon_assets(self.domain, subs_list, open_ports, [])
                self._save_stage_artifact("02_subdomains", "ai_triad_recon_triage.json", tri_triage)
                self._save_stage_artifact("02_subdomains", "ai_triad_recon_triage.txt", tri_triage.get("analysis", ""))
                await self._emit("ai_triad_triage", message="Local Triad (xploiter/pentester) completed rapid recon triage.")
            except Exception as e:
                logger.debug(f"Local Triad recon triage notice: {e}")

        self.engagement_mgr.complete_stage("01_osint", item_count=len(raw_records))
        self.engagement_mgr.complete_stage("02_subdomains", item_count=len(self.subdomains))

        await self._emit("recon_done", count=len(self.subdomains), message=f"Discovered and normalized {len(self.subdomains)} assets")
        return self.subdomains

    # ── STAGE 05 - 06: LIVE ASSETS & FINGERPRINTING ────────────────────────────
    async def stage_live_probing(self) -> List[LiveAssetRecord]:
        self.engagement_mgr.start_stage("04_alive")
        self.engagement_mgr.start_stage("11_technology")
        self.fsm.transition_to(HunterState.MAP, "Probing alive HTTP services & technology fingerprinting")
        await self._emit("live_start", message=f"Probing HTTP/HTTPS for {len(self.subdomains)} hosts...")

        live: List[LiveAssetRecord] = []
        transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False) if self.proxy else None

        async def _probe_one(rec: SubdomainRecord):
            target_host = rec.asset
            if not self.strict_scope_engine.is_host_allowed(target_host):
                return
            for scheme in ["https", "http"]:
                url = f"{scheme}://{target_host}"
                try:
                    await self.rate_limiter.acquire(target_host)
                    async with httpx.AsyncClient(transport=transport, verify=False, timeout=6.0, follow_redirects=True) as client:
                        t0 = time.time()
                        resp = await client.get(url)
                        dur = round(time.time() - t0, 3)
                        self.rate_limiter.record_response(target_host, resp.status_code, resp.headers.get("retry-after"))

                        title_m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                        title = title_m.group(1).strip() if title_m else ""

                        server = resp.headers.get("server", "")
                        techs = []
                        if server:
                            techs.append(server)
                        if "x-powered-by" in resp.headers:
                            techs.append(resp.headers["x-powered-by"])
                        if "wp-content" in resp.text:
                            techs.append("WordPress")
                        if "laravel" in resp.text.lower() or "laravel_session" in resp.headers.get("set-cookie", ""):
                            techs.append("Laravel")

                        cat = AssetCategory.WEB
                        low_host = target_host.lower()
                        if "api." in low_host or "/api" in str(resp.url):
                            cat = AssetCategory.API
                        elif "admin." in low_host:
                            cat = AssetCategory.ADMIN
                        elif "dev." in low_host or "staging." in low_host:
                            cat = AssetCategory.DEVELOPMENT
                        elif "upload." in low_host:
                            cat = AssetCategory.UPLOAD
                        elif "auth." in low_host or "login." in low_host:
                            cat = AssetCategory.AUTHENTICATION

                        live_rec = LiveAssetRecord(
                            url=str(resp.url),
                            host=target_host,
                            port=443 if scheme == "https" else 80,
                            scheme=scheme,
                            status_code=resp.status_code,
                            title=title[:80],
                            server=server,
                            content_length=len(resp.content),
                            technologies=techs,
                            response_time=dur,
                            asset_class=cat
                        )
                        live.append(live_rec)
                        self.engagement_mgr.record_lineage(
                            asset_id=live_rec.url,
                            asset_value=live_rec.url,
                            asset_type="live_url",
                            tool="httpx",
                            stage="04_alive",
                            parent_id=target_host
                        )
                        break
                except Exception:
                    continue

        tasks = [_probe_one(s) for s in self.subdomains[:30]]
        await asyncio.gather(*tasks)

        if not live:
            default_url = self.base_url
            live.append(LiveAssetRecord(
                url=default_url,
                host=self.domain,
                port=443 if default_url.startswith("https") else 80,
                scheme="https" if default_url.startswith("https") else "http",
                status_code=200,
                title="Target Host",
                server="Unknown",
                content_length=1024,
                technologies=[],
                asset_class=AssetCategory.WEB
            ))
            self.engagement_mgr.record_lineage(
                asset_id=default_url,
                asset_value=default_url,
                asset_type="live_url",
                tool="httpx",
                stage="04_alive",
                parent_id=self.domain
            )

        self.live_assets = live
        alive_txt = "\n".join([f"{a.url} [{a.status_code}] ({a.asset_class.value})" for a in self.live_assets])
        alive_urls = "\n".join([a.url for a in self.live_assets])
        alive_json = [a.model_dump() for a in self.live_assets]
        tech_json = [{"url": a.url, "server": a.server, "technologies": a.technologies} for a in self.live_assets]

        # Save to 04_alive
        self._save_stage_artifact("04_alive", "alive_hosts.txt", alive_txt)
        self._save_stage_artifact("04_alive", "alive_urls.txt", alive_urls)
        self._save_stage_artifact("04_alive", "httpx.txt", alive_txt)
        self._save_stage_artifact("04_alive", "httpx.json", alive_json)

        # Save to 11_technology
        self._save_stage_artifact("11_technology", "tech_stack.json", tech_json)
        self._save_stage_artifact("11_technology", "httpx_tech.json", tech_json)

        # Ingest detected technologies into Wordlist Intelligence
        try:
            all_techs = []
            for a in self.live_assets:
                if a.technologies:
                    all_techs.extend(a.technologies)
                if a.server:
                    all_techs.append(a.server)
            if all_techs:
                tech_mutations = self.wordlist_agent.ingest_discovery("technology", all_techs)
                if tech_mutations:
                    self._save_stage_artifact("11_technology", "tech_wordlist_candidates.txt", "\n".join(tech_mutations))
        except Exception as e:
            logger.debug(f"Wordlist intelligence technology ingestion notice: {e}")

        # Backwards compatibility
        self._save_stage_artifact("03_live_assets", "alive_hosts.txt", alive_txt)
        self._save_stage_artifact("03_live_assets", "tech_stack.json", alive_json)

        self.engagement_mgr.complete_stage("04_alive", item_count=len(self.live_assets))
        self.engagement_mgr.complete_stage("11_technology", item_count=len(self.live_assets))

        await self._emit("live_done", count=len(self.live_assets), message=f"Mapped {len(self.live_assets)} live endpoints")
        return self.live_assets

    # ── STAGE 07 - 13: ATTACK SURFACE, JS & SPECIAL FILE DISCOVERY ──────────────
    async def stage_attack_surface(self) -> Tuple[List[EndpointRecord], List[ParameterRecord]]:
        self.engagement_mgr.start_stage("06_content")
        self.engagement_mgr.start_stage("07_urls")
        self.engagement_mgr.start_stage("08_parameters")
        self.engagement_mgr.start_stage("09_javascript")
        self.engagement_mgr.start_stage("10_api")
        self.fsm.transition_to(HunterState.SURFACE, "Discovering URLs, endpoints, directories, and parameters")
        await self._emit("surface_start", message="Crawling attack surface and discovering endpoints...")

        raw_crawled_urls: Set[str] = set()
        js_urls: Set[str] = set()
        fuzz_lines: List[str] = []

        # Always include base_url and live asset URLs
        raw_crawled_urls.add(self.base_url)
        for la in self.live_assets:
            if la.url:
                raw_crawled_urls.add(la.url)

        transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False) if self.proxy else None

        # 0. Playwright Browser Intelligence — JS-rendered crawl + XHR/Fetch interception
        if self.profile in ("full", "hunter", "deep", "active"):
            try:
                from core.browser.playwright_controller import PlaywrightBrowserController, PLAYWRIGHT_AVAILABLE
                if PLAYWRIGHT_AVAILABLE:
                    await self._emit("browser_start", message=f"🌐 Launching Playwright {self.browser_type.title()} headless browser for JS-rendered crawl...")
                    browser_dir = os.path.join(self.artifact_root, "15_browser")
                    os.makedirs(browser_dir, exist_ok=True)

                    browser_ctrl = PlaywrightBrowserController(
                        output_dir=browser_dir,
                        policy_gate=self.policy_gate,
                        proxy=self.proxy,   # routes ALL traffic through Burp if --proxy is set
                        headless=True,
                    )

                    launched = await browser_ctrl.launch(browser_type=self.browser_type)
                    if launched:
                        browser_url_count = 0
                        # Prioritize base URL and top live endpoints
                        targets_to_visit = [self.base_url]
                        for la in self.live_assets:
                            if la.url not in targets_to_visit:
                                targets_to_visit.append(la.url)

                        for target_url in targets_to_visit[:5]:
                            is_valid, _ = self.strict_scope_engine.validate_url(target_url)
                            if not is_valid:
                                continue
                            try:
                                ok, nav_msg = await browser_ctrl.goto(target_url, wait_until="domcontentloaded", timeout=20000)
                                if ok:
                                    await asyncio.sleep(1.0)
                                    # Take screenshot as evidence
                                    host_name = urlparse(target_url).netloc.replace(".", "_").replace(":", "_")
                                    screenshot_name = f"{host_name}.png"
                                    await browser_ctrl.screenshot(name=screenshot_name)

                                    # Extract all links from the DOM
                                    links_raw = await browser_ctrl.evaluate_js("""
                                        () => [...document.querySelectorAll('a[href]')]
                                              .map(a => a.href)
                                              .filter(h => h.startsWith('http'))
                                    """) or []
                                    for link in links_raw:
                                        if isinstance(link, str) and self.domain in link:
                                            raw_crawled_urls.add(link)
                                            browser_url_count += 1

                                    # Extract JS script sources
                                    scripts_raw = await browser_ctrl.evaluate_js("""
                                        () => [...document.querySelectorAll('script[src]')].map(s => s.src)
                                    """) or []
                                    for js_src in scripts_raw:
                                        if isinstance(js_src, str):
                                            js_urls.add(js_src)

                                    # Extract forms (login, register, search, upload etc)
                                    forms = await browser_ctrl.extract_forms()
                                    for form in forms:
                                        form_action = form.get("action", "")
                                        if form_action and self.domain in form_action:
                                            raw_crawled_urls.add(form_action)
                                            browser_url_count += 1

                                    # Save cookies + storage
                                    await browser_ctrl.save_storage_state()

                                    await self._emit("browser_page_done", url=target_url,
                                        message=f"🌐 Browser: {target_url} → {len(links_raw)} links, {len(forms)} forms, {len(scripts_raw)} scripts")
                            except Exception as be:
                                logger.debug(f"Playwright page error on {target_url}: {be}")

                        await browser_ctrl.close()

                        # Parse all requests from requests.jsonl (captured by network hooks)
                        req_log = os.path.join(browser_dir, "requests.jsonl")
                        if os.path.isfile(req_log):
                            with open(req_log, encoding="utf-8") as rf:
                                for line in rf:
                                    try:
                                        req_rec = json.loads(line)
                                        req_url = req_rec.get("url", "")
                                        req_type = req_rec.get("resource_type", "")
                                        if req_url and self.domain in req_url:
                                            raw_crawled_urls.add(req_url)
                                            browser_url_count += 1
                                            if req_type == "script" or req_url.endswith(".js"):
                                                js_urls.add(req_url)
                                    except Exception:
                                        pass

                        await self._emit("browser_done",
                            message=f"🌐 Playwright done — {browser_url_count} URLs captured (screenshots + cookies in 15_browser/)")
                    else:
                        print(f"[!] [BROWSER] Playwright launch failed — run: playwright install {self.browser_type}")
                else:
                    print(f"[!] [BROWSER] ⚠️  Playwright not installed — run: pip install playwright && playwright install {self.browser_type}")
            except Exception as e:
                logger.debug(f"Playwright browser controller error: {e}")
                print(f"[!] [BROWSER] Playwright error: {e}")

        # 1. HTML Crawling
        for live in self.live_assets[:10]:
            is_valid_url, _ = self.strict_scope_engine.validate_url(live.url)
            if not is_valid_url:
                continue
            try:
                await self.rate_limiter.acquire(live.host)
                async with httpx.AsyncClient(transport=transport, verify=False, timeout=8.0) as client:
                    resp = await client.get(live.url)
                    self.rate_limiter.record_response(live.host, resp.status_code, resp.headers.get("retry-after"))
                    links = re.findall(r'href=[\'"]([^\'"]+)[\'"]', resp.text, re.IGNORECASE)
                    for lk in links:
                        full_url = urljoin(live.url, lk)
                        if self.domain in full_url:
                            raw_crawled_urls.add(full_url)

                    js_matches = re.findall(r'src=[\'"]([^\'"]+\.js(?:\?[^\'"]*)?)[\'"]', resp.text, re.IGNORECASE)
                    for jm in js_matches:
                        js_full = urljoin(live.url, jm)
                        js_urls.add(js_full)
            except Exception:
                continue

        # 1b. Wayback Machine Historical URL Archive
        try:
            wb_urls, meta_wb = await self.master_tools.execute_artifact(
                "waybackurls", {"domain": self.domain}, self.engagement_mgr, "07_urls", input_source=f"domain: {self.domain}"
            )
            for u in wb_urls:
                if isinstance(u, str) and u.startswith("http") and self.domain in u:
                    raw_crawled_urls.add(u)
            if meta_wb and meta_wb.raw_output_file:
                self.tool_logs.append(meta_wb.raw_output_file)
        except Exception as e:
            logger.debug(f"waybackurls error: {e}")

        # 1c. Katana Active Crawler (for deep profile)
        if self.profile in ("full", "hunter", "deep", "active"):
            try:
                for target_live in self.live_assets[:3]:
                    k_urls, meta_k = await self.master_tools.execute_artifact(
                        "katana", {"url": target_live.url}, self.engagement_mgr, "07_urls", input_source=target_live.url
                    )
                    for ku in k_urls:
                        if isinstance(ku, str) and ku.startswith("http") and self.domain in ku:
                            raw_crawled_urls.add(ku)
                    if meta_k and meta_k.raw_output_file:
                        self.tool_logs.append(meta_k.raw_output_file)
            except Exception as e:
                logger.debug(f"katana error: {e}")

        # 1d. Hakrawler - Fast passive link extraction
        try:
            for target_live in self.live_assets[:3]:
                hk_urls, meta_hk = await self.master_tools.execute_artifact(
                    "hakrawler", {"url": target_live.url}, self.engagement_mgr, "07_urls", input_source=target_live.url
                )
                for hu in hk_urls:
                    if isinstance(hu, str) and hu.startswith("http") and self.domain in hu:
                        raw_crawled_urls.add(hu)
                if meta_hk and meta_hk.raw_output_file:
                    self.tool_logs.append(meta_hk.raw_output_file)
        except Exception as e:
            logger.debug(f"hakrawler error: {e}")

        # 1e. GAU - Get All URLs from AlienVault, Wayback, CommonCrawl
        try:
            gau_urls, meta_gau = await self.master_tools.execute_artifact(
                "gau", {"domain": self.domain}, self.engagement_mgr, "07_urls", input_source=f"domain: {self.domain}"
            )
            for gu in gau_urls:
                if isinstance(gu, str) and gu.startswith("http") and self.domain in gu:
                    raw_crawled_urls.add(gu)
            if meta_gau and meta_gau.raw_output_file:
                self.tool_logs.append(meta_gau.raw_output_file)
        except Exception as e:
            logger.debug(f"gau error: {e}")

        # 2. Directory Fuzzing — ffuf (primary) with gobuster and dirsearch fallbacks
        if self.profile == "passive":
            fuzz_lines, meta_fuzz = [], None
            self.engagement_mgr.record_timeline_event(
                stage="06_content",
                event="skipped_passive_profile",
                message="Directory fuzzing skipped under passive profile"
            )
        else:
            # ── Wordlist Intelligence Selection & Tailored Hybrid Compilation ──
            custom_cands = self.wordlist_agent.generate_custom_candidates(WordlistCategory.DIRECTORIES, max_candidates=500)
            static_wl = self.wordlist_agent.resolve_wordlist_path(WordlistCategory.DIRECTORIES, profile=self.profile)
            
            # Print prominent Wordlist Intelligence Banner
            print("\n" + "─"*60)
            print("  🧠 [WORDLIST_INTEL] Attack Surface Wordlist Intelligence")
            print(f"  🎯 Target Context: {self.domain} | Profile: {self.profile.upper()}")
            if self.wordlist_agent.context.detected_tech:
                print(f"  🧩 Detected Technologies: {', '.join(sorted(list(self.wordlist_agent.context.detected_tech)))}")
            print(f"  📚 Base Selected Wordlist: {os.path.basename(static_wl)}")
            print(f"  🧬 Target Mutated Candidates: {len(custom_cands)} tokens generated")
            
            # Compile tailored hybrid list
            tailored_wl_path = os.path.join(self.artifact_root, "06_content", "tailored_fuzz_wordlist.txt")
            try:
                resolved_wl = self.wordlist_agent.build_custom_wordlist_file(
                    destination_path=tailored_wl_path,
                    category=WordlistCategory.DIRECTORIES,
                    include_base_static=True,
                    max_candidates=1000 if self.profile in ("full", "hunter", "deep") else 300
                )
                print(f"  🚀 Active Hybrid Wordlist: {tailored_wl_path}")
            except Exception as e:
                resolved_wl = static_wl
                print(f"  ⚠️ Hybrid compilation fallback: {resolved_wl} ({e})")
            print("─"*60 + "\n")

            # Primary fuzzer: ffuf (faster, smarter filtering)
            fuzz_lines, meta_fuzz = await self.master_tools.execute_artifact(
                "ffuf", {"url": self.base_url, "wordlist": resolved_wl}, self.engagement_mgr, "06_content", input_source="04_alive/alive_hosts.txt"
            )
            # If ffuf not available, try feroxbuster (recursive)
            if not fuzz_lines:
                fuzz_lines, meta_fuzz = await self.master_tools.execute_artifact(
                    "feroxbuster", {"url": self.base_url, "wordlist": resolved_wl}, self.engagement_mgr, "06_content", input_source="04_alive/alive_hosts.txt"
                )
            # Last resort: gobuster
            if not fuzz_lines:
                fuzz_lines, meta_fuzz = await self.master_tools.execute_artifact(
                    "gobuster", {"url": self.base_url, "wordlist": resolved_wl}, self.engagement_mgr, "06_content", input_source="04_alive/alive_hosts.txt"
                )
            # Dirsearch for extra coverage on deep scans (extensions-aware)
            if self.profile in ("full", "hunter", "deep"):
                try:
                    ds_lines, meta_ds = await self.master_tools.execute_artifact(
                        "dirsearch", {"url": self.base_url}, self.engagement_mgr, "06_content", input_source="04_alive/alive_hosts.txt"
                    )
                    fuzz_lines.extend([l for l in ds_lines if l not in fuzz_lines])
                    if meta_ds and meta_ds.raw_output_file:
                        self.tool_logs.append(meta_ds.raw_output_file)
                except Exception as e:
                    logger.debug(f"dirsearch error: {e}")

        if meta_fuzz and meta_fuzz.raw_output_file:
            self.tool_logs.append(meta_fuzz.raw_output_file)
        self._save_stage_artifact("06_content", "directory_fuzz.txt", "\n".join(fuzz_lines))
        self._save_stage_artifact("06_content", "directories.txt", "\n".join(fuzz_lines))
        self._save_stage_artifact("04_attack_surface", "directory_fuzz.txt", "\n".join(fuzz_lines))

        for line in fuzz_lines:
            if "(Status:" in line:
                part = line.split()[0].lstrip("/")
                fuzz_url = f"{self.base_url}/{part}"
                raw_crawled_urls.add(fuzz_url)

        # 3. Special Files & Backups Hunting (.env, .git, .bak)
        crawl_files = ["robots.txt", "sitemap.xml"]
        sensitive_candidates = [
            ".env", ".git/HEAD", "backup.sql", "config.php.bak", ".htaccess", "server-status"
        ]
        async with httpx.AsyncClient(transport=transport, verify=False, timeout=5.0) as client:
            # Crawl standard files for path discovery
            for cf in crawl_files:
                try:
                    r = await client.get(f"{self.base_url}/{cf}")
                    if r.status_code == 200 and len(r.text) > 10:
                        for line in r.text.splitlines():
                            line = line.strip()
                            if line.lower().startswith(("disallow:", "allow:", "loc>")):
                                path_part = line.split(":", 1)[-1].replace("<loc>", "").replace("</loc>", "").strip()
                                if path_part.startswith("/"):
                                    raw_crawled_urls.add(f"{self.base_url}{path_part}")
                except Exception:
                    pass

            # Audit genuine sensitive backups & exposed configs
            for sc in sensitive_candidates:
                test_url = f"{self.base_url}/{sc}"
                try:
                    r = await client.get(test_url)
                    if r.status_code == 200 and len(r.content) > 10:
                        is_valid = True
                        if sc == ".git/HEAD" and "ref:" not in r.text.lower():
                            is_valid = False
                        if sc == ".env" and "=" not in r.text:
                            is_valid = False

                        if is_valid:
                            from hunter_ai.pipeline.qualification_gate import FindingQualificationGate
                            # We fetched this resource ourselves, so a valid PoE
                            # signature may be derived from the live body.
                            payload = self._build_proof_payload("InformationDisclosure", r.text[:4000])
                            is_q, f_obj, rationale = FindingQualificationGate.evaluate_candidate(
                                title=f"Sensitive File / Backup Exposed: /{sc}",
                                asset=self.domain,
                                endpoint=test_url,
                                vuln_type="InformationDisclosure",
                                raw_evidence=r.text[:200],
                                source_tool="SpecialFileHunter",
                                verifier_result=self._court_verifier_result(payload, directly_observed=True),
                                proof_payload=payload
                            )
                            if is_q and f_obj:
                                self.findings.append(f_obj)
                            else:
                                self._defer_hypothesis(
                                    f"Sensitive File / Backup Exposed: /{sc}",
                                    test_url, "InformationDisclosure",
                                    "SpecialFileHunter", rationale, r.text[:200],
                                )
                except Exception:
                    pass

        # 4. JavaScript Secret Hunting
        self.fsm.transition_to(HunterState.TRIAGE, "JavaScript secret hunting & parameter database compilation")
        await self._emit("js_start", count=len(js_urls), message=f"Analyzing {len(js_urls)} JavaScript files for secrets...")

        secrets: List[SecretFindingRecord] = []
        SECRET_PATTERNS = {
            "generic_api_key": re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key)[\s:=]+['\"]([a-zA-Z0-9_\-]{16,64})['\"]"),
            "aws_access_key": re.compile(r"\b(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
            "jwt_token": re.compile(r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*"),
            "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
        }

        for j_url in list(js_urls)[:15]:
            try:
                async with httpx.AsyncClient(transport=transport, verify=False, timeout=6.0) as client:
                    j_resp = await client.get(j_url)
                    for sec_type, pat in SECRET_PATTERNS.items():
                        matches = pat.findall(j_resp.text)
                        for m in matches:
                            val = m if isinstance(m, str) else m[0]
                            sec_rec = SecretFindingRecord(
                                file_url=j_url,
                                secret_type=sec_type,
                                matched_string=val[:60],
                                confidence=0.92,
                                severity="High"
                            )
                            secrets.append(sec_rec)
                            self.engagement_mgr.record_lineage(
                                asset_id=f"{j_url}#{sec_type}",
                                asset_value=val[:60],
                                asset_type="secret",
                                tool="js_analyzer",
                                stage="09_javascript",
                                parent_id=j_url
                            )
            except Exception:
                continue

        self.secrets = secrets
        self._save_stage_artifact("09_javascript", "js_urls.txt", "\n".join(list(js_urls)))
        self._save_stage_artifact("09_javascript", "discovered_secrets.json", [s.model_dump() for s in self.secrets])
        self._save_stage_artifact("05_js_intelligence", "discovered_secrets.json", [s.model_dump() for s in self.secrets])

        # 5. URL Canonicalization, Clustering & Parameter Intelligence Database
        live_hosts = {la.host for la in self.live_assets if la.host}
        if not live_hosts:
            live_hosts = {self.domain}

        canon_endpoints, canon_parameters, endpoint_families = URLCanonicalizer.process_url_inventory(
            raw_urls=list(raw_crawled_urls),
            live_hosts=live_hosts,
            target_domain=self.domain,
        )

        # Record lineage for canonical endpoints and parameters
        for ep in canon_endpoints:
            self.engagement_mgr.record_lineage(
                asset_id=ep.url,
                asset_value=ep.url,
                asset_type="endpoint",
                tool="url_canonicalizer",
                stage="07_urls",
                parent_id=self.domain
            )
        for p in canon_parameters:
            self.engagement_mgr.record_lineage(
                asset_id=f"{p.endpoint}?{p.parameter}",
                asset_value=p.parameter,
                asset_type="parameter",
                tool="parameter_intelligence",
                stage="08_parameters",
                parent_id=p.endpoint
            )

        # Fallback parameters if none discovered via crawl
        if not canon_parameters:
            for fallback_p, p_classes in [("category", ["SQLi"]), ("search", ["XSS", "SQLi"]), ("url", ["SSRF"])]:
                fb_url = f"{self.base_url}/filter?{fallback_p}=test"
                fb_cls = ParameterIntelligenceEngine.classify(fb_url, fallback_p, "test")
                fb_rec = ParameterRecord(
                    parameter=fallback_p,
                    endpoint=fb_url,
                    method="GET",
                    source="inferred_fallback",
                    potential_classes=fb_cls.potential_vulns,
                    sample_value="test",
                    context={
                        "role": fb_cls.role.value,
                        "risk_level": fb_cls.risk_level,
                        "is_active_candidate": fb_cls.is_active_candidate,
                        "rationale": fb_cls.rationale,
                        "family_pattern": "/filter",
                    },
                )
                canon_parameters.append(fb_rec)
                self.engagement_mgr.record_lineage(
                    asset_id=f"{self.base_url}/filter?{fallback_p}",
                    asset_value=fallback_p,
                    asset_type="parameter",
                    tool="inferred_fallback",
                    stage="08_parameters",
                    parent_id=self.base_url
                )

        self.endpoints = canon_endpoints
        self.parameters = canon_parameters

        # Discovered endpoints in 07_urls
        all_eps_text = "\n".join([e.url for e in self.endpoints])
        self._save_stage_artifact("07_urls", "all_urls.txt", all_eps_text)
        self._save_stage_artifact("07_urls", "discovered_endpoints.json", [e.model_dump() for e in self.endpoints])
        self._save_stage_artifact("15_browser", "playwright_endpoints.json", [e.model_dump() for e in self.endpoints if "playwright" in e.source])

        # Discovered parameters & endpoint families in 08_parameters
        all_params_text = "\n".join([
            f"{p.endpoint} -> {p.parameter} (role={p.context.get('role', 'unknown') if p.context else 'unknown'}, classes={','.join(p.potential_classes)}, active={p.context.get('is_active_candidate', True) if p.context else True})"
            for p in self.parameters
        ])
        self._save_stage_artifact("08_parameters", "all_parameters.txt", all_params_text)
        self._save_stage_artifact("08_parameters", "discovered_parameters.json", [p.model_dump() for p in self.parameters])
        self._save_stage_artifact("08_parameters", "endpoint_families.json", [
            {
                "pattern_id": f.pattern_id,
                "sample_url": f.sample_url,
                "path_pattern": f.path_pattern,
                "method": f.method,
                "category": f.category,
                "raw_urls_count": f.raw_urls_count,
                "live_host": f.live_host,
                "parameters": {k: v.to_dict() for k, v in f.parameters.items()}
            }
            for f in endpoint_families
        ])

        # API Endpoints in 10_api
        api_eps = [e for e in self.endpoints if e.category == "API" or "/api" in e.path]
        api_eps_text = "\n".join([e.url for e in api_eps]) if api_eps else ""
        self._save_stage_artifact("10_api", "api_endpoints.txt", api_eps_text)
        self._save_stage_artifact("10_api", "api_map.json", [e.model_dump() for e in api_eps])

        # Ingest endpoints and parameters into Wordlist Intelligence and build customized target wordlists
        try:
            ep_urls = [e.url for e in self.endpoints]
            param_names = [p.parameter for p in self.parameters]
            if ep_urls:
                self.wordlist_agent.ingest_discovery("endpoint", ep_urls)
            if param_names:
                self.wordlist_agent.ingest_discovery("parameter", param_names)

            # Generate target-tailored custom wordlists
            custom_dir_cands = self.wordlist_agent.generate_custom_candidates(WordlistCategory.DIRECTORIES, max_candidates=500)
            if custom_dir_cands:
                self._save_stage_artifact("06_content", "custom_target_wordlist.txt", "\n".join(custom_dir_cands))

            custom_param_cands = self.wordlist_agent.generate_custom_candidates(WordlistCategory.PARAMETERS, max_candidates=500)
            if custom_param_cands:
                self._save_stage_artifact("08_parameters", "custom_parameters_wordlist.txt", "\n".join(custom_param_cands))
        except Exception as e:
            logger.debug(f"Wordlist intelligence attack surface ingestion notice: {e}")

        # Backwards compatibility
        self._save_stage_artifact("04_attack_surface", "discovered_endpoints.json", [e.model_dump() for e in self.endpoints])
        self._save_stage_artifact("04_attack_surface", "discovered_parameters.json", [p.model_dump() for p in self.parameters])

        # Burp Traffic Artifacts
        if self.burp_transactions:
            self._save_stage_artifact("04_attack_surface", "burp_traffic.json", self.burp_transactions)
            self._save_stage_artifact("08_burp_suite", "burp_proxy_traffic.json", self.burp_transactions)
            self._save_stage_artifact("08_burp_suite", "traffic_summary.txt", f"Intercepted {len(self.burp_transactions)} in-scope HTTP transactions from Burp Suite / Proxy.\n")

        self.engagement_mgr.complete_stage("06_content", item_count=len(fuzz_lines))
        self.engagement_mgr.complete_stage("07_urls", item_count=len(self.endpoints))
        self.engagement_mgr.complete_stage("08_parameters", item_count=len(self.parameters))
        self.engagement_mgr.complete_stage("09_javascript", item_count=len(self.secrets))
        self.engagement_mgr.complete_stage("10_api", item_count=len(api_eps))

        await self._emit("surface_done", endpoints=len(self.endpoints), parameters=len(self.parameters), secrets=len(self.secrets))
        return self.endpoints, self.parameters

    # ── STAGE 14 - 18: TESTING, MULTI-LAYER VERIFICATION & CORRELATION ─────────
    async def stage_testing_and_verification(self) -> List[HunterFinding]:
        self.engagement_mgr.start_stage("12_vulnerabilities")
        self.engagement_mgr.start_stage("13_evidence")
        self.fsm.transition_to(HunterState.HYPOTHESIZE, "Formulating attack hypotheses based on mapped parameters")
        await self._emit("hypothesize_start", message=f"Formulating hypotheses for {len(self.parameters)} parameters...")

        # Correlate attack surface to prioritize high-value targets
        correlated = CorrelationEngine.correlate_attack_surface(
            self.endpoints, self.parameters, self.secrets, self.live_assets
        )
        self._save_stage_artifact("06_testing", "correlated_attack_surface.json", correlated)

        hypotheses = []
        for p in self.parameters:
            ctx = getattr(p, "context", None) or {}
            if not ctx.get("is_active_candidate", True):
                continue
            for p_class in p.potential_classes:
                hypotheses.append({
                    "target_url": p.endpoint,
                    "param": p.parameter,
                    "vuln_type": p_class,
                    "rationale": f"Parameter '{p.parameter}' ({ctx.get('role', 'input')}) maps to {p_class} vulnerability pattern"
                })

        self._save_stage_artifact("12_vulnerabilities", "vulnerability_hypotheses.json", hypotheses)

        # ── Cognitive Council Dialectic Peer Review & Debate ──
        if self.use_triad and not self.ai_degraded:
            try:
                self.council.state.update_recon(
                    subdomains=[r.asset for r in self.subdomains],
                    live_assets=[la.model_dump() for la in self.live_assets],
                    technologies=[t for la in self.live_assets for t in (la.technologies or [])]
                )
                self.council.state.update_surface(
                    endpoints=[e.model_dump() for e in self.endpoints],
                    parameters=[p.model_dump() for p in self.parameters],
                    secrets=[s.model_dump() for s in self.secrets]
                )
                debated_records = []
                for hypo in hypotheses[:5]:
                    d_res = await self.council.debate_hypothesis(
                        vuln_type=hypo.get("vuln_type", "Unknown"),
                        endpoint=hypo.get("target_url", self.base_url),
                        parameter=hypo.get("param"),
                        initial_observation=hypo.get("rationale", ""),
                    )
                    debated_records.append(d_res.to_dict())
                self._save_stage_artifact("12_vulnerabilities", "cognitive_council_debates.json", debated_records)
                await self._emit("council_debate_done", count=len(debated_records), message=f"Cognitive Council evaluated {len(debated_records)} hypotheses.")
            except Exception as e:
                logger.debug(f"Cognitive Council debate notice: {e}")

        # ── Burp Repeater Controlled Differential Probing ────────────────────
        if self.burp_controller and not self.dry_run and self.authorized:
            try:
                for hypo in hypotheses[:5]:
                    h_url = hypo.get("target_url")
                    h_param = hypo.get("param")
                    h_type = hypo.get("vuln_type", "Generic")
                    if not h_url:
                        continue

                    exp = self.burp_controller.create_repeater_experiment(
                        base_tx_id=f"tx_{int(time.time())}",
                        hypothesis=f"Testing {h_type} differential behavior on {h_param}",
                        mutation_description=f"Differential probe for {h_type}",
                        mutated_request={
                            "method": "GET",
                            "url": inject_url_parameter(h_url, h_param, "' OR '1'='1") if h_param else h_url,
                            "headers": {"User-Agent": "HunterAI-Burp-Repeater/1.0", "X-Hunter-Probe": h_type}
                        }
                    )
                    executed_exp = await self.burp_controller.execute_experiment(exp.experiment_id)
                    self.burp_repeater_experiments.append(executed_exp.to_dict())

                if self.burp_repeater_experiments:
                    self._save_stage_artifact("12_vulnerabilities", "burp_repeater_experiments.json", self.burp_repeater_experiments)
                    self._save_stage_artifact("08_burp_suite", "burp_repeater_experiments.json", self.burp_repeater_experiments)
                    await self._emit("burp_repeater_done", count=len(self.burp_repeater_experiments), message=f"Burp Repeater executed {len(self.burp_repeater_experiments)} differential experiments.")
            except Exception as e:
                logger.debug(f"[BurpRepeater] Execution notice: {e}")

        self.fsm.transition_to(HunterState.TEST, "Executing targeted vulnerability skills")
        await self._emit("test_start", count=len(hypotheses), message="Dispatching testing skills with context...")

        # Profile & Authorization Guardrails
        if self.profile == "passive":
            self.engagement_mgr.record_timeline_event(
                stage="12_vulnerabilities",
                event="skipped_passive_profile",
                message="Vulnerability testing skipped under passive profile"
            )
            await self._emit("safety_notice", message="Passive profile active: skipping active vulnerability testing.")
        elif self.dry_run:
            self.engagement_mgr.record_timeline_event(
                stage="12_vulnerabilities",
                event="skipped_dry_run",
                message="Dry-run enabled: skipping active network vulnerability testing"
            )
            await self._emit("safety_notice", message="Dry-run enabled: skipping active testing.")
        elif not self.authorized:
            await self._emit("safety_notice", message="🛡️ Active testing disabled (--authorized flag not provided). Running read-only passive analysis only.")
        else:
            # ── 1. Autonomous Investigation Controller (OODA Loop) ─────────
            try:
                controller = InvestigationController(orchestrator=self)
                inv_budget = min(1800.0, self.timeout_multiplier * 300.0)
                inv_summary = await controller.run(budget_seconds=inv_budget)
                logger.info(
                    f"[InvestigationController] Completed: {inv_summary.confirmed} confirmed, "
                    f"{inv_summary.rejected} rejected, {inv_summary.tests_executed} tests, "
                    f"{inv_summary.ai_calls} AI calls in {inv_summary.duration_sec}s"
                )
            except Exception as e:
                logger.warning(f"[InvestigationController] Loop execution error: {e}", exc_info=True)

            # ── 2. Active Vulnerability Scanners (Nuclei / Dalfox / Nikto) ──────

            # 3. Nuclei Active Vulnerability Scan (Critical, High, Medium CVEs)
            if self.profile in ("full", "hunter", "deep"):
                try:
                    for target_live in self.live_assets[:3]:
                        nuc_lines, meta_nuc = await self.master_tools.execute_artifact(
                            "nuclei", {"url": target_live.url}, self.engagement_mgr, "12_vulnerabilities", input_source=target_live.url
                        )
                        if meta_nuc and meta_nuc.raw_output_file:
                            self.tool_logs.append(meta_nuc.raw_output_file)
                        for nline in nuc_lines:
                            if isinstance(nline, str) and "[" in nline:
                                from hunter_ai.pipeline.qualification_gate import FindingQualificationGate
                                title_part = nline.split("]")[0].strip("[]")
                                payload = self._build_proof_payload("NucleiExposure", nline)
                                is_q, f_obj, rationale = FindingQualificationGate.evaluate_candidate(
                                    title=f"Nuclei: {title_part}",
                                    asset=self.domain,
                                    endpoint=target_live.url,
                                    vuln_type="NucleiExposure",
                                    raw_evidence=nline,
                                    source_tool="nuclei",
                                    verifier_result=self._court_verifier_result(payload),
                                    proof_payload=payload
                                )
                                if is_q and f_obj:
                                    self.findings.append(f_obj)
                                else:
                                    self._defer_hypothesis(
                                        f"Nuclei: {title_part}", target_live.url,
                                        "NucleiExposure", "nuclei", rationale, nline,
                                    )
                except Exception as e:
                    logger.debug(f"Nuclei test error: {e}")

            # 4. Dalfox XSS Scanning on discovered endpoints with parameters
            if self.profile in ("full", "hunter", "deep"):
                try:
                    xss_targets = [p for p in self.parameters if "XSS" in p.potential_classes][:5]
                    for xss_p in xss_targets:
                        dalfox_url = xss_p.endpoint
                        dalf_lines, meta_dalf = await self.master_tools.execute_artifact(
                            "dalfox", {"url": dalfox_url}, self.engagement_mgr, "12_vulnerabilities", input_source=dalfox_url
                        )
                        if meta_dalf and meta_dalf.raw_output_file:
                            self.tool_logs.append(meta_dalf.raw_output_file)
                        for dl in dalf_lines:
                            if isinstance(dl, str) and dl:
                                from hunter_ai.pipeline.qualification_gate import FindingQualificationGate
                                payload = self._build_proof_payload("XSS", dl)
                                is_q, f_obj, rationale = FindingQualificationGate.evaluate_candidate(
                                    title=f"XSS Candidate: {xss_p.parameter}",
                                    asset=self.domain,
                                    endpoint=dalfox_url,
                                    vuln_type="XSS",
                                    raw_evidence=dl,
                                    source_tool="dalfox",
                                    verifier_result=self._court_verifier_result(payload),
                                    proof_payload=payload
                                )
                                if is_q and f_obj:
                                    self.findings.append(f_obj)
                                else:
                                    self._defer_hypothesis(
                                        f"XSS Candidate: {xss_p.parameter}", dalfox_url,
                                        "XSS", "dalfox", rationale, dl,
                                    )
                except Exception as e:
                    logger.debug(f"Dalfox XSS error: {e}")

            # 5. Nikto Web Server Vulnerability Scan
            if self.profile in ("full", "hunter", "deep"):
                try:
                    for target_live in self.live_assets[:2]:
                        nikto_lines, meta_nikto = await self.master_tools.execute_artifact(
                            "nikto", {"url": target_live.url}, self.engagement_mgr, "12_vulnerabilities", input_source=target_live.url
                        )
                        if meta_nikto and meta_nikto.raw_output_file:
                            self.tool_logs.append(meta_nikto.raw_output_file)
                        for nk in nikto_lines:
                            if isinstance(nk, str) and "OSVDB" in nk or "CVE" in str(nk):
                                from hunter_ai.pipeline.qualification_gate import FindingQualificationGate
                                payload = self._build_proof_payload("MisconfigExposure", nk)
                                is_q, f_obj, rationale = FindingQualificationGate.evaluate_candidate(
                                    title=f"Nikto: {nk[:80]}",
                                    asset=self.domain,
                                    endpoint=target_live.url,
                                    vuln_type="MisconfigExposure",
                                    raw_evidence=nk,
                                    source_tool="nikto",
                                    verifier_result=self._court_verifier_result(payload),
                                    proof_payload=payload
                                )
                                if is_q and f_obj:
                                    self.findings.append(f_obj)
                                else:
                                    self._defer_hypothesis(
                                        f"Nikto: {nk[:80]}", target_live.url,
                                        "MisconfigExposure", "nikto", rationale, nk,
                                    )
                except Exception as e:
                    logger.debug(f"Nikto scan error: {e}")

            # 6. FFUF Hidden Parameter Discovery
            if self.profile in ("full", "hunter", "deep") and self.live_assets:
                try:
                    params_wl = self.wordlist_mgr.get_wordlist("parameters", profile=self.profile)
                    target_url = self.live_assets[0].url
                    ffuf_params_lines, meta_ffuf_p = await self.master_tools.execute_artifact(
                        "ffuf_params", {
                            "url": target_url,
                            "wordlist": params_wl,
                            "content_size": 0
                        }, self.engagement_mgr, "08_parameters", input_source=target_url
                    )
                    for fp in ffuf_params_lines:
                        if isinstance(fp, str) and fp.strip():
                            p_name = fp.strip()
                            fp_cls = ParameterIntelligenceEngine.classify(target_url, p_name, "test")
                            self.parameters.append(ParameterRecord(
                                parameter=p_name,
                                endpoint=target_url,
                                method="GET",
                                source="ffuf_discovery",
                                potential_classes=fp_cls.potential_vulns,
                                sample_value="test",
                                context={
                                    "role": fp_cls.role.value,
                                    "risk_level": fp_cls.risk_level,
                                    "is_active_candidate": fp_cls.is_active_candidate,
                                    "rationale": fp_cls.rationale,
                                    "family_pattern": urlparse(target_url).path or "/",
                                }
                            ))
                    if meta_ffuf_p and meta_ffuf_p.raw_output_file:
                        self.tool_logs.append(meta_ffuf_p.raw_output_file)
                except Exception as e:
                    logger.debug(f"ffuf_params error: {e}")

        # ── AI TRIAGE (LocalTriadAgent / Ollama) ─────────────────────────────
        # Wire the real Ollama models into the pipeline for strategic analysis
        if self.profile in ("full", "hunter", "deep"):
            try:
                from hunter_ai.brain.local_triad_agent import LocalTriadAgent
                triad = LocalTriadAgent(ollama_host=self.ollama_host)
                self._triad_instance = triad

                # 1. xploiter/pentester: Recon triage — prioritize discovered assets
                subdomain_list = [la.url for la in self.live_assets[:30]]
                port_list = []  # populated by nmap if available
                ep_list = [e.url for e in self.endpoints[:30]]
                await self._emit("ai_triad_start", model="xploiter/pentester", message="AI triage of discovered assets...")
                triage_result = await triad.triage_recon_assets(
                    target=self.base_url,
                    subdomains=subdomain_list,
                    ports=port_list,
                    endpoints=ep_list
                )
                self._save_stage_artifact("12_vulnerabilities", "ai_triage_recon.json", triage_result)
                self._record_reasoning(
                    kind="triage_recon_assets", model="xploiter/pentester",
                    prompt_frame=f"{self.base_url}|{subdomain_list}|{port_list}|{ep_list}",
                    output=triage_result,
                )
                logger.info(f"[AI/xploiter] Recon triage done: {len(str(triage_result.get('analysis', '')))} chars")
                await self._emit("ai_triad_done", model="xploiter/pentester", chars=len(str(triage_result.get("analysis", ""))))

                # 2. Qwen 2.5 Coder: JS code audit for each JS file secret hit
                js_audit_results = []
                for s in self.secrets[:5]:
                    try:
                        await self._emit("ai_triad_start", model="qwen2.5-coder", message=f"Auditing JS: {s.file_url}")
                        code_result = await triad.audit_code_or_javascript(
                            js_url=s.file_url,
                            code_content=s.matched_string
                        )
                        js_audit_results.append(code_result)
                        self._record_reasoning(
                            kind="js_audit", model="qwen2.5-coder",
                            prompt_frame=f"{s.file_url}|audit:{s.secret_type}",
                            output=code_result,
                        )
                    except Exception as e:
                        logger.debug(f"[AI/Qwen] JS audit error: {e}")
                if js_audit_results:
                    self._save_stage_artifact("09_javascript", "ai_js_audit.json", js_audit_results)
                    await self._emit("ai_triad_done", model="qwen2.5-coder", count=len(js_audit_results))

                # NOTE: the former "WhiteRabbitNeo offensive strategy for raw probe
                # findings" block was removed — `raw_probe_findings` was never
                # populated (dead code). The equivalent capability now runs inside
                # InvestigationController (court-gated) — see LEDGER-009.

            except Exception as e:
                logger.warning(f"[AI/LocalTriad] Ollama not available — skipping AI analysis: {e}")

        # Add any high-confidence secrets (Shannon entropy validated)
        for s in self.secrets:
            if s.confidence >= 0.85:
                from hunter_ai.pipeline.qualification_gate import FindingQualificationGate
                # Secret presence is directly observed (we fetched the asset), but
                # a leaked key has no Proof-of-Execution signature: it is deferred
                # as a hypothesis rather than reported as a CONFIRMED vuln.
                payload = self._build_proof_payload("SecretLeak", s.matched_string)
                is_q, f_obj, rationale = FindingQualificationGate.evaluate_candidate(
                    title=f"Leaked Credential / Secret ({s.secret_type})",
                    asset=self.domain,
                    endpoint=s.file_url,
                    vuln_type="SecretLeak",
                    raw_evidence=s.matched_string,
                    source_tool="CodeIntelligence_SecretHunter",
                    verifier_result=self._court_verifier_result(payload, directly_observed=True),
                    proof_payload=payload
                )
                if is_q and f_obj:
                    self.findings.append(f_obj)
                else:
                    self._defer_hypothesis(
                        f"Leaked Credential / Secret ({s.secret_type})", s.file_url,
                        "SecretLeak", "CodeIntelligence_SecretHunter", rationale,
                        s.matched_string,
                    )

        # ── TRANSITION TO VERIFICATION (ENFORCES ZERO FALSE POSITIVES) ────────
        self.fsm.transition_to(HunterState.VERIFY, "Multi-layer verification & false positive filtering")
        await self._emit("verify_start", message="Enforcing Verification Invariants (Reflection != Execution)...")

        # ── DEDUPLICATION & CORRELATION ───────────────────────────────────────
        self.fsm.transition_to(HunterState.CORRELATE, "Correlating multi-source attack chains")
        self.findings = DeduplicationEngine.deduplicate(self.findings)

        # Artifacts in 12_vulnerabilities and 13_evidence
        findings_json = [f.model_dump() for f in self.findings]
        proofs_json = [
            {"finding": f.finding, "endpoint": f.endpoint, "parameter": f.parameter, "evidence": [e.model_dump() for e in f.evidence]}
            for f in self.findings if f.evidence
        ]
        self._save_stage_artifact("12_vulnerabilities", "findings.json", findings_json)
        self._save_stage_artifact("12_vulnerabilities", "deferred_hypotheses.json", self.deferred_hypotheses)
        self._save_stage_artifact("13_evidence", "verification_proofs.json", proofs_json)
        self._save_stage_artifact("13_evidence", "evidence_graph.json", self.evidence_graph.to_dict())
        self._save_stage_artifact("07_verification", "verification_proofs.json", findings_json)

        # Register confirmed findings with Burp Gateway and export issues
        burp_issues = []
        if hasattr(self, "_burp_agent") and self._burp_agent and hasattr(self._burp_agent, "gateway"):
            for f_obj in self.findings:
                try:
                    f_dict = f_obj.model_dump() if hasattr(f_obj, "model_dump") else f_obj
                    self._burp_agent.gateway.register_confirmed_finding({
                        "title": f_dict.get("finding", "Finding"),
                        "severity": f_dict.get("severity", "HIGH"),
                        "endpoint": f_dict.get("endpoint", self.base_url),
                        "vuln_type": f_dict.get("vuln_type", "Vulnerability"),
                        "description": f_dict.get("description", f_dict.get("finding", "")),
                        "evidence": str(f_dict.get("evidence", "")),
                    })
                    burp_issues.append(f_dict)
                except Exception as be:
                    logger.debug(f"[BurpGateway] Finding registration notice: {be}")
        if burp_issues:
            self._save_stage_artifact("08_burp_suite", "burp_findings_issues.json", burp_issues)

        self.engagement_mgr.complete_stage("12_vulnerabilities", item_count=len(self.findings))
        self.engagement_mgr.complete_stage("13_evidence", item_count=len(proofs_json))

        # ── ASSESS IMPACT & PRIORITY RANKING ──────────────────────────────────
        self.fsm.transition_to(HunterState.ASSESS_IMPACT, "Calculating dynamic CVSS scores and assigning priorities (P0 - P5)")

        # ── STAGE: FINAL EVIDENCE COURT (Phase 3) ──────────────────────────────
        # جلسة محكمة أخيرة على القائمة كاملة: أي نتيجة بلا سلسلة إثبات سليمة
        # تُخفَّض إلى deferred_hypotheses ولا تُعرض في التقرير مطلقًا.
        court_report = self._run_final_court()
        if court_report["stats"]["DEMOTED"] > 0:
            await self._emit(
                "final_court_demoted",
                demoted=court_report["stats"]["DEMOTED"],
                passed=court_report["stats"]["PASSED"],
                message=(
                    "Final Evidence Court DEMOTED "
                    f"{court_report['stats']['DEMOTED']} findings to deferred hypotheses "
                    "(insufficient evidence chain) — only court-passed findings reach the report."
                ),
            )
        else:
            await self._emit(
                "final_court_all_passed",
                passed=court_report["stats"]["PASSED"],
                message="Final Evidence Court: every finding's evidence chain fully verified.",
            )

        self.fsm.transition_to(HunterState.REPORT, "Generating final Executive and Technical reports")

        await self._emit("report_start", message="Writing final scan reports and persistent tool logs...")
        rep_paths = await self._generate_reports()
        self.last_reports = rep_paths

        self.fsm.transition_to(HunterState.COMPLETE, "All pipeline stages completed successfully")
        await self._emit("pipeline_complete", findings=len(self.findings), reports=rep_paths)

        return self.findings

    def _run_final_court(self) -> Dict[str, Any]:
        """
        جلسة المحكمة النهائية (Phase 3): تحكيم كل نتيجة قبل التقرير.
        - المحجب يُنقل إلى deferred_hypotheses (يبقى إثباته للاستمرار التحقيقي).
        - كل حكم يُسجل في EvidenceStore الموحد (court_verdict JSONL).
        - الجلسة كلها artifact في 13_evidence/court_session.json.
        آمن ضد الانفجار: لو المحكمة نفسها فشلت، القائمة تعود سليمة (fail-open للقائمة
        الموجودة، fail-closed في الجودة القديمة — لأن inspection القائم كان court-gated).
        """
        from hunter_ai.pipeline.final_court import FinalEvidenceCourt
        from core.evidence_store import EvidenceStore

        report = FinalEvidenceCourt(run_id=self.session_id).audit_docket(self.findings)
        try:
            store = EvidenceStore()
            for entry in report.entries:
                try:
                    store.record_court_verdict(
                        run_id=self.session_id,
                        finding_id=entry.finding_id,
                        title=entry.title,
                        endpoint=entry.endpoint,
                        verdict=entry.verdict,
                        reason_code=entry.reason_code,
                        rationale=entry.rationale,
                        session_id=self.session_id,
                    )
                except Exception as ve:  # noqa: BLE001
                    logger.debug(f"[FinalCourt] verdict record notice: {ve}")
        except Exception as se:  # noqa: BLE001
            logger.debug(f"[FinalCourt] evidence store notice: {se}")

        # تنفيذ الأحكام: الإسقاط الفعلي (نشطب بالمُعرِّف — عناوين مكررة/فارغة لا تلعق سجلًا)
        if report.demoted:
            demoted_ids = {e.finding_id for e in report.entries if e.verdict == "DEMOTED"}
            self.deferred_hypotheses.extend(report.demoted)
            kept: List[Any] = []
            for f in self.findings:
                d = f if isinstance(f, dict) else f.model_dump()
                if str(d.get("id", "")) in demoted_ids:
                    continue
                kept.append(f)
            self.findings = kept

        session = report.to_dict()
        session["deferred_by_court"] = report.demoted
        try:
            self._save_stage_artifact("13_evidence", "court_session.json", session)
        except Exception:  # noqa: BLE001
            pass
        return session

    async def _generate_reports(self) -> Dict[str, str]:
        """Generate final JSON, Markdown, and HTML reports ordered by Priority Tier across 14_reports and legacy 09_reports"""
        self.engagement_mgr.start_stage("14_reports")
        reports_dir = os.path.join(self.artifact_root, "14_reports")
        legacy_dir = os.path.join(self.artifact_root, "09_reports")
        os.makedirs(reports_dir, exist_ok=True)
        os.makedirs(legacy_dir, exist_ok=True)

        ranked = PriorityEngine.rank_findings(self.findings)
        findings_data = self.secret_sanitizer.sanitize_data([
            {"priority": tier, **item.model_dump()} for tier, item in ranked
        ])

        # JSON Summary
        json_path = os.path.join(reports_dir, "final_findings.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(findings_data, f, indent=2, default=str)
        self._save_stage_artifact("09_reports", "final_findings.json", findings_data)

        # Program-Specific Deliverables (BBP vs VDP)
        if self.program_metadata:
            try:
                from core.program_intelligence import ProgramIntelligence
                if self.program_metadata.program_type in (ProgramType.BBP, ProgramType.SELF_HOSTED_BBP):
                    h1_rep = ProgramIntelligence.generate_hackerone_report(self.domain, findings_data, self.program_metadata)
                    with open(os.path.join(reports_dir, "hackerone_bounty_submission.md"), "w", encoding="utf-8") as f:
                        f.write(h1_rep)
                    self._save_stage_artifact("09_reports", "hackerone_bounty_submission.md", h1_rep)

                if self.program_metadata.contact_email:
                    vdp_email = ProgramIntelligence.generate_vdp_email_template(
                        self.domain,
                        self.program_metadata.contact_email,
                        findings_data,
                        self.program_metadata.acknowledgments_url
                    )
                    with open(os.path.join(reports_dir, "vdp_disclosure_email.txt"), "w", encoding="utf-8") as f:
                        f.write(vdp_email)
                    self._save_stage_artifact("09_reports", "vdp_disclosure_email.txt", vdp_email)

                if self.program_metadata.visibility == ProgramVisibility.PRIVATE:
                    nda_notice = f"CONFIDENTIAL / STRICT NDA\nTarget {self.domain} is a PRIVATE security program.\nZero public disclosure permitted."
                    with open(os.path.join(reports_dir, "CONFIDENTIAL_NDA_NOTICE.txt"), "w", encoding="utf-8") as f:
                        f.write(nda_notice)
            except Exception as e:
                logger.debug(f"Program reporting notice: {e}")

        # Bug Bounty Markdown Report
        md_lines = [
            f"# 🎯 HunterAI Bug Bounty Master Report: {self.domain}",
            f"- **Target**: `{self.raw_target}`",
            f"- **Session ID**: `{self.session_id}`",
            f"- **Active Testing Mode**: `{'AUTHORIZED' if self.authorized else 'RESTRICTED (Safe)'}`",
            f"- **Workflow Mode**: `{self.workflow.upper()}`",
            f"- **Date**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **Total Confirmed Vulnerabilities**: {len(self.findings)}",
            f"- **Artifacts Directory**: `{self.artifact_root}`",
            f"- **Tool Output Logs**: {len(self.tool_logs)} files saved in `data/tool_outputs/`\n",
            "## 🌐 Target Reconnaissance & Attack Surface Inventory\n",
            "| Asset Category | Discovered Count | Operational Status |",
            "| :--- | :--- | :--- |",
            f"| **Subdomains Discovered** | `{len(self.subdomains)}` | Mapped via crt.sh & subfinder |",
            f"| **Live Web Assets** | `{len(self.live_assets)}` | Active HTTP/HTTPS Services |",
            f"| **Discovered Endpoints** | `{len(self.endpoints)}` | Crawled & Mapped Routes |",
            f"| **Mapped Parameters** | `{len(self.parameters)}` | Evaluated for Attack Hypotheses |\n",
            "## ⚖️ Confirmed Vulnerabilities (Evidence Court Adjudicated)\n",
        ]

        if not self.findings:
            md_lines.append("> **✅ ZERO VULNERABILITIES CONFIRMED (Clean Defense Boundary)**")
            md_lines.append("> All raw observations were evaluated by the Evidence Court and Finding Qualification Gate.")
            md_lines.append("> Expected public files (`/robots.txt`, `/sitemap.xml`) and standard web ports (80/443) have zero security impact and are classified as Perimeter Inventory.")
            md_lines.append("> No high-confidence, reproducible vulnerabilities were confirmed in this engagement run.\n")

        # Group by Priority (P0 - P5)
        for priority_tag in ["P0", "P1", "P2", "P3", "P4", "P5"]:
            tier_items = [item for tier, item in ranked if tier == priority_tag]
            if tier_items:
                md_lines.append(f"### Tier {priority_tag} ({len(tier_items)} Findings)")
                for f in tier_items:
                    md_lines.append(f"#### 🔥 [{priority_tag}] {f.finding}")
                    md_lines.append(f"- **Endpoint**: `{f.endpoint}`")
                    if f.parameter:
                        md_lines.append(f"- **Parameter**: `{f.parameter}`")
                    md_lines.append(f"- **Severity**: `{f.severity}` | **CVSS v3.1**: `{f.cvss_score}`")
                    md_lines.append(f"- **Confidence**: `{int(f.confidence * 100)}%` | **Status**: `{f.status.value}`")
                    if f.evidence:
                        md_lines.append(f"- **Evidence**: {f.evidence[0].description}")
                    if f.reproduction:
                        md_lines.append(f"- **Reproduction**: `{f.reproduction.curl_command}`")
                    md_lines.append(f"- **Remediation**: {f.remediation}\n")

        md_content = self.secret_sanitizer.sanitize_text("\n".join(md_lines))
        md_path = os.path.join(reports_dir, "bug_bounty_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)
        self._save_stage_artifact("09_reports", "bug_bounty_report.md", md_content)

        # HTML Report
        html_path = os.path.join(reports_dir, "report.html")
        html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>HunterAI Security Report - {self.domain}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }}
    .card {{ background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #38bdf8; }}
    .critical {{ border-left-color: #ef4444; }}
    .high {{ border-left-color: #f97316; }}
    .code {{ background: #0f172a; padding: 8px; border-radius: 4px; font-family: monospace; }}
    h1 {{ color: #38bdf8; }}
  </style>
</head>
<body>
  <h1>HunterAI Security Engagement Report</h1>
  <p><strong>Target:</strong> {self.domain} | <strong>Mode:</strong> {self.workflow.upper()} | <strong>Findings:</strong> {len(self.findings)}</p>
"""
        for tier, f in ranked:
            cls = "critical" if f.severity == "Critical" else ("high" if f.severity == "High" else "")
            html_content += f"""  <div class="card {cls}">
    <h3>[{tier}] {f.finding} ({f.severity})</h3>
    <p><strong>Endpoint:</strong> <span class="code">{f.endpoint}</span></p>
    <p><strong>CVSS Score:</strong> {f.cvss_score}</p>
    <p><strong>Remediation:</strong> {f.remediation}</p>
  </div>\n"""
        html_content += "</body>\n</html>"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(self.secret_sanitizer.sanitize_text(html_content))

        # Compute Temporal Diff against prior engagement run
        diff_info = {}
        try:
            prev_run = self.engagement_mgr.get_previous_run_dir()
            diff_engine = EngagementDiffEngine(self.artifact_root, prev_run)
            diff_json, diff_md = diff_engine.write_diff_reports(self.domain)
            diff_info = {"diff_json": diff_json, "diff_md": diff_md, "previous_run": prev_run}
            self.engagement_mgr.record_timeline_event(
                stage="14_reports",
                event="temporal_diff_computed",
                message=f"Attack surface drift calculated against {prev_run or 'Baseline'}"
            )
        except Exception as e:
            logger.debug(f"Could not compute diff: {e}")

        # Structured Comprehensive Desktop Workspace Export
        reports_dict = {"json": json_path, "markdown": md_path, "html": html_path, **diff_info}
        try:
            desktop_target_dir = DesktopExportManager.export_engagement(
                domain=self.domain,
                artifact_root=self.artifact_root,
                reports_dict=reports_dict,
                subdomains=self.subdomains,
                live_assets=self.live_assets,
                endpoints=self.endpoints,
                parameters=self.parameters,
                findings=self.findings,
                tool_logs=self.tool_logs,
                workflow=self.workflow,
                profile=self.profile,
                ai_status=self.ai_preflight_result.to_dict() if self.ai_preflight_result else None,
            )
            if desktop_target_dir:
                diff_info["desktop_export"] = desktop_target_dir
                reports_dict["desktop_export"] = desktop_target_dir
        except Exception as e:
            logger.debug(f"Could not generate Desktop export workspace: {e}")

        self.last_reports = reports_dict
        self.engagement_mgr.complete_stage("14_reports", item_count=len(self.findings))
        return reports_dict

    async def run(self) -> Dict[str, Any]:
        """Execute full HunterAI Master Pipeline end-to-end"""
        # Windows consoles may use a legacy code page (e.g. cp1256) that cannot
        # encode the Unicode banners/emoji printed below.  Make stdio safe first.
        configure_stdio()
        t0 = time.time()
        await self._emit("pipeline_start", target=self.raw_target, message=f"Starting HunterAI Pipeline on {self.domain}")

        # 🔬 Print tool availability diagnostic so user knows what runs natively
        self.master_tools.print_tools_status(profile=self.profile)

        # Step 0: Scope Gate — MUST run before anything that touches the network
        # (including the AI preflight, which egresses to the model host).
        # A purely local pattern/subnet decision, so an unauthorized target is
        # rejected with reason="out_of_scope" and no outbound request is made.
        if not await self.stage_scope_check():
            return {"status": "aborted", "reason": "out_of_scope", "target": self.raw_target}

        # 🔴 BurpAgent & Gateway Subsystem (Auto-Detect 127.0.0.1:8080 & Launch Port 8085)
        await self._init_burp_agent_subsystem()

        # Validate local integration before AI, scope, or any target-facing stage.
        if not await self.stage_integration_preflight():
            return {
                "status": "aborted",
                "reason": "agent_burp_browser_preflight_failed",
                "target": self.raw_target,
                "preflight": self.integration_preflight,
            }

        # Step 1: AI Preflight Gate (3-Tier Check: Host, Models, Live Inference)
        if not await self.stage_ai_preflight():
            return {
                "status": "aborted",
                "reason": "ai_preflight_failed",
                "target": self.raw_target,
                "error": self.ai_preflight_result.error_message if self.ai_preflight_result else "AI server offline",
                "preflight": self.ai_preflight_result.to_dict() if self.ai_preflight_result else {},
            }

        # Step 1.5: Environment Readiness Gate (Phase 1 — local probes only)
        if not await self.stage_env_readiness():
            return {
                "status": "aborted",
                "reason": "environment_not_ready",
                "target": self.raw_target,
                "readiness": self.readiness_report,
            }

        # Step 2: Recon & Subdomains
        await self.stage_recon()

        # Step 2: Live Assets
        await self.stage_live_probing()

        # Step 3: Attack Surface & JS
        await self.stage_attack_surface()

        # Step 4: Testing & Verification
        await self.stage_testing_and_verification()

        duration = round(time.time() - t0, 2)

        # Finalize engagement manager with manifest, timeline, lineage graph
        finalize_summary = self.engagement_mgr.finalize(
            findings_count=len(self.findings),
            live_assets_count=len(self.live_assets),
            endpoints_count=len(self.endpoints)
        )

        desktop_export = getattr(self, "last_reports", {}).get("desktop_export")
        coverage_summary = self.coverage_ledger.get_summary()
        self._save_stage_artifact("13_evidence", "coverage_ledger.json", coverage_summary)
        return {
            "status": "completed",
            "target": self.raw_target,
            "domain": self.domain,
            "session_id": self.session_id,
            "duration": duration,
            "subdomains_count": len(self.subdomains),
            "live_assets_count": len(self.live_assets),
            "endpoints_count": len(self.endpoints),
            "parameters_count": len(self.parameters),
            "findings_count": len(self.findings),
            "findings": [f.model_dump() for f in self.findings],
            "artifact_directory": self.artifact_root,
            "engagement_directory": str(self.engagement_mgr.run_dir),
            "manifest_file": str(self.engagement_mgr.manifest_file),
            "timeline_file": str(self.engagement_mgr.timeline_file),
            "lineage_file": str(self.engagement_mgr.lineage_file),
            "desktop_directory": desktop_export,
            "reports": getattr(self, "last_reports", {}),
            "tool_logs": self.tool_logs,
            "coverage_summary": coverage_summary,
            "tool_failures": self.tool_failures,
        }
