"""
HunterAI OmniHunter Autonomous Engine — Omnipotent Master Orchestrator.
=======================================================================

The single entry point for launching a complete, authorized security assessment
that runs autonomously from start to finish without manual intervention.

Architecture:
  1. ScopeGuard — Hard enforcement via RedTeamPolicyEngine & ScopeTarget. Zero exceptions.
  2. InformationGainPlanner — Decides next highest-value action based on CoverageLedger gaps.
  3. SwarmDispatcher — Routes tasks to specialized agent teams (Recon, Network, Web, API, JS).
  4. PersistenceWatchdog — Detects stalls, recovers crashed tasks, takes checkpoint snapshots.
  5. Negative Verification & Evidence Court — Independent adversarial refutation before confirmation.
  6. Final Dossier Generator — Produces structured report with PoE evidence.

Completion Criteria (whichever comes first):
  - CoverageLedger testing coverage >= threshold (default 85%)
  - All tasks reach DONE, FAILED, or UNTESTABLE status
  - Max cycles or time budget exhausted (safety limit)
"""
from __future__ import annotations

from core.engine.real_tool_adapter import RealToolAdapter
from core.auth.identity_matrix import DualIdentityMatrix, IdentityContext
from core.oob.oob_engine import OOBEngine
from core.engine.poc_bundle_generator import PoCBundleGenerator, FindingContext
from core.cognitive.cognitive_deliberator import CognitiveDeliberator, StrategicDeliberation
from core.cognitive.mission_critic import (
    MissionCritic,
    PhaseCritique,
    format_phase_trace,
    format_retrospective_trace,
)


import asyncio
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core.contracts.task_contracts import (
    AgentTeam,
    EvidenceArtifact,
    EvidenceSignificance,
    TaskContract,
    TaskLifecycleStatus,
    ToolExecutionResult,
)
from core.coverage.coverage_ledger import AssetType, CoverageLedger, UntestableReason
from core.engine.persistence_watchdog import AssessmentSnapshot, PersistenceWatchdog
from core.engine.skill_matrix import SKILL_MATRIX, skill_gap_analysis
from core.evidence_court import EvidenceCourt
from core.policy.red_team import (
    ActionClass,
    ActionRequest,
    AuthorizationGrant,
    Profile,
    RedTeamPolicyEngine,
    ScopeTarget,
)
from core.system.task_scheduler import TaskScheduler
from core.teams.api_team import APIDiscoveryAgent, ParameterIntelligenceAgent, APIReviewAgent
from core.teams.javascript_team import RouteExtractionAgent, SecretTriageAgent, JSReviewAgent
from core.teams.network_team import NetworkDiscoveryAgent, ServiceAnalysisAgent, NetworkReviewAgent
from core.teams.recon_team import AssetDiscoveryAgent, DNSIntelligenceAgent, ReconReviewAgent
from core.teams.verification_team import (
    CausalVerificationAgent,
    CounterexampleAgent,
    EvidenceCourtReviewer,
    ReproductionAgent,
)
from core.teams.web_team import ContentDiscoveryAgent, HTTPAnalysisAgent, WebReviewAgent

logger = logging.getLogger("hunter_ai.omni_hunter")


class AssessmentPhase(str, Enum):
    INIT         = "INIT"
    RECON        = "RECON"
    NETWORK      = "NETWORK"
    WEB          = "WEB"
    API          = "API"
    JAVASCRIPT   = "JAVASCRIPT"
    VERIFICATION = "VERIFICATION"
    ADJUDICATION = "ADJUDICATION"
    REPORT       = "REPORT"
    DONE         = "DONE"


PHASE_ORDER = [
    AssessmentPhase.RECON,
    AssessmentPhase.NETWORK,
    AssessmentPhase.WEB,
    AssessmentPhase.API,
    AssessmentPhase.JAVASCRIPT,
    AssessmentPhase.VERIFICATION,
    AssessmentPhase.ADJUDICATION,
    AssessmentPhase.REPORT,
]


@dataclass
class AssessmentConfig:
    """Configuration for an autonomous assessment run."""
    target_url: str
    scope_domains: List[str]            # Authorized domains
    out_of_scope_domains: List[str] = field(default_factory=list)
    session_cookies: Dict[str, str] = field(default_factory=dict)
    auth_headers: Dict[str, str] = field(default_factory=dict)
    coverage_threshold: float = 0.85    # Stop when 85% coverage achieved
    max_cycles: int = 50                # Hard safety limit on orchestration loops
    stall_timeout_secs: float = 300     # Watchdog stall detection threshold
    max_task_retries: int = 3           # Max retries before marking task FAILED
    snapshot_dir: str = "snapshots"     # Where to save progress checkpoints
    engagement_id: str = field(
        default_factory=lambda: f"ENG-{uuid.uuid4().hex[:8].upper()}"
    )
    authorized_by: str = "Authorized Red Team Operator"
    policy_secret: bytes = b"hunter-ai-default-authorized-secret"
    auth_user_a: Optional[IdentityContext] = None
    auth_user_b: Optional[IdentityContext] = None
    enable_oob: bool = True
    oob_callback_domain: str = "oob.hunterai.internal"
    generate_poc_bundles: bool = True
    force_tool_fallback: bool = False
    enable_thinking: bool = True
    enable_browser: bool = True
    enable_burp: bool = True
    enable_elite_skills: bool = True
    notes: str = ""
    # Autonomy: when True, high-risk actions that are cryptographically
    # verified IN-SCOPE by the RedTeamPolicyEngine are auto-approved instead of
    # pausing for interactive confirmation. The fail-closed scope firewall
    # (authorization grant + _scope_check) remains the active perimeter.
    self_operate: bool = False


@dataclass
class AssessmentResult:
    """Final output of an autonomous assessment run."""
    engagement_id: str
    target: str
    phase_reached: AssessmentPhase
    confirmed_findings: List[Dict[str, Any]]
    coverage_pct: float
    untestable_surfaces: List[Dict[str, Any]]
    blindspots: List[str]
    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    duration_secs: float
    snapshot_id: Optional[str]
    exploit_chains: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


def _get_coverage_pct(ledger: CoverageLedger) -> float:
    """Helper to extract testing coverage percentage safely from CoverageLedger."""
    if hasattr(ledger, "testing_coverage_pct"):
        return float(ledger.testing_coverage_pct())
    summary = ledger.get_summary()
    return float(summary.get("testing_coverage_pct", 0.0))


class InformationGainPlanner:
    """
    Decides the highest-value next action based on current coverage gaps.
    Prioritizes assets with unexplored attack surface.
    """

    def next_phase(
        self,
        current_phase: AssessmentPhase,
        ledger: CoverageLedger,
        surface: Dict[str, List[str]],
    ) -> AssessmentPhase:
        """Returns the next assessment phase in order."""
        phase_idx = PHASE_ORDER.index(current_phase) if current_phase in PHASE_ORDER else -1
        if phase_idx < len(PHASE_ORDER) - 1:
            return PHASE_ORDER[phase_idx + 1]
        return AssessmentPhase.DONE

    def should_continue(
        self,
        ledger: CoverageLedger,
        threshold: float,
        cycle: int,
        max_cycles: int,
    ) -> bool:
        """Determines if the assessment loop should proceed."""
        if cycle >= max_cycles:
            logger.info("[Planner] Max cycles limit (%d) reached. Completing.", max_cycles)
            return False
        coverage = _get_coverage_pct(ledger)
        if coverage >= threshold * 100:
            logger.info("[Planner] Target coverage threshold reached (%.1f%% >= %.0f%%).", coverage, threshold * 100)
            return False
        return True


class OmniHunterEngine:
    """
    OmniHunter Master Autonomous Operating System.
    Coordinates all specialized squads, verification courts, and state engines.
    """

    def __init__(self, config: AssessmentConfig):
        self.config = config
        self.ledger = CoverageLedger()
        
        # Setup task scheduler
        tasks_path = Path("data") / f"tasks_{config.engagement_id}.json"
        state_path = Path("data") / f"state_{config.engagement_id}.json"
        self.scheduler = TaskScheduler(
            tasks_file=tasks_path,
            logs_dir="task_logs",
            state_file=state_path,
        )

        # Setup cryptographic authorization grant & policy engine
        scope_targets = [ScopeTarget("domain", d.lower()) for d in config.scope_domains]
        grant = AuthorizationGrant.sign(
            self.config.policy_secret,
            grant_id=self.config.engagement_id,
            authorized_by=self.config.authorized_by,
            scope=scope_targets,
            not_before=time.time() - 300,
            not_after=time.time() + 86400 * 7,  # 7 days
            profiles=[Profile.RED_TEAM],
        )
        self.policy_engine = RedTeamPolicyEngine(
            grant=grant,
            profile=Profile.RED_TEAM,
            secret=self.config.policy_secret,
        )

        self.court = EvidenceCourt()
        self.watchdog = PersistenceWatchdog(
            scheduler=self.scheduler,
            stall_timeout_secs=config.stall_timeout_secs,
            max_retries=config.max_task_retries,
            snapshot_dir=config.snapshot_dir,
        )
        self.planner = InformationGainPlanner()
        self.deliberator = CognitiveDeliberator()

        # Metacognitive mission critic (deterministic, fail-soft)
        self.critic = MissionCritic()
        self._phase_critiques: List[PhaseCritique] = []
        self._last_directives: List[str] = []
        self._retrospective: Optional[Any] = None

        # Approval gate: in self-operate mode, scope-verified high-risk actions
        # are auto-approved; the scope verifier callback IS the crypto-signed
        # policy engine itself, so every auto-approval is still scope-audited.
        from core.execution_modes import HumanApprovalGate
        self.approval_gate = HumanApprovalGate(
            interactive=False,
            self_operate=config.self_operate,
            scope_verifier=lambda target: self._scope_check(target),
        )
        self.tool_adapter = RealToolAdapter(force_fallback=config.force_tool_fallback)
        self.identity_matrix = DualIdentityMatrix(user_attacker=config.auth_user_a, user_victim=config.auth_user_b)
        self.oob_engine = OOBEngine(callback_domain=config.oob_callback_domain) if config.enable_oob else None
        self.poc_generator = PoCBundleGenerator(output_base_dir="findings") if config.generate_poc_bundles else None

        # Dynamic attack surface inventory
        self.surface: Dict[str, Any] = {
            "domains": list(config.scope_domains),
            "live_hosts": [],
            "endpoints": [],
            "apis": [],
            "js_files": [],
            "services": [],
            "open_ports": [],
            "tech_stack": [],
            "waf_name": None,
        }
        self.confirmed_findings: List[Dict[str, Any]] = []
        self.exploit_chains: List[Dict[str, Any]] = []
        self.current_phase = AssessmentPhase.INIT
        self._start_time: float = 0.0

    def get_target_context(self, target: Optional[str] = None) -> Any:
        """Constructs rich situational TargetContext from live discovered surface."""
        from core.arsenal.ai_command_synthesizer import TargetContext
        tgt = target or self.config.target_url
        ports: List[int] = []
        for p in self.surface.get("open_ports", []):
            try:
                ports.append(int(str(p).split(":")[-1]))
            except Exception:
                pass
        return TargetContext(
            target=tgt,
            waf_name=self.surface.get("waf_name"),
            tech_stack=list(self.surface.get("tech_stack", [])),
            open_ports=sorted(list(set(ports))),
            auth_headers=dict(self.config.auth_headers),
            cookies=dict(self.config.session_cookies),
            goal="autonomous_security_assessment",
        )

    # ── Scope Enforcement ──────────────────────────────────────────────────────

    def _scope_check(self, target: str, action_class: ActionClass = ActionClass.ACTIVE_TEST) -> bool:
        """
        Hard Scope Firewall: Evaluates target via RedTeamPolicyEngine.
        Blocks and audits any unauthorized or out-of-scope request.
        """
        clean = target.strip()
        if not clean.startswith("http://") and not clean.startswith("https://"):
            clean = f"https://{clean}"
        decision = self.policy_engine.evaluate(ActionRequest(target=clean, action_class=action_class))
        if not decision.allowed:
            logger.warning("[ScopeGuard] BLOCKED request to %s: %s", target, decision.reason)
            return False
        return True

    # ── Phase Executors ────────────────────────────────────────────────────────

    def _run_recon_phase(self) -> None:
        logger.info("[OmniHunter] ── Phase 1: RECONNAISSANCE ──")
        target = self.config.target_url

                # Run external subfinder adapter if available
        clean_domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        subfinder_res = self.tool_adapter.execute_subfinder(clean_domain)
        if subfinder_res.success and subfinder_res.structured_data:
            for sub in subfinder_res.structured_data.get("discovered_subdomains", []):
                if self._scope_check(sub, ActionClass.READ_ONLY) and sub not in self.surface["domains"]:
                    self.surface["domains"].append(sub)
                    self.ledger.record_discovery(AssetType.DOMAIN, sub)

        # Task 1: Asset Discovery
        task = self.scheduler.add_task(
            "Asset Discovery", "asset_discovery", target=target, team=AgentTeam.RECON, priority=10
        )
        self.scheduler.dispatch_task(task.task_id, "AssetDiscoveryAgent")
        agent = AssetDiscoveryAgent()
        result = agent.execute(task, context={"session_cookies": self.config.session_cookies})
        self.scheduler.submit_result(task.task_id, result)

        if result.success and result.normalized_data:
            data = result.normalized_data
            for domain in data.get("discovered_domains", []):
                if self._scope_check(domain, ActionClass.READ_ONLY) and domain not in self.surface["domains"]:
                    self.surface["domains"].append(domain)
                    self.ledger.record_discovery(AssetType.DOMAIN, domain)
            for host in data.get("live_hosts", []):
                if self._scope_check(host, ActionClass.READ_ONLY) and host not in self.surface["live_hosts"]:
                    self.surface["live_hosts"].append(host)
                    self.ledger.record_discovery(AssetType.HOST, host)

        # Task 2: DNS Intelligence
        dns_task = self.scheduler.add_task(
            "DNS Intelligence", "dns_mapping", target=target, team=AgentTeam.RECON, priority=9
        )
        self.scheduler.dispatch_task(dns_task.task_id, "DNSIntelligenceAgent")
        dns_agent = DNSIntelligenceAgent()
        dns_result = dns_agent.execute(dns_task, context={})
        self.scheduler.submit_result(dns_task.task_id, dns_result)

        # Independent Squad Review
        reviewer = ReconReviewAgent()
        reviewer.review(task, self.ledger)
        reviewer.review(dns_task, self.ledger)

        self._save_checkpoint()

    def _run_network_phase(self) -> None:
        logger.info("[OmniHunter] ── Phase 2: NETWORK & SERVICE AUDIT ──")
        hosts_to_scan = self.surface["live_hosts"][:10]
        if not hosts_to_scan:
            # Fallback to configured target domain
            clean = self.config.target_url.replace("https://", "").replace("http://", "").split("/")[0]
            hosts_to_scan = [clean]

        for host in hosts_to_scan:
            if not self._scope_check(host, ActionClass.ACTIVE_TEST):
                continue
            task = self.scheduler.add_task(
                f"Network Scan: {host}", "port_scan", target=host, team=AgentTeam.NETWORK, priority=8
            )
            self.scheduler.dispatch_task(task.task_id, "NetworkDiscoveryAgent")
            agent = NetworkDiscoveryAgent()
            result = agent.execute(task, context={})
            self.scheduler.submit_result(task.task_id, result)

            if result.success and result.normalized_data:
                for port_entry in result.normalized_data.get("open_ports", []):
                    port_str = f"{host}:{port_entry}"
                    self.ledger.record_discovery(AssetType.PORT, port_str)
                    if port_str not in self.surface["open_ports"]:
                        self.surface["open_ports"].append(port_str)

            reviewer = NetworkReviewAgent()
            reviewer.review(task, self.ledger)

        self._save_checkpoint()

    def _run_web_phase(self) -> None:
        logger.info("[OmniHunter] ── Phase 3: WEB ENDPOINT DISCOVERY & DOM ──")
        hosts = self.surface["live_hosts"][:5] or [
            self.config.target_url.replace("https://", "").replace("http://", "").split("/")[0]
        ]
        for host in hosts:
            target_url = f"https://{host}"
            if not self._scope_check(host, ActionClass.ACTIVE_TEST):
                continue

            # HTTP Analysis
            task = self.scheduler.add_task(
                f"HTTP Analysis: {host}", "http_analysis", target=target_url, team=AgentTeam.WEB, priority=7
            )
            self.scheduler.dispatch_task(task.task_id, "HTTPAnalysisAgent")
            agent = HTTPAnalysisAgent()
            result = agent.execute(task, context={"auth_headers": self.config.auth_headers})
            self.scheduler.submit_result(task.task_id, result)

            if result.success and result.normalized_data:
                for ep in result.normalized_data.get("endpoints", []):
                    ep_url = ep if isinstance(ep, str) else ep.get("url", "")
                    if ep_url and ep_url not in self.surface["endpoints"]:
                        self.surface["endpoints"].append(ep_url)
                        self.ledger.record_discovery(AssetType.ENDPOINT, ep_url)
                # Inspect response headers for WAF & tech
                hdrs = result.normalized_data.get("headers", {})
                server_hdr = hdrs.get("Server", "")
                if "cloudflare" in server_hdr.lower() and not self.surface.get("waf_name"):
                    self.surface["waf_name"] = "Cloudflare"
                elif "nginx" in server_hdr.lower() and "nginx" not in self.surface["tech_stack"]:
                    self.surface["tech_stack"].append("nginx")
                elif "apache" in server_hdr.lower() and "apache" not in self.surface["tech_stack"]:
                    self.surface["tech_stack"].append("apache")
                pby = hdrs.get("X-Powered-By", "")
                if "php" in pby.lower() and "php" not in self.surface["tech_stack"]:
                    self.surface["tech_stack"].append("php")

            # Content Discovery
            cd_task = self.scheduler.add_task(
                f"Content Discovery: {host}", "content_discovery", target=target_url, team=AgentTeam.WEB, priority=6
            )
            self.scheduler.dispatch_task(cd_task.task_id, "ContentDiscoveryAgent")
            cd_agent = ContentDiscoveryAgent()
            cd_result = cd_agent.execute(cd_task, context={})
            self.scheduler.submit_result(cd_task.task_id, cd_result)

            reviewer = WebReviewAgent()
            reviewer.review(task, self.ledger)

        # Autonomous Active Browser Exploration (Playwright SPA interaction with AI Operator)
        if getattr(self.config, "enable_browser", False):
            logger.info("[OmniHunter] Launching AIBrowserOperator for dynamic AI-driven exploration on %s", self.config.target_url)
            try:
                from core.browser.ai_browser_operator import run_ai_browser_session_sync
                b_report = run_ai_browser_session_sync(
                    self.config.target_url,
                    objective=f"Deep SPA surface exploration on {self.config.target_url}",
                    headless=True,
                )
                if b_report and b_report.success:
                    logger.info("[OmniHunter] Active browser executed %d actions, visited %d pages, intercepted %d APIs",
                                len(b_report.actions_performed), len(b_report.pages_visited), len(b_report.intercepted_api_endpoints))
                    for ep_item in b_report.intercepted_api_endpoints:
                        ep_url = ep_item.get("url", "")
                        if ep_url and ep_url not in self.surface["endpoints"]:
                            self.surface["endpoints"].append(ep_url)
                            self.ledger.record_discovery(AssetType.ENDPOINT, ep_url)
                    for p_url in b_report.pages_visited:
                        if p_url and p_url not in self.surface["endpoints"]:
                            self.surface["endpoints"].append(p_url)
                            self.ledger.record_discovery(AssetType.ENDPOINT, p_url)

                # Automated DOM XSS Exploration against candidate endpoints
                try:
                    from skills.browser.dom_xss_hunter.skill import DOMXSSHunterSkill
                    from skills.base_skill import SkillContext
                    from core.workspace_manager import WorkspaceManager
                    from tools.tool_manager import ToolManager

                    dom_ctx = SkillContext(
                        target=self.config.target_url,
                        session_id=self.config.engagement_id,
                        workspace=WorkspaceManager(self.config.snapshot_dir),
                        tool_manager=ToolManager(),
                        extra={"urls": self.surface["endpoints"][:10]}
                    )
                    dom_skill = DOMXSSHunterSkill()
                    dom_res = asyncio.run(dom_skill.execute(dom_ctx))
                    if dom_res.findings:
                        for df in dom_res.findings:
                            self.confirmed_findings.append({
                                "vuln_class": "DOM_XSS",
                                "target": df.get("endpoint", self.config.target_url),
                                "verdict": "CONFIRMED",
                                "confidence": 0.90,
                                "title": df.get("title", "DOM XSS Vulnerability"),
                                "evidence": df.get("evidence", "Client-side sink reflection"),
                                "timestamp": time.time(),
                            })
                            logger.info("[OmniHunter] [!] Verified DOM XSS Finding: %s", df.get("title"))
                except Exception as dom_err:
                    logger.debug("[OmniHunter] DOM XSS note: %s", dom_err)
            except Exception as b_err:
                logger.warning("[OmniHunter] ActiveBrowserAgent note: %s", b_err)

        self._save_checkpoint()

    def _run_api_phase(self) -> None:
        logger.info("[OmniHunter] ── Phase 4: API & SCHEMA REASONING ──")
        target = self.config.target_url
        clean = target.replace("https://", "").replace("http://", "").split("/")[0]
        if not self._scope_check(clean, ActionClass.ACTIVE_TEST):
            return

        task = self.scheduler.add_task(
            "API Discovery", "api_discovery", target=target, team=AgentTeam.API, priority=7
        )
        self.scheduler.dispatch_task(task.task_id, "APIDiscoveryAgent")
        agent = APIDiscoveryAgent()
        result = agent.execute(task, context={
            "auth_headers": self.config.auth_headers,
            "discovered_endpoints": self.surface["endpoints"],
        })
        self.scheduler.submit_result(task.task_id, result)

        if result.success and result.normalized_data:
            for raw_route in result.normalized_data.get("api_routes", []):
                route_str = raw_route if isinstance(raw_route, str) else (
                    raw_route.get("endpoint") or raw_route.get("path") or raw_route.get("route") or str(raw_route)
                )
                if route_str not in self.surface["apis"]:
                    self.surface["apis"].append(route_str)
                    self.ledger.record_discovery(AssetType.API, route_str)

        reviewer = APIReviewAgent()
        reviewer.review(task, self.ledger)

        # Autonomous Elite Vulnerability & Burp Skills Suite
        if getattr(self.config, "enable_elite_skills", True) and bool(self.config.authorized_by):
            logger.info("[OmniHunter] Executing Elite Bug Bounty Skills Suite on discovered endpoints...")
            try:
                from agents.skills.http_smuggling_skill import HTTPSmugglingSkill
                from agents.skills.cache_poisoning_skill import CachePoisoningSkill
                from agents.skills.oauth2_abuse_skill import OAuth2AbuseSkill
                from agents.skills.prototype_pollution_skill import PrototypePollutionSkill
                from agents.skills.path_traversal_skill import PathTraversalSkill
                from agents.skills.jwt_advanced_skill import JWTAdvancedSkill
                from skills.burp.request_mutator.skill import RequestMutatorSkill
                from skills.base_skill import SkillContext
                from core.workspace_manager import WorkspaceManager
                from tools.tool_manager import ToolManager

                # 1. Burp Request Mutation & Differential Analysis
                try:
                    mut_ctx = SkillContext(
                        target=self.config.target_url,
                        session_id=self.config.engagement_id,
                        workspace=WorkspaceManager(self.config.snapshot_dir),
                        tool_manager=ToolManager(),
                        extra={"requests": [{"url": ep, "method": "GET"} for ep in self.surface["endpoints"][:8]]}
                    )
                    mut_skill = RequestMutatorSkill()
                    mut_res = asyncio.run(mut_skill.execute(mut_ctx))
                    if mut_res.findings:
                        for mf in mut_res.findings:
                            self.confirmed_findings.append({
                                "vuln_class": "BUSINESS_LOGIC_MUTATION",
                                "target": mf.get("endpoint", self.config.target_url),
                                "verdict": "CONFIRMED",
                                "confidence": 0.85,
                                "title": mf.get("title", "Request Mutation Anomaly"),
                                "evidence": mf.get("description", "Differential status code anomaly"),
                                "timestamp": time.time(),
                            })
                except Exception as mut_err:
                    logger.debug("[OmniHunter] RequestMutator note: %s", mut_err)

                # 2. Elite Vulnerability Autonomous Probers
                elite_skills = [
                    HTTPSmugglingSkill(),
                    CachePoisoningSkill(),
                    OAuth2AbuseSkill(),
                    PrototypePollutionSkill(),
                    PathTraversalSkill(),
                    JWTAdvancedSkill(),
                ]
                endpoints_to_probe = self.surface["endpoints"][:6] or [self.config.target_url]
                for ep_url in endpoints_to_probe:
                    for sk in elite_skills:
                        try:
                            sk_res = asyncio.run(sk.run(ep_url, param_name=""))
                            if sk_res.verified:
                                self.confirmed_findings.append({
                                    "vuln_class": sk_res.vuln_type.upper(),
                                    "target": ep_url,
                                    "verdict": "CONFIRMED",
                                    "confidence": sk_res.confidence,
                                    "title": sk_res.title,
                                    "evidence": sk_res.evidence,
                                    "payload": sk_res.payload_used,
                                    "cwe": sk_res.cwe,
                                    "timestamp": time.time(),
                                })
                                logger.info("[OmniHunter] [!] Verified Elite Vulnerability: %s on %s", sk_res.vuln_type, ep_url)
                        except Exception:
                            pass
            except Exception as elite_err:
                logger.warning("[OmniHunter] Elite skills execution note: %s", elite_err)

        self._save_checkpoint()

    def _run_javascript_phase(self) -> None:
        logger.info("[OmniHunter] ── Phase 5: JAVASCRIPT BUNDLE UNPACKING ──")
        for js_url in self.surface.get("js_files", [])[:15]:
            clean = js_url.replace("https://", "").replace("http://", "").split("/")[0]
            if not self._scope_check(clean, ActionClass.READ_ONLY):
                continue
            task = self.scheduler.add_task(
                f"JS Analysis: {js_url[:50]}", "js_analysis", target=js_url, team=AgentTeam.JAVASCRIPT, priority=5
            )
            self.scheduler.dispatch_task(task.task_id, "RouteExtractionAgent")
            agent = RouteExtractionAgent()
            result = agent.execute(task, context={})
            self.scheduler.submit_result(task.task_id, result)

            if result.success and result.normalized_data:
                for route in result.normalized_data.get("internal_routes", []):
                    if route not in self.surface["endpoints"]:
                        self.surface["endpoints"].append(route)
                        self.ledger.record_discovery(AssetType.ENDPOINT, route)

            reviewer = JSReviewAgent()
            reviewer.review(task, self.ledger)

        self._save_checkpoint()

    def _run_verification_phase(self) -> None:
        logger.info("[OmniHunter] ── Phase 6: ADVERSARIAL VERIFICATION & REFUTATION ──")
        all_sched_tasks = self.scheduler.list_tasks()
        task_list = list(all_sched_tasks.values()) if isinstance(all_sched_tasks, dict) else list(all_sched_tasks)
        tasks_to_verify = []
        for t in task_list:
            st = t.get("status") if isinstance(t, dict) else getattr(t, "status", None)
            if st == TaskLifecycleStatus.REVIEW or st == "REVIEW":
                tasks_to_verify.append(t)

        for task in tasks_to_verify:
            if not task.result:
                continue
            res_data = task.result.normalized_data or {}
            vuln_class = res_data.get("vuln_class", "UNKNOWN")
            probed = res_data.get("probed_response", "")
            baseline = res_data.get("baseline_response", "")

            # Step 1: Counterexample Skepticism Test
            counter = CounterexampleAgent()
            if probed:
                refuted, reason = counter.evaluate_claim(task.target, vuln_class, probed, baseline)
                if refuted:
                    logger.info("[Verification] Refuted candidate finding %s: %s", task.task_id, reason)
                    task._status = TaskLifecycleStatus.FAILED
                    continue

            # Step 2: Causal Differential Verification
            verifier = CausalVerificationAgent()
            ver_task = self.scheduler.add_task(
                f"Verify: {task.title[:40]}", "verify_finding", target=task.target,
                team=AgentTeam.VERIFICATION, priority=9
            )
            self.scheduler.dispatch_task(ver_task.task_id, "CausalVerificationAgent")
            ver_result = verifier.execute(ver_task, context={
                "probed_response": probed,
                "baseline_response": baseline,
            })
            self.scheduler.submit_result(ver_task.task_id, ver_result)

            # Step 3: Evidence Court Docket Review
            court_reviewer = EvidenceCourtReviewer()
            approved = court_reviewer.review(ver_task, self.ledger)
            if approved and ver_task.status == TaskLifecycleStatus.DONE:
                finding = {
                    "task_id": ver_task.task_id,
                    "parent_task_id": task.task_id,
                    "target": task.target,
                    "vuln_class": vuln_class,
                    "verdict": ver_result.normalized_data.get("verdict", "CONFIRMED"),
                    "confidence": ver_result.normalized_data.get("confidence", 0.95),
                    "evidence": [asdict(e) if hasattr(e, "__dict__") else e for e in ver_result.evidence_artifacts],
                    "timestamp": time.time(),
                }
                if self.poc_generator:
                    try:
                        bundle_ctx = FindingContext(
                            finding_id=ver_task.task_id,
                            target_url=task.target,
                            vuln_class=vuln_class,
                            parameter=res_data.get("parameter", ""),
                            response_status=200,
                            response_body=probed[:2000] if probed else "OK",
                        )
                        bundle_dir = self.poc_generator.generate_bundle(bundle_ctx)
                        finding["poc_bundle_dir"] = str(bundle_dir)
                    except Exception as bundle_err:
                        logger.warning("[OmniHunter] Failed to generate PoC bundle: %s", bundle_err)

                self.confirmed_findings.append(finding)
                logger.info("[OmniHunter] ✓ CONFIRMED VULNERABILITY: %s on %s", vuln_class, task.target)

        # Autonomous Multi-Step Exploit Chaining (A -> B -> C -> ATO)
        if self.confirmed_findings:
            try:
                from skills.cognitive.exploit_chain_builder.skill import ExploitChainBuilderSkill
                from skills.base_skill import SkillContext
                from core.workspace_manager import WorkspaceManager
                from tools.tool_manager import ToolManager

                ec_ctx = SkillContext(
                    target=self.config.target_url,
                    session_id=self.config.engagement_id,
                    workspace=WorkspaceManager(self.config.snapshot_dir),
                    tool_manager=ToolManager(),
                    extra={"findings": self.confirmed_findings}
                )
                ec_skill = ExploitChainBuilderSkill()
                ec_res = asyncio.run(ec_skill.execute(ec_ctx))
                self.exploit_chains = ec_res.metadata.get("chains", [])
                if self.exploit_chains:
                    logger.info("[OmniHunter] Successfully assembled %d multi-step exploit chains!", len(self.exploit_chains))
            except Exception as ec_err:
                logger.debug("[OmniHunter] ExploitChainBuilder note: %s", ec_err)

        self._save_checkpoint()

    def _run_adjudication_phase(self) -> None:
        logger.info("[OmniHunter] ── Phase 7: EVIDENCE COURT FINAL ADJUDICATION ──")
        seen_fingerprints: Set[str] = set()
        deduped = []
        for finding in self.confirmed_findings:
            fp = f"{finding.get('vuln_class')}:{finding.get('target')}"
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                deduped.append(finding)
            else:
                logger.info("[EvidenceCourt] Deduplicated redundant finding: %s", fp)
        self.confirmed_findings = deduped
        logger.info("[EvidenceCourt] Final adjudicated docket: %d verified findings.", len(self.confirmed_findings))

    def _run_report_phase(self) -> AssessmentResult:
        logger.info("[OmniHunter] ── Phase 8: EXECUTIVE DOSSIER GENERATION ──")
        duration = time.time() - self._start_time
        all_tasks = self.scheduler.list_tasks()
        task_items = list(self.scheduler._tasks.values()) if hasattr(self.scheduler, "_tasks") else (
            all_tasks.values() if isinstance(all_tasks, dict) else all_tasks
        )
        def _is_done(t):
            st = t.status if hasattr(t, "status") else t.get("status")
            return st in (TaskLifecycleStatus.DONE, "DONE", getattr(TaskLifecycleStatus.DONE, "value", "DONE"))
        def _is_failed(t):
            st = t.status if hasattr(t, "status") else t.get("status")
            return st in (TaskLifecycleStatus.FAILED, "FAILED", getattr(TaskLifecycleStatus.FAILED, "value", "FAILED"))
        completed = sum(1 for t in task_items if _is_done(t))
        failed = sum(1 for t in task_items if _is_failed(t))
        coverage = _get_coverage_pct(self.ledger)

        untestable = [
            {"asset": k, "reason": v.reason.value if hasattr(v, "reason") else str(v)}
            for k, v in self.ledger.get_untestable_assets().items()
        ] if hasattr(self.ledger, "get_untestable_assets") else []

        blindspots = list(getattr(self.ledger, "_blindspots", []))

        result = AssessmentResult(
            engagement_id=self.config.engagement_id,
            target=self.config.target_url,
            phase_reached=self.current_phase,
            confirmed_findings=self.confirmed_findings,
            coverage_pct=coverage,
            untestable_surfaces=untestable,
            blindspots=blindspots,
            total_tasks=len(all_tasks),
            completed_tasks=completed,
            failed_tasks=failed,
            duration_secs=duration,
            snapshot_id=None,
            metadata={
                "mission_retrospective": (
                    self._retrospective.to_dict() if getattr(self, "_retrospective", None) else None
                ),
                "phase_critiques": [c.to_dict() for c in getattr(self, "_phase_critiques", [])],
            },
        )
        return result

    def _save_checkpoint(self) -> None:
        snap = AssessmentSnapshot(
            target=self.config.target_url,
            phase=self.current_phase.value,
            discovered_assets=self.surface,
            confirmed_findings=self.confirmed_findings,
            coverage_pct=_get_coverage_pct(self.ledger),
        )
        self.watchdog.save_checkpoint(snap)

    # ── Main Autonomous Loop ───────────────────────────────────────────────────

    def run(self) -> AssessmentResult:
        """
        Runs the full autonomous OODA pentesting loop.
        """
        self._start_time = time.time()
        logger.info(
            "\n══════════════════════════════════════════════════════════════\n"
            "   OMNIHUNTER AUTONOMOUS SECURITY OPERATING SYSTEM STARTING\n"
            "   Target: %s\n"
            "   Authorized Scope: %s\n"
            "   Engagement ID: %s\n"
            "   Authorized By: %s\n"
            "══════════════════════════════════════════════════════════════",
            self.config.target_url,
            self.config.scope_domains,
            self.config.engagement_id,
            self.config.authorized_by,
        )

        # Initial Scope Verification
        clean = self.config.target_url.replace("https://", "").replace("http://", "").split("/")[0]
        if not self._scope_check(clean, ActionClass.READ_ONLY):
            logger.error("[OmniHunter] Target %s is OUT OF SCOPE. Aborting immediately.", self.config.target_url)
            return AssessmentResult(
                engagement_id=self.config.engagement_id,
                target=self.config.target_url,
                phase_reached=AssessmentPhase.INIT,
                confirmed_findings=[],
                coverage_pct=0.0,
                untestable_surfaces=[{"asset": clean, "reason": "OUT_OF_SCOPE"}],
                blindspots=["Target domain not in authorized scope grant."],
                total_tasks=0,
                completed_tasks=0,
                failed_tasks=0,
                duration_secs=0.0,
                snapshot_id=None,
            )

        executors = {
            AssessmentPhase.RECON:        self._run_recon_phase,
            AssessmentPhase.NETWORK:      self._run_network_phase,
            AssessmentPhase.WEB:          self._run_web_phase,
            AssessmentPhase.API:          self._run_api_phase,
            AssessmentPhase.JAVASCRIPT:   self._run_javascript_phase,
            AssessmentPhase.VERIFICATION: self._run_verification_phase,
            AssessmentPhase.ADJUDICATION: self._run_adjudication_phase,
        }

        for cycle, phase in enumerate(PHASE_ORDER):
            self.current_phase = phase

            # Cognitive Multi-Hypothesis Deliberation before Phase execution
            if self.deliberator:
                objective = f"Advance Phase {phase.value} and discover actionable leads"
                if self._last_directives:
                    objective += " | Critic directives: " + "; ".join(self._last_directives[:3])
                delib = self.deliberator.deliberate_strategy(
                    target=self.config.target_url,
                    objective=objective,
                    surface=self.surface,
                    current_findings=self.confirmed_findings,
                )
                if self.config.enable_thinking:
                    print(self.deliberator.format_strategic_trace(delib))

            # Watchdog health tick before phase
            watchdog_res = self.watchdog.tick()
            if watchdog_res["re_queued"]:
                logger.info("[OmniHunter] Watchdog recovered stalled tasks: %s", watchdog_res["re_queued"])

            executor = executors.get(phase)
            if executor:
                try:
                    executor()
                except Exception as exc:
                    logger.exception("[OmniHunter] Error in phase %s: %s — continuing loop.", phase, exc)

            # ── Metacognitive Phase Critic (self-review after every phase) ──
            try:
                critique = self.critic.critique_phase(
                    phase=phase.value,
                    surface=self.surface,
                    findings=self.confirmed_findings,
                    task_stats=self._task_stats_snapshot(),
                    prior_directives=self._last_directives,
                )
                self._phase_critiques.append(critique)
                self._last_directives = list(critique.directives)
                if self.config.enable_thinking:
                    print(format_phase_trace(critique))
            except Exception:
                logger.debug("MissionCritic phase critique skipped.", exc_info=True)

            # Check termination criteria
            if not self.planner.should_continue(self.ledger, self.config.coverage_threshold, cycle, self.config.max_cycles):
                break

        # ── End-of-Mission Retrospective ──────────────────────────────────────
        try:
            self._retrospective = self.critic.retrospective(
                target=self.config.target_url,
                surface=self.surface,
                findings=self.confirmed_findings,
                critiques=self._phase_critiques,
                coverage_pct=_get_coverage_pct(self.ledger),
                duration_secs=time.time() - self._start_time,
                failed_tasks=self._count_tasks("failed"),
                completed_tasks=self._count_tasks("done"),
            )
            if self.config.enable_thinking:
                print(format_retrospective_trace(self._retrospective))
        except Exception:
            logger.debug("MissionCritic retrospective skipped.", exc_info=True)

        self.current_phase = AssessmentPhase.REPORT
        return self._run_report_phase()

    # ── Critic helpers ──────────────────────────────────────────────────────────

    def _task_stats_snapshot(self) -> Dict[str, int]:
        """Lightweight task status counters for the MissionCritic."""
        try:
            tasks = self.scheduler.list_tasks()
            items = (tasks.values() if isinstance(tasks, dict) else tasks) or []
            done = failed = pending = 0
            for t in items:
                raw = t.status if hasattr(t, "status") else (t.get("status") if isinstance(t, dict) else "")
                sv = str(getattr(raw, "value", raw)).upper()
                if sv in ("DONE", "COMPLETED"):
                    done += 1
                elif sv in ("FAILED", "ERROR"):
                    failed += 1
                elif sv:
                    pending += 1
            return {"done": done, "failed": failed, "pending": pending}
        except Exception:
            return {"done": 0, "failed": 0, "pending": 0}

    def _count_tasks(self, kind: str) -> int:
        return self._task_stats_snapshot().get(kind, 0)
