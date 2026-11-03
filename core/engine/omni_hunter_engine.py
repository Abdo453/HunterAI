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
    enable_thinking: bool = False
    notes: str = ""


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
        self.tool_adapter = RealToolAdapter(force_fallback=config.force_tool_fallback)
        self.identity_matrix = DualIdentityMatrix(user_attacker=config.auth_user_a, user_victim=config.auth_user_b)
        self.oob_engine = OOBEngine(callback_domain=config.oob_callback_domain) if config.enable_oob else None
        self.poc_generator = PoCBundleGenerator(output_base_dir="findings") if config.generate_poc_bundles else None

        # Dynamic attack surface inventory
        self.surface: Dict[str, List[str]] = {
            "domains": list(config.scope_domains),
            "live_hosts": [],
            "endpoints": [],
            "apis": [],
            "js_files": [],
            "services": [],
        }
        self.confirmed_findings: List[Dict[str, Any]] = []
        self.current_phase = AssessmentPhase.INIT
        self._start_time: float = 0.0

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
                    self.ledger.record_discovery(AssetType.PORT, f"{host}:{port_entry}")

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
        task_list = all_sched_tasks.values() if isinstance(all_sched_tasks, dict) else all_sched_tasks
        tasks_to_verify = [
            t for t in task_list
            if t.status == TaskLifecycleStatus.REVIEW
        ]

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
                delib = self.deliberator.deliberate_strategy(
                    target=self.config.target_url,
                    objective=f"Advance Phase {phase.value} and discover actionable leads",
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

            # Check termination criteria
            if not self.planner.should_continue(self.ledger, self.config.coverage_threshold, cycle, self.config.max_cycles):
                break

        self.current_phase = AssessmentPhase.REPORT
        return self._run_report_phase()
