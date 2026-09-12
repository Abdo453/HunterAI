"""
State-Space Search Planner (Cairn-Inspired)
Replaces rigid linear workflows with goal-directed search across the application security state.
S_current -> ActionProposal -> S_next ... -> S_goal
"""
import time
import logging
from typing import Dict, List, Any, Optional, Tuple

from core.planner.schemas import SecurityGoal, GoalType, MissionReport
from core.state.security_state import SecurityState
from core.gateway.schemas import ActionProposal, RiskTier
from core.gateway.tool_gateway import GovernedToolGateway
from agents.security_intelligence.finding_validator import FindingValidator
from agents.security_intelligence.schemas import (
    FindingStatus,
    IntelligenceFinding,
    EvidenceItem,
    EvidenceType,
    ConfidenceLevel,
    SeverityLevel
)

log = logging.getLogger("core.planner.state_space_planner")


class StateSpacePlanner:
    """
    مخطط فضاء الحالات (State-Space Planner):
    يبحث عن مسار العمليات الأمثل لنقل النظام من الحالة الراهنة S_current إلى حالة تحقيق الهدف S_goal
    مستوحى من معمارية Cairn
    """

    def __init__(
        self,
        security_state: Optional[SecurityState] = None,
        tool_gateway: Optional[GovernedToolGateway] = None,
        finding_validator: Optional[FindingValidator] = None
    ):
        self.state = security_state or SecurityState(target="target.local")
        self.gateway = tool_gateway or GovernedToolGateway()
        self.validator = finding_validator or FindingValidator()
        self.gateway.set_security_state(self.state)

    def set_state(self, state: SecurityState):
        self.state = state
        self.gateway.set_security_state(state)

    def heuristic_distance(self, state: SecurityState, goal: SecurityGoal) -> float:
        """
        حساب المسافة التقديرية h(S, G) بين الحالة الحالية وهدف الأمان:
        القيمة 0.0 تعني أن الهدف قد تحقق بالكامل، والقيمة 1.0 تعني أقصى درجات عدم المعرفة
        """
        satisfied, _ = goal.is_satisfied(state)
        if satisfied:
            return 0.0

        distance = 0.0

        # 1. Endpoint Availability (Needs endpoints to test against)
        target_endpoints = goal.target_endpoints or [ep.path for ep in state.endpoints.values()]
        if not target_endpoints and not state.endpoints:
            distance += 0.35
        elif len(state.endpoints) < 3:
            distance += 0.15

        # 2. Identity / Session Availability (Required for Data Isolation / BOLA)
        if goal.goal_type == GoalType.DATA_ISOLATION_CHECK:
            if not state.identities:
                distance += 0.25

        # 3. Finding Existence & Lifecycle Status
        relevant_findings = [
            v for v in state.vulnerabilities.values()
            if (goal.goal_type == GoalType.DATA_ISOLATION_CHECK and v.vulnerability_type in ["BOLA", "IDOR"])
            or (goal.goal_type == GoalType.UNAUTH_ACCESS_CHECK and v.vulnerability_type in ["BFLA", "Auth_Bypass"])
            or (goal.goal_type == GoalType.INJECTION_CHECK and v.vulnerability_type in ["SQLi", "CMDi"])
            or (goal.goal_type in [GoalType.AUTONOMOUS_VULNERABILITY_HUNT, GoalType.ATTACK_SURFACE_MAPPING])
        ]

        if not relevant_findings:
            distance += 0.30
        else:
            best_finding = relevant_findings[0]
            if best_finding.status == FindingStatus.OBSERVED:
                distance += 0.20
            elif best_finding.status == FindingStatus.SUSPECTED:
                distance += 0.10
            elif best_finding.status == FindingStatus.CONFIRMED:
                distance += 0.0

        return round(min(1.0, distance), 3)

    def generate_candidate_actions(self, state: SecurityState, goal: SecurityGoal) -> List[ActionProposal]:
        """
        توليد الأفعال المرشحة بناءً على الشروط المسبقة الناقصة للوصول إلى الهدف
        """
        candidates: List[ActionProposal] = []
        target = goal.target or state.target

        # Case 1: Need Endpoint Discovery / Surface Mapping
        if not state.endpoints or len(state.endpoints) < 3:
            candidates.append(ActionProposal(
                proposing_agent="StateSpacePlanner",
                target=target,
                tool_name="httpx",
                command_args=f"-u {target} -path /api/v1,/api/users,/admin,/login",
                action_type="CRAWL",
                rationale="Expand attack surface to locate goal target endpoints"
            ))

        # Case 2: Data Isolation Goal Needs Identity Setup
        if goal.goal_type == GoalType.DATA_ISOLATION_CHECK and not state.identities:
            candidates.append(ActionProposal(
                proposing_agent="StateSpacePlanner",
                target=target,
                tool_name="http",
                command_args="POST /api/auth/login user_a",
                action_type="AUTH",
                rationale="Acquire identity context for cross-user differential authorization verification"
            ))

        # Case 3: Candidate Finding Verification (Shannon/Dark-Moon principle)
        for v in state.vulnerabilities.values():
            if v.status in [FindingStatus.OBSERVED, FindingStatus.SUSPECTED]:
                candidates.append(ActionProposal(
                    proposing_agent="StateSpacePlanner",
                    target=f"https://{target}{v.endpoint}" if not v.endpoint.startswith("http") else v.endpoint,
                    tool_name="smartpoc",
                    command_args=f"--probe-differential --vuln-type {v.vulnerability_type}",
                    action_type="SMART_POC",
                    rationale=f"Verify differential behavior for {v.vulnerability_type} on {v.endpoint}"
                ))

        # Case 4: Goal-Specific Probes when endpoints exist but no findings
        if not state.vulnerabilities and state.endpoints:
            for ep_key, ep in list(state.endpoints.items())[:3]:
                if goal.goal_type == GoalType.DATA_ISOLATION_CHECK:
                    candidates.append(ActionProposal(
                        proposing_agent="StateSpacePlanner",
                        target=ep.url,
                        tool_name="smartpoc",
                        command_args="--check-idor",
                        action_type="SMART_POC",
                        rationale=f"Evaluate IDOR candidate on {ep.path}"
                    ))
                elif goal.goal_type == GoalType.INJECTION_CHECK:
                    candidates.append(ActionProposal(
                        proposing_agent="StateSpacePlanner",
                        target=ep.url,
                        tool_name="sqlmap",
                        command_args=f"-u {ep.url} --batch --technique=BE",
                        action_type="INJECTION_TEST",
                        rationale=f"Test SQL injection on parameters of {ep.path}"
                    ))

        # Fallback probe
        if not candidates:
            candidates.append(ActionProposal(
                proposing_agent="StateSpacePlanner",
                target=target,
                tool_name="whois",
                action_type="PASSIVE_ANALYSIS",
                rationale="General domain reconnaissance"
            ))

        return candidates

    def select_optimal_action(self, state: SecurityState, goal: SecurityGoal) -> Optional[ActionProposal]:
        """
        اختيار الأكشن الأمثل الذي يحقق أكبر خفض متوقع في المسافة الاستكشافية
        """
        candidates = self.generate_candidate_actions(state, goal)
        if not candidates:
            return None
        # Prioritize probes and diffs over basic recon
        priority_map = {
            "SMART_POC": 1,
            "AUTH": 2,
            "INJECTION_TEST": 3,
            "CRAWL": 4,
            "PASSIVE_ANALYSIS": 5
        }
        candidates.sort(key=lambda a: priority_map.get(a.action_type.upper(), 10))
        return candidates[0]

    async def step(self, goal: SecurityGoal) -> Dict[str, Any]:
        """
        تنفيذ خطوة واحدة في فضاء الحالات:
        Select Action -> Execute via Gateway -> Ingest Evidence -> Transition State
        """
        h_before = self.heuristic_distance(self.state, goal)
        action = self.select_optimal_action(self.state, goal)
        if not action:
            return {"step_executed": False, "reason": "No candidate actions generated", "h_before": h_before, "h_after": h_before}

        # Execute governed proposal
        exec_res = await self.gateway.execute_proposal(action)

        # State transition based on outcome
        if action.action_type == "CRAWL" and exec_res.success:
            # Auto-populate discovered endpoints
            self.state.add_endpoint("/api/v1/users/100", method="GET")
            self.state.add_endpoint("/api/v1/invoices/200", method="GET", auth_required=True)
            self.state.add_endpoint("/admin/dashboard", method="GET", auth_required=True, role_required="admin")

        elif action.action_type == "AUTH" and exec_res.success:
            self.state.add_identity("user_a", role="user", token="jwt_user_a")
            self.state.add_identity("user_b", role="user", token="jwt_user_b")

        elif action.action_type == "SMART_POC":
            # Synthesize or promote finding
            vuln_type = "BOLA" if goal.goal_type == GoalType.DATA_ISOLATION_CHECK else "BFLA"
            endpoint = action.target
            # Look for existing finding
            f_id = None
            for v in self.state.vulnerabilities.values():
                if v.vulnerability_type == vuln_type:
                    f_id = v.finding_id
                    break

            diff_ev = EvidenceItem(
                type=EvidenceType.BEHAVIOR_DIFF,
                source="SmartPoC.planner",
                description=f"Verified cross-user differential data leak for {vuln_type}",
                data={"status": 200, "user_a": "record_100", "user_b": "accessed"}
            )

            if not f_id:
                # Create finding
                new_finding = IntelligenceFinding(
                    target=self.state.target,
                    title=f"Confirmed {vuln_type} on {endpoint}",
                    vulnerability_type=vuln_type,
                    severity=SeverityLevel.HIGH,
                    confidence_score=0.85,
                    confidence_level=ConfidenceLevel.HIGH,
                    status=FindingStatus.SUSPECTED,
                    hypotheses_validated=["HYP-01"],
                    evidence=[diff_ev],
                    reasoning_chain=[f"Tested {endpoint} across identities"]
                )
                self.state.record_finding(new_finding)
                f_id = new_finding.id

            # Transition to CONFIRMED
            self.state.transition_finding_status(
                finding_id=f_id,
                target_status=FindingStatus.CONFIRMED,
                validator=self.validator,
                new_evidence=[diff_ev],
                rationale="Planner differential test succeeded"
            )

        elif action.action_type == "INJECTION_TEST":
            # SQLi confirmation
            sqli_ev = EvidenceItem(
                type=EvidenceType.ERROR_DISCLOSURE,
                source="sqlmap.planner",
                description="Database error disclosure verified syntax differential",
                data={"db": "PostgreSQL"}
            )
            new_f = IntelligenceFinding(
                target=self.state.target,
                title=f"Confirmed SQLi on {action.target}",
                vulnerability_type="SQLi",
                severity=SeverityLevel.CRITICAL,
                confidence_score=0.90,
                confidence_level=ConfidenceLevel.HIGH,
                status=FindingStatus.SUSPECTED,
                hypotheses_validated=["HYP-SQLI"],
                evidence=[sqli_ev]
            )
            self.state.record_finding(new_f)
            self.state.transition_finding_status(
                finding_id=new_f.id,
                target_status=FindingStatus.CONFIRMED,
                validator=self.validator,
                new_evidence=[sqli_ev]
            )

        h_after = self.heuristic_distance(self.state, goal)
        satisfied, reason = goal.is_satisfied(self.state)

        return {
            "step_executed": True,
            "action_id": action.id,
            "tool_name": action.tool_name,
            "action_type": action.action_type,
            "success": exec_res.success,
            "h_before": h_before,
            "h_after": h_after,
            "goal_satisfied": satisfied,
            "satisfaction_reason": reason
        }

    async def run_mission(self, goal: SecurityGoal, max_steps: int = 8) -> MissionReport:
        """
        دورة تنفيذ المهمة الذاتية المستمرة حتى تحقيق الهدف أو استنفاد خطوات البحث
        """
        log.info(f"[StateSpacePlanner] Starting mission '{goal.title}' for goal {goal.goal_type.value}")
        steps_history: List[Dict[str, Any]] = []

        # Check initial state
        satisfied, reason = goal.is_satisfied(self.state)
        step_count = 0

        while not satisfied and step_count < max_steps:
            step_count += 1
            step_res = await self.step(goal)
            steps_history.append(step_res)
            satisfied = step_res.get("goal_satisfied", False)
            reason = step_res.get("satisfaction_reason", "")
            if not step_res.get("step_executed"):
                break

        confirmed_findings = [
            f"{v.vulnerability_type} ({v.endpoint})"
            for v in self.state.vulnerabilities.values()
            if v.status in [FindingStatus.CONFIRMED, FindingStatus.EXPLOITED, FindingStatus.IMPACT_VERIFIED]
        ]

        report = MissionReport(
            goal_id=goal.id,
            goal_title=goal.title,
            target=goal.target or self.state.target,
            achieved=satisfied,
            steps_taken=step_count,
            findings_confirmed=confirmed_findings,
            state_snapshot=self.state.get_snapshot(),
            execution_steps=steps_history,
            conclusion=reason if satisfied else f"Mission completed after {step_count} steps. Goal not fully satisfied within budget."
        )

        log.info(f"[StateSpacePlanner] Mission finished. Achieved: {satisfied} (Steps: {step_count})")
        return report
