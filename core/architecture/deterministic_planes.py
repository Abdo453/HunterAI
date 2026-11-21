"""
Deterministic 3-Plane Agent Architecture
========================================
تطبيق القوانين المعمارية الثلاثة الصارمة للوكيل:
  1. فصل "التفكير" (ReasoningPlane) عن "التحكم" (DeterministicControlPlane) عن "التنفيذ" (ExecutionPlane).
  2. تمثيل الحالة في رسم بياني (KnowledgeGraph) وآلة حالة منتهية (AgentStateMachine / FSM)، وليس في نص محادثة متزايد (Zero Growing Chat History).
  3. فرض النطاق والسلامة عبر كود حتمي صارم (DeterministicSafetyGate + RedTeamPolicyEngine)، وليس عبر "طلب" نصي في الـ Prompt.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import shlex
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from agents.security_intelligence.task_clue_cache import TaskClueCache
from core.graph.knowledge_graph import KnowledgeGraph
from core.policy.red_team import (
    ActionClass,
    ActionRequest,
    AuthorizationGrant,
    Profile,
    RedTeamPolicyEngine,
    ScopeTarget,
)
from hunter_ai.knowledge.rag_engine import PreExecutionSyntaxValidator


# ═══════════════════════════════════════════════════════════════════════════
# القانون الثاني: آلة الحالة المنتهية (Finite State Machine - FSM)
# ═══════════════════════════════════════════════════════════════════════════

class FSMState(str, Enum):
    INIT = "INIT"
    OBSERVING = "OBSERVING"
    THINKING = "THINKING"
    PLANNING = "PLANNING"
    GATE_VERIFICATION = "GATE_VERIFICATION"
    EXECUTING = "EXECUTING"
    PARSING = "PARSING"
    GRAPH_UPDATING = "GRAPH_UPDATING"
    DECIDING = "DECIDING"
    VERIFYING = "VERIFYING"
    ADVANCING = "ADVANCING"
    HALTED_BLOCKED = "HALTED_BLOCKED"


ALLOWED_FSM_TRANSITIONS: Dict[FSMState, Set[FSMState]] = {
    FSMState.INIT: {FSMState.OBSERVING, FSMState.HALTED_BLOCKED},
    FSMState.OBSERVING: {FSMState.THINKING, FSMState.HALTED_BLOCKED},
    FSMState.THINKING: {FSMState.PLANNING, FSMState.HALTED_BLOCKED},
    FSMState.PLANNING: {FSMState.GATE_VERIFICATION, FSMState.HALTED_BLOCKED},
    FSMState.GATE_VERIFICATION: {FSMState.EXECUTING, FSMState.HALTED_BLOCKED},
    FSMState.EXECUTING: {FSMState.PARSING, FSMState.HALTED_BLOCKED},
    FSMState.PARSING: {FSMState.GRAPH_UPDATING, FSMState.HALTED_BLOCKED},
    FSMState.GRAPH_UPDATING: {FSMState.DECIDING, FSMState.HALTED_BLOCKED},
    FSMState.DECIDING: {
        FSMState.OBSERVING,
        FSMState.VERIFYING,
        FSMState.ADVANCING,
        FSMState.HALTED_BLOCKED,
    },
    FSMState.VERIFYING: {FSMState.OBSERVING, FSMState.ADVANCING, FSMState.HALTED_BLOCKED},
    FSMState.ADVANCING: {FSMState.OBSERVING, FSMState.HALTED_BLOCKED},
    FSMState.HALTED_BLOCKED: {FSMState.OBSERVING},
}


class AgentStateMachine:
    """
    آلة حالة منتهية حتمية (Deterministic Finite State Machine)
    تمثل حالة المهمة بدقة وتمنع أي انتقال غير قانوني بين المراحل،
    مع إلغاء الاعتماد على سجل المحادثة النصي المتزايد (Zero Chat History Bloat).
    """

    def __init__(self, target: str, phase: str = "recon"):
        self.target = target
        self.phase = phase
        self.current_state: FSMState = FSMState.INIT
        self.cycle_count: int = 0
        self.transitions_log: List[Dict[str, Any]] = []

    def transition_to(self, next_state: FSMState, reason: str = "") -> bool:
        allowed = ALLOWED_FSM_TRANSITIONS.get(self.current_state, set())
        if next_state not in allowed:
            raise RuntimeError(
                f"Illegal FSM state transition: {self.current_state.value} -> {next_state.value}"
            )
        prev = self.current_state
        self.current_state = next_state
        if next_state == FSMState.OBSERVING:
            self.cycle_count += 1
        self.transitions_log.append({
            "from": prev.value,
            "to": next_state.value,
            "reason": reason,
            "timestamp": time.time(),
        })
        return True

    def export_compact_state(self, kg: KnowledgeGraph, clue_cache: Optional[TaskClueCache] = None) -> Dict[str, Any]:
        """
        يُصدر تمثيلاً مضغوطاً بحجم ثابت O(1) من آلة الحالة والرسم البياني فقط
        (بدون أي سجل محادثة نصي متراكم).
        """
        facts = kg.export_verified_facts_context(max_facts=25)
        active_clues_count = len(clue_cache.clues) if clue_cache else 0
        failed_tasks_count = len(clue_cache.get_failed_tasks()) if clue_cache else 0
        return {
            "fsm_state": self.current_state.value,
            "phase": self.phase,
            "cycle_count": self.cycle_count,
            "transitions_count": len(self.transitions_log),
            "chat_history_messages_retained": 0,  # Zero growing text history!
            "graph_verified_counts": {
                "hosts": facts["verified_hosts_count"],
                "ports": facts["verified_ports_count"],
                "endpoints": facts["verified_endpoints_count"],
                "findings": facts["verified_findings_count"],
                "edges": facts["verified_edges_count"],
            },
            "clue_cache_counts": {
                "total_clues": active_clues_count,
                "failed_tasks": failed_tasks_count,
            },
            "verified_facts_prompt": facts["facts_prompt"],
        }


# ═══════════════════════════════════════════════════════════════════════════
# القانون الثالث: بوابة النطاق والسلامة الحتمية (Deterministic Safety & Scope Gate)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SafetyGateDecision:
    allowed: bool
    target_verified: str
    extracted_hosts: List[str]
    syntax_valid: bool
    repaired_command: str
    policy_reason: str
    directive_token: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "target_verified": self.target_verified,
            "extracted_hosts": list(self.extracted_hosts),
            "syntax_valid": self.syntax_valid,
            "repaired_command": self.repaired_command,
            "policy_reason": self.policy_reason,
            "directive_token": self.directive_token,
        }


class DeterministicSafetyGate:
    """
    بوابة أمان ونطاق حتمية بالكود (Code-Enforced Deterministic Firewall):
    لا تعتمد إطلاقاً على طلبات الـ Prompt، بل تفكك الأمر برمجياً وتتحقق من:
      1. خلو الأمر من محارف حقن الأوامر (Shell Chaining / Injection) أو العمليات التدميرية.
      2. استخراج كافة النطاقات والروابط وعناوين IP المذكورة داخل الأمر والتحقق من وجودها
         ضمن النطاق الموقّع تشفيرياً (HMAC Signed AuthorizationGrant).
      3. صحة بناء الجملة عبر PreExecutionSyntaxValidator.
      4. إصدار ختم توقيع حتمي (HMAC Directive Token) لا تقبل طبقة التنفيذ العمل بدونه.
    """

    FORBIDDEN_SHELL_PATTERNS = [
        r";", r"&&", r"\|\|", r"`", r"\$\(", r"\|\s*(sh|bash|zsh|cmd|powershell)\b",
        r">\s*/etc/", r"\brm\s+-rf\b", r"\bmkfs\b", r"\bshutdown\b", r"\breboot\b",
        r"\bDROP\s+TABLE\b", r"\bTRUNCATE\s+TABLE\b", r"\bDELETE\s+FROM\b",
    ]

    URL_OR_DOMAIN_REGEX = re.compile(
        r"(?:https?://)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?::\d+)?(?:/[^\s\"']*)?",
        re.IGNORECASE,
    )

    def __init__(
        self,
        scope_domains: List[str],
        secret: bytes = b"hunter-ai-deterministic-plane-secret",
        allowed_tools: Optional[List[str]] = None,
    ):
        self.scope_domains = [d.lower().strip() for d in scope_domains if d.strip()]
        self.secret = secret
        self.allowed_tools = allowed_tools
        scope_targets = [ScopeTarget("domain", d) for d in self.scope_domains] or [
            ScopeTarget("domain", "localhost")
        ]
        self.grant = AuthorizationGrant.sign(
            secret=self.secret,
            grant_id=f"GRANT-{uuid.uuid4().hex[:8].upper()}",
            authorized_by="DeterministicControlPlane",
            scope=scope_targets,
            not_before=time.time() - 300,
            not_after=time.time() + 86400 * 7,
            profiles=[Profile.RED_TEAM],
        )
        self.policy_engine = RedTeamPolicyEngine(
            grant=self.grant,
            profile=Profile.RED_TEAM,
            secret=self.secret,
        )

    def _extract_candidate_hosts(self, command: str, primary_target: str) -> List[str]:
        hosts: List[str] = []
        clean_primary = primary_target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0].lower()
        if clean_primary:
            hosts.append(clean_primary)

        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()

        for tok in tokens[1:]:
            if tok.startswith("-"):
                continue
            if tok.startswith("http://") or tok.startswith("https://"):
                parsed = urlparse(tok)
                if parsed.hostname:
                    hosts.append(parsed.hostname.lower())
            else:
                # Check if token looks like a domain/host (and not a file path like .json/.txt/.yaml)
                m = self.URL_OR_DOMAIN_REGEX.fullmatch(tok)
                if m:
                    candidate = m.group(1).lower()
                    if not candidate.endswith((".json", ".txt", ".xml", ".yaml", ".yml", ".py", ".sh", ".md", ".log", ".html")):
                        hosts.append(candidate)

        return sorted(set(hosts))

    def evaluate_and_sign(
        self,
        target: str,
        command: str,
        action_class: ActionClass = ActionClass.ACTIVE_TEST,
    ) -> SafetyGateDecision:
        # 1. Deterministic check for forbidden shell chaining / destructive patterns
        for pat in self.FORBIDDEN_SHELL_PATTERNS:
            if re.search(pat, command, re.IGNORECASE):
                return SafetyGateDecision(
                    allowed=False,
                    target_verified=target,
                    extracted_hosts=[],
                    syntax_valid=False,
                    repaired_command=command,
                    policy_reason=f"Deterministic Safety Block: forbidden pattern '{pat}' detected in command",
                )

        # 2. Deterministic Syntax Validation (shlex + placeholder check)
        syn = PreExecutionSyntaxValidator.validate_command_syntax(
            command=command,
            allowed_tools=self.allowed_tools,
            target=target,
        )
        if not syn["valid"]:
            return SafetyGateDecision(
                allowed=False,
                target_verified=target,
                extracted_hosts=[],
                syntax_valid=False,
                repaired_command=syn["repaired_command"],
                policy_reason=f"Deterministic Syntax Block: {syn['reason']}",
            )

        repaired_cmd = syn["repaired_command"]

        # 3. Deterministic Scope Verification for EVERY host referenced in target or command
        extracted_hosts = self._extract_candidate_hosts(repaired_cmd, target)
        if not extracted_hosts:
            return SafetyGateDecision(
                allowed=False,
                target_verified=target,
                extracted_hosts=[],
                syntax_valid=True,
                repaired_command=repaired_cmd,
                policy_reason="Deterministic Scope Block: no verifiable target host found",
            )

        for host in extracted_hosts:
            req = ActionRequest(target=f"https://{host}", action_class=action_class)
            dec = self.policy_engine.evaluate(req)
            if not dec.allowed:
                return SafetyGateDecision(
                    allowed=False,
                    target_verified=target,
                    extracted_hosts=extracted_hosts,
                    syntax_valid=True,
                    repaired_command=repaired_cmd,
                    policy_reason=f"Deterministic Scope Block on host '{host}': {dec.reason}",
                )

        # 4. Issue HMAC-SHA256 Execution Directive Token (verified by ExecutionPlane)
        sig = hmac.new(
            self.secret,
            f"{target}|{repaired_cmd}|ALLOWED".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return SafetyGateDecision(
            allowed=True,
            target_verified=target,
            extracted_hosts=extracted_hosts,
            syntax_valid=True,
            repaired_command=repaired_cmd,
            policy_reason="Deterministic Scope & Safety Gate: VERIFIED",
            directive_token=sig,
        )

    def verify_directive_token(self, target: str, command: str, token: Optional[str]) -> bool:
        if not token:
            return False
        expected = hmac.new(
            self.secret,
            f"{target}|{command}|ALLOWED".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, token)


# ═══════════════════════════════════════════════════════════════════════════
# القانون الأول: الفصل الصارم بين طبقات (التفكير) و(التحكم) و(التنفيذ)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ReasoningIntent:
    """مخرجات طبقة التفكير فقط — اقتراح مجرد بدون أي صلاحية تنفيذ مباشر."""
    phase: str
    classifications: List[str]
    proposed_tool: Optional[str]
    proposed_skill: Optional[str]
    proposed_command: str
    confidence: float
    rationale: str
    rag_hypotheses: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ControlDirective:
    """أمر تحكم صادر وموقّع من طبقة التحكم الحتمية إلى طبقة التنفيذ."""
    directive_id: str
    fsm_state: str
    target: str
    tool: Optional[str]
    skill: Optional[str]
    approved_command: str
    safety_decision: SafetyGateDecision
    planned_chain: List[str] = field(default_factory=list)


class ReasoningPlane:
    """
    طبقة التفكير (Reasoning Plane):
    تستقبل فقط ملخص الحالة المضغوط (الحقائق المؤكدة من الرسم البياني + حالة FSM)،
    وتُرجع نية/فرضية منظمة (ReasoningIntent).
    معزولة تماماً عن الأدوات وعن الشيل وعن تعديل الحالة.
    """

    def formulate_intent(
        self,
        compact_state: Dict[str, Any],
        thought_data: Dict[str, Any],
        target: str,
    ) -> ReasoningIntent:
        tool = thought_data.get("next_tool")
        skill = thought_data.get("next_skill")
        cmd = f"{tool or skill or 'httpx'} -u {target}"
        return ReasoningIntent(
            phase=str(compact_state.get("phase", "recon")),
            classifications=list(thought_data.get("classifications", [])),
            proposed_tool=tool,
            proposed_skill=skill,
            proposed_command=cmd,
            confidence=float(thought_data.get("confidence", 0.5)),
            rationale=str(thought_data.get("reasoning", "")),
            rag_hypotheses=list(thought_data.get("rag_hypotheses", [])),
        )


class DeterministicControlPlane:
    """
    طبقة التحكم الحتمية (Control Plane):
    تدير آلة الحالة (AgentStateMachine) وبوابة النطاق والسلامة الحتمية (DeterministicSafetyGate).
    تستقبل (ReasoningIntent) من طبقة التفكير، تتحقق منها حتمياً بالكود، وتُصدر (ControlDirective) موقّعاً.
    """

    def __init__(
        self,
        target: str,
        scope_domains: Optional[List[str]] = None,
        phase: str = "recon",
        secret: bytes = b"hunter-ai-deterministic-plane-secret",
    ):
        clean_host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        domains = list(scope_domains) if scope_domains else [clean_host]
        if clean_host and clean_host not in domains:
            domains.append(clean_host)
        self.fsm = AgentStateMachine(target=target, phase=phase)
        self.safety_gate = DeterministicSafetyGate(scope_domains=domains, secret=secret)

    def authorize_intent(
        self,
        intent: ReasoningIntent,
        target: str,
        explicit_scope_flag: bool = True,
        planned_chain: Optional[List[str]] = None,
    ) -> ControlDirective:
        self.fsm.transition_to(FSMState.GATE_VERIFICATION, reason="Validating ReasoningIntent at DeterministicSafetyGate")

        if not explicit_scope_flag:
            decision = SafetyGateDecision(
                allowed=False,
                target_verified=target,
                extracted_hosts=[],
                syntax_valid=False,
                repaired_command=intent.proposed_command,
                policy_reason="Deterministic Scope Block: scope_authorized=False",
            )
            self.fsm.transition_to(FSMState.HALTED_BLOCKED, reason=decision.policy_reason)
        else:
            decision = self.safety_gate.evaluate_and_sign(
                target=target,
                command=intent.proposed_command,
                action_class=ActionClass.ACTIVE_TEST,
            )
            if not decision.allowed:
                self.fsm.transition_to(FSMState.HALTED_BLOCKED, reason=decision.policy_reason)

        return ControlDirective(
            directive_id=f"DIR-{uuid.uuid4().hex[:8].upper()}",
            fsm_state=self.fsm.current_state.value,
            target=target,
            tool=intent.proposed_tool if decision.allowed else None,
            skill=intent.proposed_skill if decision.allowed else None,
            approved_command=decision.repaired_command if decision.allowed else "",
            safety_decision=decision,
            planned_chain=list(planned_chain or []) if decision.allowed else [],
        )


class ExecutionPlane:
    """
    طبقة التنفيذ المعزولة (Sandboxed Execution Plane):
    ترفض تنفيذ أي أمر لم يصدر بتوقيع تشفيري حتمي (HMAC Token) من طبقة التحكم (DeterministicControlPlane).
    """

    def execute_directive(
        self,
        directive: ControlDirective,
        control_plane: DeterministicControlPlane,
    ) -> Dict[str, Any]:
        dec = directive.safety_decision
        if not dec.allowed:
            return {
                "executed": False,
                "in_scope": False,
                "directive_id": directive.directive_id,
                "fsm_state": control_plane.fsm.current_state.value,
                "tool": None,
                "skill": None,
                "reason": dec.policy_reason,
                "syntax_validation": {
                    "valid": dec.syntax_valid,
                    "repaired_command": dec.repaired_command,
                    "reason": dec.policy_reason,
                },
                "deterministic_gate": dec.to_dict(),
                "next_skills": [],
                "suggested_finding": None,
            }

        # Verify cryptographic HMAC token issued by DeterministicControlPlane
        if not control_plane.safety_gate.verify_directive_token(
            directive.target,
            directive.approved_command,
            dec.directive_token,
        ):
            control_plane.fsm.transition_to(
                FSMState.HALTED_BLOCKED,
                reason="ExecutionPlane rejected unsigned/tampered ControlDirective",
            )
            raise PermissionError("ExecutionPlane refused to run directive without valid ControlPlane HMAC signature")

        control_plane.fsm.transition_to(
            FSMState.EXECUTING,
            reason=f"Executing signed directive {directive.directive_id}",
        )

        return {
            "executed": True,
            "in_scope": True,
            "directive_id": directive.directive_id,
            "fsm_state": control_plane.fsm.current_state.value,
            "tool": directive.tool,
            "skill": directive.skill,
            "approved_command": directive.approved_command,
            "reason": f"[DeterministicGate:VERIFIED] {dec.policy_reason}",
            "syntax_validation": {
                "valid": dec.syntax_valid,
                "repaired_command": dec.repaired_command,
                "reason": dec.policy_reason,
            },
            "deterministic_gate": dec.to_dict(),
            "next_skills": ["agent_reasoning_loop"] + directive.planned_chain,
            "suggested_finding": None,
        }
