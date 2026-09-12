"""
Governed Tool Gateway (CyberStrikeAI-Inspired)
The centralized governed execution gateway.
Every action proposal from agents/LLMs must be evaluated, policy-approved, safe-executed,
and converted into immutable EvidenceItem records in SecurityState.
"""
import time
import logging
from typing import Optional, List, Dict, Any

from core.gateway.schemas import (
    ActionProposal,
    PolicyVerdict,
    GovernedExecutionResult,
    RiskTier
)
from core.gateway.policy_engine import PolicyEngine
from tools.tool_manager import ToolManager, ToolResult
from agents.security_intelligence.schemas import (
    EvidenceItem,
    EvidenceType,
    ProvenanceRecord
)
from core.state.security_state import SecurityState

log = logging.getLogger("core.gateway.tool_gateway")


class GovernedToolGateway:
    """
    بوابة الأدوات المحكومة:
    المنفذ الوحيد المسموح للوكلاء الأذكياء (LLMs / Autonomous Agents) بتنفيذ الأدوات من خلاله.
    تضمن:
    - فحص السياسات والمخاطر قبل كل تشغيل
    - تحويل النتائج والمخرجات الخام فوراً إلى أدلة رقمية موثقة
    - حفظ الأدلة في ذاكرة حالة الهجوم (SecurityState)
    - تسجيل سجل تدقيق صارم لا يقبل التعديل
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        tool_manager: Optional[ToolManager] = None,
        security_state: Optional[SecurityState] = None
    ):
        self.policy = policy_engine or PolicyEngine()
        self.tool_manager = tool_manager or ToolManager()
        self.security_state = security_state
        self._audit_trail: List[Dict[str, Any]] = []

    def set_security_state(self, state: SecurityState):
        """ربط بوابة الأدوات بذاكرة حالة الهجوم النشطة"""
        self.security_state = state

    async def execute_proposal(self, proposal: ActionProposal) -> GovernedExecutionResult:
        """
        تنفيذ المقترح الأمني وفق المسار المحكوم:
        Proposal -> Policy Evaluation -> Execution -> Evidence Creation -> Ingestion
        """
        t0 = time.time()

        # 1. Policy & Scope & Risk Evaluation
        verdict: PolicyVerdict = self.policy.evaluate_proposal(proposal)

        # 2. Handle Blocked Proposals
        if not verdict.allowed:
            self._record_audit(
                event="proposal_blocked",
                proposal_id=proposal.id,
                tool_name=proposal.tool_name,
                target=proposal.target,
                risk_tier=verdict.risk_tier.value,
                status=verdict.status,
                reason=verdict.reason
            )
            return GovernedExecutionResult(
                proposal_id=proposal.id,
                tool_name=proposal.tool_name,
                target=proposal.target,
                success=False,
                blocked=True,
                risk_tier=verdict.risk_tier,
                error=verdict.reason,
                duration=round(time.time() - t0, 3)
            )

        self._record_audit(
            event="proposal_approved",
            proposal_id=proposal.id,
            tool_name=proposal.tool_name,
            target=proposal.target,
            risk_tier=verdict.risk_tier.value
        )

        # 3. Governed Execution via ToolManager or HTTP
        raw_stdout = ""
        raw_stderr = ""
        returncode = 0
        error_msg = None
        cmd_args = verdict.sanitized_args if verdict.sanitized_args is not None else proposal.command_args

        try:
            if proposal.action_type.upper() == "HTTP_REQUEST" and not proposal.command_args:
                # Direct HTTP request fallback via httpx
                import httpx
                async with httpx.AsyncClient(timeout=proposal.timeout, verify=False) as client:
                    resp = await client.get(proposal.target)
                    raw_stdout = resp.text[:10000]
                    returncode = 0 if resp.status_code < 400 else 1
            else:
                # CLI tool execution via ToolManager
                tool_res: ToolResult = await self.tool_manager.execute_tool(
                    tool_name=proposal.tool_name,
                    args=cmd_args,
                    timeout=proposal.timeout
                )
                raw_stdout = tool_res.stdout
                raw_stderr = tool_res.stderr
                returncode = tool_res.returncode
                error_msg = tool_res.error
        except Exception as e:
            log.exception(f"[GovernedToolGateway] Execution error for proposal {proposal.id}: {e}")
            error_msg = str(e)
            returncode = -1

        duration = round(time.time() - t0, 3)
        success = (returncode == 0 and not error_msg)

        # 4. Synthesize EvidenceItem from Raw Output
        evidence_item = self._create_evidence_item(
            proposal=proposal,
            verdict=verdict,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            returncode=returncode,
            duration=duration
        )

        # 5. Ingest Evidence into SecurityState
        if self.security_state and evidence_item:
            self.security_state.add_evidence(evidence_item)

        self._record_audit(
            event="proposal_executed",
            proposal_id=proposal.id,
            tool_name=proposal.tool_name,
            success=success,
            duration=duration,
            evidence_id=evidence_item.id if evidence_item else None
        )

        return GovernedExecutionResult(
            proposal_id=proposal.id,
            tool_name=proposal.tool_name,
            target=proposal.target,
            success=success,
            blocked=False,
            risk_tier=verdict.risk_tier,
            raw_stdout=raw_stdout,
            raw_stderr=raw_stderr,
            returncode=returncode,
            duration=duration,
            evidence_item=evidence_item,
            error=error_msg
        )

    def _create_evidence_item(
        self,
        proposal: ActionProposal,
        verdict: PolicyVerdict,
        raw_stdout: str,
        raw_stderr: str,
        returncode: int,
        duration: float
    ) -> EvidenceItem:
        """
        تحويل مخرجات الأداة الخام إلى EvidenceItem متوافق مع معايير الأدلة الجنائية والتحقق
        """
        combined_output = (raw_stdout + "\n" + raw_stderr).strip()

        # Infer evidence type
        ev_type = EvidenceType.RESPONSE
        weight = 0.50

        lower_out = combined_output.lower()
        if any(err_kw in lower_out for err_kw in ["syntax error", "sql syntax", "ora-", "mysql_fetch", "sqlite3", "pg_"]):
            ev_type = EvidenceType.ERROR_DISCLOSURE
            weight = 0.80
        elif any(diff_kw in lower_out for diff_kw in ["differential", "unauthorized 200", "cross-user", "different response"]):
            ev_type = EvidenceType.BEHAVIOR_DIFF
            weight = 0.90
        elif any(auth_kw in lower_out for auth_kw in ["token", "jwt", "authenticated", "session_id", "bypass"]):
            ev_type = EvidenceType.AUTH_ANOMALY
            weight = 0.85
        elif returncode == 0 and len(combined_output) > 0:
            ev_type = EvidenceType.STATUS_CODE
            weight = 0.60

        provenance = ProvenanceRecord(
            source_component=f"GovernedToolGateway.{proposal.tool_name}",
            model_name=proposal.proposing_agent,
            confidence=1.0 if returncode == 0 else 0.5,
            notes=f"RiskTier: {verdict.risk_tier.value} | Duration: {duration}s"
        )

        return EvidenceItem(
            type=ev_type,
            source=f"gateway.{proposal.tool_name}",
            description=f"Governed execution output of '{proposal.tool_name}' on {proposal.target}: {proposal.rationale or 'Diagnostic probe'}",
            data={
                "proposal_id": proposal.id,
                "command_args": proposal.command_args,
                "action_type": proposal.action_type,
                "returncode": returncode,
                "stdout_sample": raw_stdout[:2000],
                "stderr_sample": raw_stderr[:1000],
                "duration": duration
            },
            weight=weight,
            verified=(returncode == 0),
            provenance=provenance
        )

    def _record_audit(self, event: str, **kwargs) -> None:
        self._audit_trail.append({
            "timestamp": time.time(),
            "event": event,
            **kwargs
        })

    @property
    def audit_trail(self) -> List[Dict[str, Any]]:
        return list(self._audit_trail)
