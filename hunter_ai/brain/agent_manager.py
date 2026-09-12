"""
Hunter Agent Protocol v1: Central Agent Manager & Orchestrator
==============================================================
The Master Brain of HunterAI:
- Manages the Agent Registry & Validates Agent Contracts
- Hosts the 3-Tier Blackboard Shared Memory
- Coordinates Handoffs through an Asynchronous Task Queue
- Routes AI inferences via the AIModelRouter
- Coordinates full Bug Bounty missions without unmediated agent chatter
"""
from __future__ import annotations

import time
import asyncio
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Callable, Coroutine

from hunter_ai.protocol.contract import AgentContract, ModelTierPreference
from hunter_ai.protocol.blackboard import (
    ThreeTierBlackboardMemory,
    Level1Summary,
    Level2EvidenceItem
)
from hunter_ai.protocol.handoff import HandoffEnvelope, HandoffPriority
from hunter_ai.protocol.result import StructuredTaskResult, StructuredFinding
from hunter_ai.brain.model_router import AIModelRouter, RoutedModelSelection
from hunter_ai.brain.memory_hierarchy import MemoryHierarchy

logger = logging.getLogger("hunter_ai.agent_manager")


class BaseContractAgent:
    """Base class that every contract-bound agent must inherit and implement"""
    def __init__(self, contract: AgentContract):
        self.contract = contract

    async def execute_task(
        self,
        task_id: str,
        job_id: str,
        blackboard: ThreeTierBlackboardMemory,
        memory: MemoryHierarchy,
        router: AIModelRouter,
        handoff_input: Optional[HandoffEnvelope] = None
    ) -> StructuredTaskResult:
        raise NotImplementedError("Subclasses must implement execute_task")


class HunterAgentManager:
    """
    مدير الوكلاء المركزي (Hunter Agent Manager):
    العقل المدبر لمنظومة الوكلاء المتعددة:
    - يعرف من انتهى؟ ومن يحتاج النتيجة؟
    - يمرر ملخصات المستوى 1 فقط لمنع إرهاق الـ Context.
    - يتحكم في طابور المهام وعمليات التسليم (Handoffs).
    """

    def __init__(
        self,
        base_storage_dir: str = "storage/jobs",
        root_memory_dir: str = "memory"
    ):
        self.blackboard = ThreeTierBlackboardMemory(base_storage_dir=base_storage_dir)
        self.memory = MemoryHierarchy(root_memory_dir=root_memory_dir)
        self.router = AIModelRouter()
        self._agents: Dict[str, BaseContractAgent] = {}
        self._handoff_history: List[HandoffEnvelope] = []
        self._task_queue: asyncio.Queue[HandoffEnvelope] = asyncio.Queue()

    def register_agent(self, agent: BaseContractAgent):
        """Registers a contract-compliant agent"""
        self._agents[agent.contract.name] = agent
        logger.info(f"[Brain] Registered agent '{agent.contract.name}' (Skills: {agent.contract.skills})")

    def get_agent(self, agent_name: str) -> Optional[BaseContractAgent]:
        return self._agents.get(agent_name)

    def list_contracts(self) -> List[Dict[str, Any]]:
        return [ag.contract.to_dict() for ag in self._agents.values()]

    def find_agent_for_task(self, required_skill: str, input_format: str = "*") -> Optional[BaseContractAgent]:
        """Finds the registered agent matching skill and input schema requirements"""
        for ag in self._agents.values():
            if ag.contract.matches_task(required_skill, input_format):
                return ag
        return None

    async def post_handoff(self, envelope: HandoffEnvelope) -> bool:
        """
        Receives a handoff from an agent, logs it in history, and enqueues it.
        """
        self._handoff_history.append(envelope)
        logger.info(f"[Handoff] Received handoff from {envelope.from_agent} -> {envelope.to_agent} (Task: {envelope.task})")
        await self._task_queue.put(envelope)
        return True

    async def execute_mission(
        self,
        target_url: str,
        initial_agent_name: str = "ReconAgent"
    ) -> Dict[str, Any]:
        """
        Runs an end-to-end multi-agent mission orchestrated strictly via Blackboard & Handoffs.
        """
        t0 = time.time()
        job_id = f"job_{int(t0)}"
        summary = self.blackboard.get_or_create_summary(job_id, target_url)
        summary.active_agent = initial_agent_name

        logger.info(f"[*] Starting Multi-Agent Mission {job_id} for target {target_url} via {initial_agent_name}")

        initial_agent = self.get_agent(initial_agent_name)
        if not initial_agent:
            raise ValueError(f"Initial agent '{initial_agent_name}' not registered in manager!")

        # Initial Task Execution
        result: StructuredTaskResult = await initial_agent.execute_task(
            task_id=f"task_{job_id}_init",
            job_id=job_id,
            blackboard=self.blackboard,
            memory=self.memory,
            router=self.router
        )

        # Process any handoffs generated
        all_findings: List[Dict[str, Any]] = [asdict(f) for f in result.findings]

        if result.next_agent and result.handoff_envelope:
            envelope_data = result.handoff_envelope
            envelope = HandoffEnvelope(
                from_agent=result.agent_name,
                to_agent=result.next_agent,
                task=result.next_step,
                context_id=job_id,
                priority=HandoffPriority.HIGH,
                summary=self.blackboard.get_summary_dict(job_id),
                evidence_ref=envelope_data.get("evidence_ref"),
                raw_data_path=envelope_data.get("raw_data_path"),
                required_skill=envelope_data.get("required_skill")
            )
            await self.post_handoff(envelope)

        # Process queued handoffs
        while not self._task_queue.empty():
            handoff = await self._task_queue.get()
            target_agent = self.get_agent(handoff.to_agent)
            if not target_agent and handoff.required_skill:
                target_agent = self.find_agent_for_task(handoff.required_skill)

            if target_agent:
                self.blackboard.update_summary(job_id, active_agent=target_agent.contract.name)
                logger.info(f"[Brain] Executing Handoff: {target_agent.contract.name} picking up '{handoff.task}'")
                sub_res: StructuredTaskResult = await target_agent.execute_task(
                    task_id=f"task_{job_id}_{target_agent.contract.name.lower()}",
                    job_id=job_id,
                    blackboard=self.blackboard,
                    memory=self.memory,
                    router=self.router,
                    handoff_input=handoff
                )
                for fnd in sub_res.findings:
                    all_findings.append(asdict(fnd))

                # Chain next handoff if present
                if sub_res.next_agent and sub_res.handoff_envelope:
                    sub_env = HandoffEnvelope(
                        from_agent=sub_res.agent_name,
                        to_agent=sub_res.next_agent,
                        task=sub_res.next_step,
                        context_id=job_id,
                        summary=self.blackboard.get_summary_dict(job_id),
                        evidence_ref=sub_res.handoff_envelope.get("evidence_ref"),
                        raw_data_path=sub_res.handoff_envelope.get("raw_data_path")
                    )
                    await self.post_handoff(sub_env)
            self._task_queue.task_done()

        # Finalize Mission
        self.blackboard.update_summary(job_id, status="completed", vulns_delta=len(all_findings))
        self.memory.record_completed_mission(job_id, target_url, t0, all_findings)

        return {
            "job_id": job_id,
            "target": target_url,
            "status": "completed",
            "duration_seconds": round(time.time() - t0, 2),
            "level1_summary": self.blackboard.get_summary_dict(job_id),
            "findings_count": len(all_findings),
            "findings": all_findings,
            "handoffs_executed": len(self._handoff_history)
        }
