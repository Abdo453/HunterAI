"""
HunterAI / ARTEX Worker Trace Exchange Engine
=============================================
Enables process-level observation exchange between workers:
- Records raw execution steps, stdout, stderr, and contextual observations.
- Allows any worker to search across other workers' activity traces by keyword.
- Automatically excludes the requesting worker's own steps to avoid redundancy.
- Reuses tokens, hidden endpoints, error messages, and parameters before they become formal facts.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.worker_trace")


@dataclass
class WorkerActivityStep:
    step_id: str
    intent_id: str
    worker_id: str
    tool_name: str
    command_or_input: str
    output_summary: str
    full_output: str
    is_error: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class WorkerTraceSearchResult:
    step_id: str
    intent_id: str
    worker_id: str
    tool_name: str
    summary_snippet: str
    is_error: bool
    timestamp: float


class WorkerTraceStore:
    """
    Central activity trace repository for all concurrent workers within a hunt task.
    """

    def __init__(self):
        self.steps: Dict[str, WorkerActivityStep] = {}
        # intent_id -> list of step_ids
        self.intent_steps: Dict[str, List[str]] = {}

    def record_step(
        self,
        intent_id: str,
        worker_id: str,
        tool_name: str,
        command_or_input: str,
        full_output: str,
        is_error: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> WorkerActivityStep:
        step_id = f"step_{uuid.uuid4().hex[:8]}"
        summary = full_output.strip().split("\n")[0][:120] if full_output else ""
        step = WorkerActivityStep(
            step_id=step_id,
            intent_id=intent_id,
            worker_id=worker_id,
            tool_name=tool_name,
            command_or_input=command_or_input,
            output_summary=summary,
            full_output=full_output,
            is_error=is_error,
            metadata=metadata or {},
        )
        self.steps[step_id] = step
        self.intent_steps.setdefault(intent_id, []).append(step_id)
        return step

    def search_all_worker_traces(
        self,
        query: str,
        caller_worker_id: Optional[str] = None,
        caller_intent_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[WorkerTraceSearchResult]:
        """
        Keyword-searches all recorded worker traces.
        Excludes the caller's own steps if caller_worker_id or caller_intent_id is provided.
        """
        q = query.strip().lower()
        if not q:
            return []

        hits: List[WorkerTraceSearchResult] = []
        for step in self.steps.values():
            if caller_worker_id and step.worker_id == caller_worker_id:
                continue
            if caller_intent_id and step.intent_id == caller_intent_id:
                continue

            text_to_search = f"{step.tool_name} {step.command_or_input} {step.output_summary} {step.full_output}".lower()
            if q in text_to_search:
                # Find matching snippet directly in full_output if present, else summary
                out_lower = step.full_output.lower()
                f_idx = out_lower.find(q)
                if f_idx >= 0:
                    start = max(0, f_idx - 40)
                    end = min(len(step.full_output), f_idx + len(q) + 40)
                    snippet = step.full_output[start:end].replace("\n", " ")
                else:
                    snippet = step.output_summary

                hits.append(
                    WorkerTraceSearchResult(
                        step_id=step.step_id,
                        intent_id=step.intent_id,
                        worker_id=step.worker_id,
                        tool_name=step.tool_name,
                        summary_snippet=snippet or step.output_summary,
                        is_error=step.is_error,
                        timestamp=step.timestamp,
                    )
                )
                if len(hits) >= limit:
                    break

        return hits

    def get_worker_trace(self, intent_id: str, step_ids: Optional[List[str]] = None) -> List[WorkerActivityStep]:
        """
        Returns the step-by-step trace of a specific work intent.
        """
        all_intent_step_ids = self.intent_steps.get(intent_id, [])
        if step_ids:
            return [self.steps[sid] for sid in step_ids if sid in self.steps]
        return [self.steps[sid] for sid in all_intent_step_ids if sid in self.steps]

    def list_executed_works(self) -> List[Dict[str, Any]]:
        """Lists all intents that have at least one recorded activity step."""
        out = []
        for intent_id, sids in self.intent_steps.items():
            first_step = self.steps[sids[0]] if sids else None
            out.append({
                "intent_id": intent_id,
                "step_count": len(sids),
                "tool": first_step.tool_name if first_step else "",
                "worker_id": first_step.worker_id if first_step else "",
            })
        return out
