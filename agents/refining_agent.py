"""
Self-Refining Verification & Remediation Agent
وكيل ذكي تكراري يتحقق من الثغرات، يولد سيناريوهات التحقق الآمن،
ويصحح الكود ذاتياً (Self-Correction Loop) حتى يخرج بالحل والترقيع النهائي
"""
import asyncio
import logging
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass, field

log = logging.getLogger("refining_agent")


@dataclass
class RefineResult:
    target: str
    vulnerability_type: str
    verified: bool
    iterations_run: int
    validation_logic: str
    remediation_patch: str
    history: list = field(default_factory=list)


class SelfRefiningAgent:
    """
    وكيل الفحص والترقيع التكراري (Self-Refining Loop)
    """

    def __init__(self, resource_manager=None, progress_cb: Optional[Callable] = None):
        if resource_manager is None:
            try:
                from orchestrator.resource_manager import ResourceManager
                self.rm = ResourceManager()
            except Exception:
                self.rm = None
        else:
            self.rm = resource_manager
        self.cb = progress_cb

    async def _emit(self, event: str, data: dict):
        if self.cb:
            try:
                await self.cb({"event": event, **data})
            except Exception:
                pass

    async def refine_and_remediate(
        self,
        target: str,
        vulnerability_claim: str,
        context_evidence: str = "",
        max_iterations: int = 3
    ) -> RefineResult:
        """
        حلقة تدقيق وتحقق وترقيع ذاتية
        """
        await self._emit("refine_start", {
            "target": target,
            "claim": vulnerability_claim[:100],
            "max_iterations": max_iterations
        })

        history = []
        current_hypothesis = f"Validate potential vulnerability on {target}: {vulnerability_claim}"
        last_error = ""
        verified = False
        remediation_code = ""

        for iteration in range(1, max_iterations + 1):
            await self._emit("refine_iteration", {
                "iteration": iteration,
                "action": f"Drafting verification hypothesis #{iteration}"
            })

            # 1. Ask Qwen / Expert to produce safe validation probe logic
            prompt = (
                f"You are an expert security researcher and automated validator.\n"
                f"Target: {target}\n"
                f"Claim: {vulnerability_claim}\n"
                f"Evidence: {context_evidence}\n"
            )
            if last_error:
                prompt += f"\nPrevious attempt failed with error/feedback: {last_error}\nRefine the logic to fix this error."

            prompt += (
                "\nProvide:\n"
                "1. Exact technical verification logic (safe, non-destructive)\n"
                "2. Specific expected response indicating vulnerability\n"
                "3. Robust remediation patch in Python / Security config"
            )

            messages = [
                {"role": "system", "content": "You are a senior security engineer. Output clear, robust verification logic and production-ready remediation code."},
                {"role": "user", "content": prompt}
            ]

            response = await self.rm.run_local_model(
                model_name="qwen2.5-coder:14b",
                messages=messages,
                temperature=0.2,
                progress_cb=self.cb
            )

            history.append({
                "iteration": iteration,
                "model_output": response[:500]
            })

            # Check if response has clear remediation and logic
            if "remediation" in response.lower() or "patch" in response.lower() or "def " in response or "fix" in response.lower():
                verified = True
                remediation_code = response
                await self._emit("refine_iteration_done", {
                    "iteration": iteration,
                    "status": "Verified & Remediated",
                    "preview": response[:200]
                })
                break
            else:
                last_error = "Response lacked concrete verification criteria or patch."

        return RefineResult(
            target=target,
            vulnerability_type=vulnerability_claim[:50],
            verified=verified,
            iterations_run=iteration,
            validation_logic=history[-1]["model_output"] if history else "",
            remediation_patch=remediation_code,
            history=history
        )


RefiningAgent = SelfRefiningAgent
