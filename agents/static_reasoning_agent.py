"""
Static Security Reasoning Agent
وكيل التحليل الأمني الاستنتاجي المعتمد على الأدلة وتتبع مسار البيانات
"""
import logging
from typing import Dict, Any, List, Optional, Callable
from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from core.static_reasoning_engine import StaticSecurityReasoningEngine

log = logging.getLogger("agent.static_reasoner")


class StaticSecurityReasoningAgent(BaseAgent):
    """
    وكيل أمني مستقل يحلل الأكواد المصدرية (Source Code / Decompiled APK / APIs)
    بمنهجية الاستنتاج والتحقق من الفرضيات (Hypothesis & Evidence Reasoning)
    """

    def __init__(
        self,
        name: str = "StaticSecurityReasoningAgent",
        description: str = "وكيل التحليل الأمني الاستنتاجي المعتمد على الأدلة وتتبع مسار البيانات",
        tool_manager: Optional[ToolManager] = None,
        progress_callback: Optional[Callable] = None
    ):
        tm = tool_manager if tool_manager is not None else ToolManager()
        super().__init__(name=name, description=description, tool_manager=tm, progress_callback=progress_callback)
        self.engine = StaticSecurityReasoningEngine()

    async def audit_code(self, source_code: str, target_name: str = "Component", context: str = "") -> Dict[str, Any]:
        """فحص الشيفرة المصدرية وتطبيق دورة الاستنتاج الثابتة"""
        await self.emit("status", {"message": f"Starting 8-Phase Static Security Reasoning on {target_name}"})
        result = await self.engine.analyze_source(source_code, target_name=target_name, additional_context=context)
        await self.emit("reasoning_complete", {
            "target": target_name,
            "total_findings": result["total_findings"],
            "findings": result["findings"]
        })
        return result

    async def run(self, task: AgentTask) -> AgentResult:
        source_code = task.target
        target_name = task.session_id or "SourceAudit"
        context = task.extra.get("context", "") if task.extra else ""
        
        result = await self.audit_code(source_code, target_name=target_name, context=context)
        
        return AgentResult(
            agent_name=self.name,
            target=target_name,
            findings=result["findings"],
            raw_output={
                "total_findings": str(result["total_findings"]),
                "reasoning_memory": str(len(result["reasoning_memory"])),
                "raw_analysis": result.get("raw_analysis", "")
            }
        )
