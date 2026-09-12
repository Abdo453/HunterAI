"""
Report Agent — تجميع النتائج وتوليد التقرير + تصدير لـ Taskade
"""
import uuid
from typing import Optional
from datetime import datetime
from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from core.session_manager import SessionManager, Finding
from core.report_engine import ReportEngine

SEV_CVSS = {"Critical": 9.5, "High": 7.5, "Medium": 5.5, "Low": 2.5, "Info": 0.0}


class ReportAgent(BaseAgent):
    """
    وكيل التقارير:
    1. يجمع كل النتائج من الجلسة
    2. يولد تقارير HTML + JSON
    3. يصدر النتائج لـ Taskade (اختياري)
    """

    def __init__(self, tool_manager: ToolManager, session_manager: Optional[SessionManager] = None, cb=None):
        super().__init__(
            name="report_agent",
            description="تجميع النتائج وتوليد التقارير",
            tool_manager=tool_manager,
            progress_callback=cb,
        )
        self.sessions = session_manager or SessionManager()
        self.reporter = ReportEngine()

    async def run(self, task: AgentTask) -> AgentResult:
        result = AgentResult(agent_name=self.name, target=task.target)
        await self.emit("start", {"message": "Generating final report..."})

        session = self.sessions.load(task.session_id)
        if not session:
            result.success = False
            result.errors.append(f"Session {task.session_id} not found")
            return result

        # توليد التقارير
        paths = self.reporter.generate_all(session)
        self.sessions.complete(session)

        result.raw_output = paths
        await self.emit("complete", {
            "reports": paths,
            "total_findings": len(session.findings),
        })

        # تصدير لـ Taskade لو API Key موجود
        import os
        if os.getenv("TASKADE_API_KEY"):
            await self.emit("tool_start", {"tool": "taskade", "action": "export"})
            try:
                from models.api.taskade_provider import TaskadeProvider
                taskade = TaskadeProvider()
                findings_dicts = [
                    {"title": f.title, "severity": f.severity, "tool": f.tool}
                    for f in session.findings
                ]
                taskade_url = await taskade.export_findings_to_taskade(
                    session.id, findings_dicts
                )
                result.raw_output["taskade"] = taskade_url
                await self.emit("tool_done", {"tool": "taskade", "url": taskade_url})
            except Exception as e:
                await self.emit("tool_done", {"tool": "taskade", "error": str(e)})

        return result
