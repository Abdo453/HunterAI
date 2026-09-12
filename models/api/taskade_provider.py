"""
Taskade AI Provider — https://www.taskade.com/
يدعم موديلات Taskade للتحليل الأمني والتنظيم
"""
import os
import httpx
from typing import List
from models.base_model import BaseModel, Message, ModelResponse


class TaskadeProvider(BaseModel):
    """
    Taskade AI Provider
    API Docs: https://developers.taskade.com/
    """

    def __init__(self, model: str = "taskade-ai", role: str = "task_organizer"):
        super().__init__(
            name=model,
            role=role,
            description="Taskade AI — تنظيم المهام والتقارير"
        )
        self.api_key = os.getenv("TASKADE_API_KEY", "")
        self.base_url = "https://api.taskade.com/v1"
        self.timeout = 60

    async def generate(self, prompt: str, system_prompt: str = "") -> ModelResponse:
        return await self.chat([
            Message(role="system", content=system_prompt or "You are an expert security analyst and task organizer."),
            Message(role="user", content=prompt)
        ])

    async def chat(self, messages: List[Message]) -> ModelResponse:
        if not self.api_key:
            return ModelResponse(
                content="", model_name=self.name, role=self.role,
                error="TASKADE_API_KEY not set in .env"
            )
        # Taskade API — chat completion endpoint
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        # تحويل الرسائل لصيغة Taskade
        payload = {
            "messages": [
                {"role": m.role, "content": m.content}
                for m in messages
            ],
            "model": "taskade-ai",
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as c:
                r = await c.post(

                    f"{self.base_url}/ai/completion",
                    headers=headers,
                    json=payload
                )
                r.raise_for_status()
                data = r.json()
                # محاولة استخراج الرد من أي صيغة
                content = (
                    data.get("choices", [{}])[0].get("message", {}).get("content")
                    or data.get("response")
                    or data.get("content")
                    or str(data)
                )
                return ModelResponse(content=content, model_name=self.name, role=self.role)
        except httpx.HTTPStatusError as e:
            return ModelResponse(
                content="", model_name=self.name, role=self.role,
                error=f"HTTP {e.response.status_code}: {e.response.text[:200]}"
            )
        except Exception as e:
            return ModelResponse(content="", model_name=self.name, role=self.role, error=str(e))

    async def create_project(self, title: str, tasks: List[str]) -> dict:
        """إنشاء مشروع في Taskade مع المهام"""
        if not self.api_key:
            return {"error": "No API key"}
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "name": title,
            "tasks": [{"content": t} for t in tasks]
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post(
                    f"{self.base_url}/projects",
                    headers=headers,
                    json=payload
                )
                return r.json()
        except Exception as e:
            return {"error": str(e)}

    async def export_findings_to_taskade(self, session_id: str, findings: List[dict]) -> str:
        """
        تصدير نتائج الـ pentest لـ Taskade كـ project منظم
        Critical findings → أعلى الـ tasks
        """
        if not findings:
            return "No findings to export"

        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.get("severity","Info"), 4))

        tasks = []
        for f in sorted_findings:
            sev = f.get("severity", "Info")
            title = f.get("title", "Unknown")
            tool = f.get("tool", "")
            emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "🔵"}.get(sev, "⚪")
            tasks.append(f"{emoji} [{sev}] {title} (via {tool})")

        project_title = f"PentestAI Report — Session {session_id}"
        result = await self.create_project(project_title, tasks)

        if "error" in result:
            return f"Taskade export failed: {result['error']}"

        project_url = result.get("url") or result.get("id", "")
        return f"✅ Exported to Taskade: {project_url}"

    async def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(
                    f"{self.base_url}/me",
                    headers={"Authorization": f"Bearer {self.api_key}"}
                )
                return r.status_code in (200, 401)  # 401 = key وجود لكن غلط
        except Exception:
            return False
