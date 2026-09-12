"""
sylink/sylink:8b — محلل سريع للـ recon وتلخيص النتائج
"""
import os
import httpx
from typing import List
from models.base_model import BaseModel, Message, ModelResponse
from models.ollama_manager import normalize_ollama_host

SYSTEM_PROMPT = """You are a rapid security analyst specializing in reconnaissance and results triage.
Strengths:
- Fast analysis of large scan data
- Quick identification of critical findings
- Efficient summarization of complex technical results
- Prioritizing by exploitability and impact

In the Model Council:
1. Review and validate other models' proposals
2. Add overlooked attack vectors
3. Provide concise actionable summaries
4. Give the final synthesis verdict"""


class SylinkModel(BaseModel):
    def __init__(self, host: str = None):
        super().__init__(
            name="sylink/sylink:8b",
            role="recon_analyst",
            description="محلل سريع للـ recon وتلخيص النتائج"
        )
        raw_host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.host = normalize_ollama_host(raw_host).rstrip("/")
        self.api_url = f"{self.host}/api/chat"
        self.timeout = 90

    async def generate(self, prompt: str, system_prompt: str = "") -> ModelResponse:
        messages = [
            {"role": "system", "content": system_prompt or SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
        return await self._call(messages)

    async def chat(self, messages: List[Message]) -> ModelResponse:
        ollama_msgs = []
        if not any(m.role == "system" for m in messages):
            ollama_msgs.append({"role": "system", "content": SYSTEM_PROMPT})
        for m in messages:
            ollama_msgs.append({"role": m.role, "content": m.content})
        return await self._call(ollama_msgs)

    async def _call(self, messages: list) -> ModelResponse:
        payload = {
            "model": self.name,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.3, "num_ctx": 4096}
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, trust_env=False) as c:
                r = await c.post(self.api_url, json=payload)
                r.raise_for_status()
                content = r.json().get("message", {}).get("content", "")
                return ModelResponse(content=content, model_name=self.name, role=self.role)
        except Exception as e:
            return ModelResponse(content="", model_name=self.name, role=self.role, error=str(e))

    async def is_available(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as c:
                r = await c.get(f"{self.host}/api/tags")
                if r.status_code == 200:
                    return any("sylink" in m["name"] for m in r.json().get("models", []))
        except Exception:
            pass
        return False

