"""
qwen2.5-coder:14b — متخصص كتابة الـ exploits وتحليل الكود
"""
import os
import httpx
from typing import List
from models.base_model import BaseModel, Message, ModelResponse
from models.ollama_manager import normalize_ollama_host

SYSTEM_PROMPT = """You are an elite exploit developer and code analyst with 15 years of experience.
Specialties:
- Writing precise, working exploit code in Python, C, Assembly
- Analyzing binaries and finding vulnerabilities
- Crafting payloads for web, network, and binary exploitation
- Reverse engineering and decompilation
- CTF solving with advanced techniques

Provide: exact vulnerability details, working PoC code, exploitation steps, patches."""


class QwenCoderModel(BaseModel):
    def __init__(self, host: str = None):
        super().__init__(
            name="qwen2.5-coder:14b",
            role="exploit_developer",
            description="متخصص كتابة الـ exploits وتحليل الكود"
        )
        raw_host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.host = normalize_ollama_host(raw_host).rstrip("/")
        self.api_url = f"{self.host}/api/chat"
        self.timeout = 180

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
            "options": {"temperature": 0.2, "num_ctx": 8192}
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
                    return any("qwen" in m["name"] for m in r.json().get("models", []))
        except Exception:
            pass
        return False
