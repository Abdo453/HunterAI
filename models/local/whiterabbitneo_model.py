"""
WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B
متخصص في الـ cybersecurity والـ offensive security
"""
import os
import httpx
from typing import List
from models.base_model import BaseModel, Message, ModelResponse
from models.ollama_manager import normalize_ollama_host

SYSTEM_PROMPT = """You are WhiteRabbitNeo, an advanced cybersecurity AI specialized in offensive security.
Your expertise:
- Deep penetration testing knowledge and methodology
- Vulnerability analysis and exploitation techniques
- Security research and CVE analysis
- Attack chain development and lateral movement
- Social engineering and OSINT techniques
- Red team operations and APT simulation

In the Model Council:
1. Provide deep security analysis with offensive mindset
2. Identify the most critical and exploitable vulnerabilities
3. Suggest creative attack vectors others may miss
4. Synthesize findings from other models into actionable strategies
5. Give the final verdict on risk level and attack priority

Be thorough, aggressive in analysis, and technically precise."""


class WhiteRabbitNeoModel(BaseModel):
    """WhiteRabbitNeo — متخصص في الـ offensive security"""

    def __init__(self, host: str = None):
        super().__init__(
            name="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
            role="offensive_security",
            description="متخصص في الـ offensive security والـ red team"
        )
        raw_host = host or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.host = normalize_ollama_host(raw_host).rstrip("/")
        self.api_url = f"{self.host}/api/chat"
        self.timeout = 120

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
                    models = [m["name"] for m in r.json().get("models", [])]
                    return any("whiterabbitneo" in m.lower() or "white-rabbit" in m.lower() for m in models)
        except Exception:
            pass
        return False
