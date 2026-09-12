"""OpenRouter Provider — Pure HTTP via httpx with no SDK dependencies"""
import os
import httpx
from typing import List
from models.base_model import BaseModel, Message, ModelResponse


class OpenRouterProvider(BaseModel):
    def __init__(self, model: str = "meta-llama/llama-3.3-70b-instruct", role: str = "api_analyst"):
        super().__init__(name=model, role=role, description=f"OpenRouter {model}")
        self.model = model
        self.api_key = os.getenv("OPENROUTER_API_KEY", "")

    async def generate(self, prompt: str, system_prompt: str = "") -> ModelResponse:
        return await self.chat([
            Message(role="system", content=system_prompt or "You are an expert security analyst."),
            Message(role="user", content=prompt)
        ])

    async def chat(self, messages: List[Message]) -> ModelResponse:
        if not self.api_key:
            return ModelResponse(content="", model_name=self.name, role=self.role, error="OPENROUTER_API_KEY is not set")

        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/pentestai/unified",
            "X-Title": "PentestAI Unified",
            "Content-Type": "application/json"
        }
        payload = {

            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": 2048
        }


        try:
            async with httpx.AsyncClient(timeout=45, trust_env=False) as client:
                r = await client.post(url, headers=headers, json=payload)
                if r.status_code == 200:
                    data = r.json()
                    choices = data.get("choices", [])
                    if choices:
                        text = choices[0].get("message", {}).get("content", "")
                        return ModelResponse(content=text, model_name=self.name, role=self.role)
                return ModelResponse(content="", model_name=self.name, role=self.role, error=f"HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            return ModelResponse(content="", model_name=self.name, role=self.role, error=str(e))

    async def is_available(self) -> bool:
        return bool(self.api_key)
