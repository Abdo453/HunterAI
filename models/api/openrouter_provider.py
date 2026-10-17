"""OpenRouter Provider — Pure HTTP via httpx with no SDK dependencies"""
import json
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

    async def stream(self, messages: List[Message], on_token=None) -> ModelResponse:
        """OpenAI-compatible SSE streaming over httpx."""
        if not self.api_key:
            return ModelResponse(content="", model_name=self.name, role=self.role, error="OPENROUTER_API_KEY is not set")

        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "HTTP-Referer": "https://github.com/pentestai/unified",
            "X-Title": "PentestAI Unified",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "max_tokens": 2048,
            "stream": True,
        }
        parts: List[str] = []
        try:
            async with httpx.AsyncClient(timeout=120, trust_env=False) as client:
                async with client.stream("POST", url, headers=headers, json=payload) as r:
                    if r.status_code != 200:
                        body = (await r.aread()).decode("utf-8", "replace")[:200]
                        return ModelResponse(content="", model_name=self.name, role=self.role,
                                             error=f"HTTP {r.status_code}: {body}")
                    async for line in r.aiter_lines():
                        if not line.startswith("data:"):
                            continue
                        chunk = line[5:].strip()
                        if not chunk or chunk == "[DONE]":
                            continue
                        try:
                            data = json.loads(chunk)
                        except Exception:
                            continue
                        choices = data.get("choices", [])
                        if not choices:
                            continue
                        delta = (choices[0].get("delta") or {}).get("content")
                        if delta:
                            parts.append(delta)
                            if on_token:
                                await on_token(delta)
            content = "".join(parts)
            return ModelResponse(content=content, model_name=self.name, role=self.role,
                                 error=None if content else "empty stream")
        except Exception as e:
            return ModelResponse(content="".join(parts), model_name=self.name, role=self.role, error=str(e))

    async def is_available(self) -> bool:
        return bool(self.api_key)
