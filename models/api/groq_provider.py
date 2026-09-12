"""Groq Provider — سريع جداً"""
import os
from typing import List
from models.base_model import BaseModel, Message, ModelResponse

try:
    from openai import AsyncOpenAI
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


class GroqProvider(BaseModel):
    def __init__(self, model: str = "llama-3.3-70b-versatile", role: str = "api_analyst"):
        super().__init__(name=model, role=role, description=f"Groq {model}")
        self.model = model
        self.api_key = os.getenv("GROQ_API_KEY", "")
        self.client = (
            AsyncOpenAI(api_key=self.api_key, base_url="https://api.groq.com/openai/v1")
            if AVAILABLE and self.api_key else None
        )

    async def generate(self, prompt: str, system_prompt: str = "") -> ModelResponse:
        return await self.chat([
            Message(role="system", content=system_prompt or "You are an expert security analyst."),
            Message(role="user", content=prompt)
        ])

    async def chat(self, messages: List[Message]) -> ModelResponse:
        if not self.client:
            return ModelResponse(content="", model_name=self.name, role=self.role, error="Not configured")
        try:
            r = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": m.role, "content": m.content} for m in messages],
            )
            return ModelResponse(content=r.choices[0].message.content or "", model_name=self.name, role=self.role)
        except Exception as e:
            return ModelResponse(content="", model_name=self.name, role=self.role, error=str(e))

    async def is_available(self) -> bool:
        return bool(AVAILABLE and self.api_key)
