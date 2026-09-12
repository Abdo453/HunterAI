"""Anthropic Provider — Claude"""
import os
from typing import List
from models.base_model import BaseModel, Message, ModelResponse

try:
    import anthropic as sdk
    AVAILABLE = True
except ImportError:
    AVAILABLE = False


class AnthropicProvider(BaseModel):
    def __init__(self, model: str = "claude-3-5-sonnet-20241022", role: str = "api_analyst"):
        super().__init__(name=model, role=role, description=f"Anthropic {model}")
        self.model = model
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "")

    async def generate(self, prompt: str, system_prompt: str = "") -> ModelResponse:
        return await self.chat([
            Message(role="system", content=system_prompt or "You are an expert security analyst."),
            Message(role="user", content=prompt)
        ])

    async def chat(self, messages: List[Message]) -> ModelResponse:
        if not AVAILABLE or not self.api_key:
            return ModelResponse(content="", model_name=self.name, role=self.role, error="Not configured")
        try:
            client = sdk.AsyncAnthropic(api_key=self.api_key)
            system = next((m.content for m in messages if m.role == "system"), "")
            user_msgs = [{"role": m.role, "content": m.content} for m in messages if m.role != "system"]
            r = await client.messages.create(model=self.model, max_tokens=4096, system=system, messages=user_msgs)
            content = r.content[0].text if r.content else ""
            return ModelResponse(content=content, model_name=self.name, role=self.role)
        except Exception as e:
            return ModelResponse(content="", model_name=self.name, role=self.role, error=str(e))

    async def is_available(self) -> bool:
        return bool(AVAILABLE and self.api_key)
