"""Google Gemini Provider — Pure HTTP via httpx with no SDK dependencies"""
import os
import httpx
from typing import List
from models.base_model import BaseModel, Message, ModelResponse


class GeminiProvider(BaseModel):
    def __init__(self, model: str = "gemini-2.0-flash", role: str = "api_analyst"):
        super().__init__(name=model, role=role, description=f"Google Gemini {model}")
        self.model_name = model
        self.api_key = os.getenv("GEMINI_API_KEY", "")

    async def generate(self, prompt: str, system_prompt: str = "") -> ModelResponse:
        return await self.chat([
            Message(role="system", content=system_prompt or "You are an expert security analyst."),
            Message(role="user", content=prompt)
        ])

    async def chat(self, messages: List[Message]) -> ModelResponse:
        if not self.api_key:
            return ModelResponse(content="", model_name=self.name, role=self.role, error="GEMINI_API_KEY is not set")

        system = next((m.content for m in messages if m.role == "system"), "")
        user_msgs = [m.content for m in messages if m.role == "user"]
        combined_text = f"{system}\n\n" + "\n".join(user_msgs) if system else "\n".join(user_msgs)

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": combined_text}]}]
        }

        try:
            async with httpx.AsyncClient(timeout=30, trust_env=False) as client:
                r = await client.post(url, json=payload)
                if r.status_code == 200:
                    data = r.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        return ModelResponse(content=text, model_name=self.name, role=self.role)
                return ModelResponse(content="", model_name=self.name, role=self.role, error=f"HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            return ModelResponse(content="", model_name=self.name, role=self.role, error=str(e))

    async def is_available(self) -> bool:
        return bool(self.api_key)
