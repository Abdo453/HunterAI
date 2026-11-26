"""Google Gemini Provider — Pure HTTP via httpx with no SDK dependencies"""
import json
import os
import httpx
from typing import Any, Dict, List
from core.llm.manifest import DEFAULT_GEMINI_MODEL
from models.base_model import BaseModel, Message, ModelResponse


class GeminiProvider(BaseModel):
    def __init__(self, model: str = DEFAULT_GEMINI_MODEL, role: str = "api_analyst"):
        super().__init__(name=model, role=role, description=f"Google Gemini {model}")
        self.model_name = model
        self.api_key = os.getenv("GEMINI_API_KEY", "")

    def _build_request(self, messages: List[Message]) -> tuple[Dict[str, Any], Dict[str, str]]:
        """Build native Gemini payload (separate systemInstruction) and x-goog-api-key header."""
        system_parts: List[str] = []
        contents: List[Dict[str, Any]] = []
        for m in messages:
            if m.role == "system":
                if m.content:
                    system_parts.append(m.content)
            else:
                gem_role = "model" if m.role == "assistant" else "user"
                contents.append({"role": gem_role, "parts": [{"text": m.content}]})

        if not contents:
            contents = [{"role": "user", "parts": [{"text": ""}]}]

        payload: Dict[str, Any] = {"contents": contents}
        if system_parts:
            payload["systemInstruction"] = {
                "parts": [{"text": "\n\n".join(system_parts)}]
            }

        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.api_key,
        }
        return payload, headers

    async def generate(self, prompt: str, system_prompt: str = "") -> ModelResponse:
        return await self.chat([
            Message(role="system", content=system_prompt or "You are an expert security analyst."),
            Message(role="user", content=prompt)
        ])

    async def chat(self, messages: List[Message]) -> ModelResponse:
        if not self.api_key:
            return ModelResponse(content="", model_name=self.name, role=self.role, error="GEMINI_API_KEY is not set")

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent"
        payload, headers = self._build_request(messages)

        try:
            async with httpx.AsyncClient(timeout=30, verify=True, trust_env=False) as client:
                r = await client.post(url, json=payload, headers=headers)
                if r.status_code == 200:
                    data = r.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                        return ModelResponse(content=text, model_name=self.name, role=self.role)
                return ModelResponse(content="", model_name=self.name, role=self.role, error=f"HTTP {r.status_code}: {r.text[:200]}")
        except Exception as e:
            return ModelResponse(content="", model_name=self.name, role=self.role, error=str(e))

    async def stream(self, messages: List[Message], on_token=None) -> ModelResponse:
        """Native Gemini SSE streaming (streamGenerateContent?alt=sse)."""
        if not self.api_key:
            return ModelResponse(content="", model_name=self.name, role=self.role, error="GEMINI_API_KEY is not set")

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model_name}:streamGenerateContent?alt=sse"
        )
        payload, headers = self._build_request(messages)
        parts: List[str] = []
        try:
            async with httpx.AsyncClient(timeout=120, verify=True, trust_env=False) as client:
                async with client.stream("POST", url, json=payload, headers=headers) as r:
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
                        for cand in data.get("candidates", []) or []:
                            for p in cand.get("content", {}).get("parts", []) or []:
                                tok = p.get("text", "")
                                if tok:
                                    parts.append(tok)
                                    if on_token:
                                        await on_token(tok)
            content = "".join(parts)
            return ModelResponse(content=content, model_name=self.name, role=self.role,
                                 error=None if content else "empty stream")
        except Exception as e:
            return ModelResponse(content="".join(parts), model_name=self.name, role=self.role, error=str(e))

    async def is_available(self) -> bool:
        return bool(self.api_key)
