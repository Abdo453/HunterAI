from abc import ABC, abstractmethod
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class Message:
    role: str       # "system" | "user" | "assistant"
    content: str


@dataclass
class ModelResponse:
    content: str
    model_name: str
    role: str
    tokens_used: int = 0
    error: Optional[str] = None


class BaseModel(ABC):
    def __init__(self, name: str, role: str, description: str):
        self.name = name
        self.role = role
        self.description = description

    @abstractmethod
    async def generate(self, prompt: str, system_prompt: str = "") -> ModelResponse:
        pass

    @abstractmethod
    async def chat(self, messages: List[Message]) -> ModelResponse:
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        pass
