"""Base Agent — الكلاس الأساسي"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from tools.tool_manager import ToolManager


@dataclass
class AgentTask:
    target: str
    mode: str = "auto"
    session_id: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    agent_name: str
    target: str
    findings: List[Dict] = field(default_factory=list)
    raw_output: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    success: bool = True


class BaseAgent(ABC):
    def __init__(self, name: str, description: str, tool_manager: ToolManager,
                 progress_callback: Optional[Callable] = None):
        self.name = name
        self.description = description
        self.mgr = tool_manager
        self.cb = progress_callback

    async def emit(self, event: str, data: dict):
        if self.cb:
            try:
                await self.cb({"agent": self.name, "event": event, **data})
            except Exception:
                pass

    @abstractmethod
    async def run(self, task: AgentTask) -> AgentResult:
        pass
