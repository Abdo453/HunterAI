"""
Tool Registry & Tool Definition Schemas
Defines structured contracts for all tools available to the HunterAI Brain.
Enforces clean schema validation, category separation (browser, burp, analyzer, artifact, cli),
and safe asynchronous dispatching.
"""
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Awaitable
from pydantic import BaseModel, Field


class ToolCategory(str, Enum):
    BROWSER = "browser"
    BURP = "burp"
    ANALYZER = "analyzer"
    ARTIFACT = "artifact"
    CLI = "cli"


class ToolDefinition(BaseModel):
    """تعريف عقد الأداة البرمجية المتاحة للـ Agent"""
    name: str                           # e.g., "browser.navigate", "burp.send_request"
    category: ToolCategory
    description: str
    parameters_schema: Dict[str, Any] = Field(default_factory=dict)
    returns_schema: Dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ToolRegistry:
    """
    سجل الأدوات المركزي:
    يسجل كافة الأدوات والـ Handlers المرتبطة بها ويوفر واجهة استدعاء موحدة
    """

    def __init__(self):
        self._tools: Dict[str, ToolDefinition] = {}
        self._handlers: Dict[str, Callable[..., Awaitable[Any]]] = {}

    def register_tool(
        self,
        tool_def: ToolDefinition,
        handler: Optional[Callable[..., Awaitable[Any]]] = None
    ):
        self._tools[tool_def.name] = tool_def
        if handler:
            self._handlers[tool_def.name] = handler

    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def list_tools(self, category: Optional[ToolCategory] = None) -> List[ToolDefinition]:
        if category:
            return [t for t in self._tools.values() if t.category == category]
        return list(self._tools.values())

    async def execute(self, tool_name: str, **kwargs) -> Any:
        if tool_name not in self._tools:
            raise ValueError(f"Tool '{tool_name}' is not registered in ToolRegistry.")

        handler = self._handlers.get(tool_name)
        if not handler:
            raise NotImplementedError(f"No executable handler attached to tool '{tool_name}'.")

        return await handler(**kwargs)
