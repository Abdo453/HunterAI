"""
تكوين خوادم MCP (Model Context Protocol) — مرحلة E.

يحدد schéma إعداد كل خادم MCP متصل بالنظام:
- النقل (stdio / HTTP)
- الأمر والوسائط (للخوادم القائمة على عملية محلية)
- نقطة النهاية والمصادقة (للخوادم الشبكية)
- الصلاحيات الممنوحة لأدوات الخادم
- المهلة ومحاولة إعادة الاتصال

كل إعداد يُValidate عند التحميل؛ لا تُخزن أسرار خام في هذا الملف —
تُقرأ من متغيرات البيئة أو مدير الأسرار في وقت التشغيل.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field, field_validator
    _HAS_PYDANTIC = True
except ImportError:  # pragma: no cover - fallback when pydantic missing
    _HAS_PYDANTIC = False


class MCPTransport(str, Enum):
    STDIO = "stdio"      # عملية محلية تتواصل عبر stdin/stdout
    HTTP = "http"        # خادم distant عبر HTTP (SSE / streamable)


class MCPServerStatus(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class MCPToolPermission:
    """إذن خاص بأداة من خادم MCP."""
    tool_name: str
    allowed: bool = True
    requires_approval: bool = False
    risk_level: str = "medium"   # low | medium | high | critical


@dataclass
class MCPServerConfig:
    """
    إعداد خادم MCP واحد.

    security notes:
    - ``command``/``args`` تُستخدم فقط مع النقل stdio وتُتحقق منها (allowlist للمسار التنفيذي).
    - ``env`` يُمرر فقط المتغيرات المصرح بها؛ الأسرار تُقرأ من متغيرات البيئة في وقت التشغيل.
    - network servers تُخضع لسياسة النطاق (ScopeEnforcer) قبل أي استدعاء.
    """
    server_id: str
    name: str
    transport: MCPTransport = MCPTransport.STDIO
    command: Optional[str] = None           # الملف التنفيذي (للحالات المحلية)
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    endpoint: Optional[str] = None          # نقطة النهاية (للنقل الشبكي)
    auth_token_env: Optional[str] = None    # اسم متغير البيئة الذي يحمل التوكن (لا القيمة)
    capabilities: List[str] = field(default_factory=list)  # ["tools", "resources", ...]
    tool_permissions: List[MCPToolPermission] = field(default_factory=list)
    timeout_s: float = 30.0
    max_retries: int = 3
    retry_backoff_s: float = 1.0
    enabled: bool = True

    def get_auth_token(self) -> Optional[str]:
        """قراءة توكن المصادقة من متغير البيئة في وقت التشغيل (لا يُخزن هنا)."""
        if not self.auth_token_env:
            return None
        return os.environ.get(self.auth_token_env)

    def effective_env(self) -> Dict[str, str]:
        """بيئة عملية الخادم: متغيرات آمنة فقط + ما يُصرح به صراحةً."""
        safe = {"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP"}
        env: Dict[str, str] = {}
        for k, v in os.environ.items():
            if k in safe:
                env[k] = v
        for k, v in self.env.items():
            kl = k.lower()
            if any(s in kl for s in ("secret", "key", "token", "password",
                                     "api_", "credential")):
                # الأسرار تُمرر عبر auth_token_env فقط، لا تُورث من env هذا الملف
                continue
            env[k] = v
        token = self.get_auth_token()
        if token and self.auth_token_env:
            env[self.auth_token_env] = token
        return env


# ---------------------------------------------------------------------------
# نماذج Pydantic للتحقق من ملفات الإعداد (إن وُجدت)
# ---------------------------------------------------------------------------

if _HAS_PYDANTIC:

    class MCPServerConfigModel(BaseModel):
        server_id: str
        name: str
        transport: str = "stdio"
        command: Optional[str] = None
        args: List[str] = Field(default_factory=list)
        env: Dict[str, str] = Field(default_factory=dict)
        endpoint: Optional[str] = None
        auth_token_env: Optional[str] = None
        capabilities: List[str] = Field(default_factory=list)
        tool_permissions: List[Dict[str, Any]] = Field(default_factory=list)
        timeout_s: float = 30.0
        max_retries: int = 3
        retry_backoff_s: float = 1.0
        enabled: bool = True

        @field_validator("transport")
        def _validate_transport(cls, v: str) -> str:
            if v not in ("stdio", "http"):
                raise ValueError("transport must be 'stdio' or 'http'")
            return v

        @field_validator("server_id")
        def _validate_server_id(cls, v: str) -> str:
            if not v or not v.replace("-", "").replace("_", "").isalnum():
                raise ValueError("server_id must be alphanumeric (with -/_ allowed)")
            return v

    class MCPConfigModel(BaseModel):
        servers: List[MCPServerConfigModel] = Field(default_factory=list)
        default_timeout_s: float = 30.0
        max_concurrent_servers: int = 5

    def load_mcp_config_from_dict(data: Dict[str, Any]) -> MCPConfigModel:
        return MCPConfigModel(**data)

    def load_mcp_config_from_file(path: str) -> MCPConfigModel:
        import json
        with open(path, "r", encoding="utf-8") as f:
            return MCPConfigModel(**json.load(f))

else:

    class MCPConfigModel:  # type: ignore[no-redef]
        """ stub عند عدم توفر pydantic """
        def __init__(self, **kwargs: Any):
            self.__dict__.update(kwargs)

    def load_mcp_config_from_dict(data: Dict[str, Any]) -> MCPConfigModel:
        return MCPConfigModel(**data)

    def load_mcp_config_from_file(path: str) -> MCPConfigModel:
        import json
        with open(path, "r", encoding="utf-8") as f:
            return MCPConfigModel(**json.load(f))
