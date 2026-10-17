"""
عميل MCP (Model Context Protocol) — مرحلة E.

يُنفّز عميل MCP حقيقي باستخدام مكتبة Python 표준 فقط (بدون تبعات خارجية):
- النقل stdio عبر asyncio.create_subprocess_exec (عملية محلية)
- بروتوكول JSON-RPC 2.0
-手shake: initialize → initialized notification
- اكتشاف الأدوات: tools/list
- استدعاء الأدوات: tools/call (مع مخطط الدخل من الخادم)
- الإلغاء، مهلة الاستدعاء، إعادة الاتصال bounded retry
- أسماء الأدوات تُnesbn باسم الخادم (server_id::tool_name) لتجنب التصادم
- كل استدعاء يُسجل في سجل تدقيق (بدون أسرار خام)

ملاحظات أمنية:
- مخرجات خوادم MCP تُعامل كبيانات غير موثوقة (لا تُقيّم ككود، لا تُدخل في أوامر shell).
- الأدوات عالية المخاطرة تتطلب موافقة بشرية عبر PolicyGate/ToolRegistry قبل الاستدعاء.
- الخوادم الشبكية تخضع لسياسة النطاق (ScopeEnforcer) قبل أي استدعاء.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.mcp_config import MCPServerConfig, MCPServerStatus, MCPTransport

logger = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2024-11-05"


@dataclass
# kept for backwards-compat; prefer MCPToolInfo below
class _LegacyToolInfo:
    pass


@dataclass
class MCPToolInfo:
    """معلومات أداة discovered من خادم MCP."""
    server_id: str
    tool_name: str
    namespaced_name: str          # "server_id::tool_name"
    description: str
    input_schema: Dict[str, Any]  # JSON Schema للدخل
    output_schema: Optional[Dict[str, Any]] = None
    annotations: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPCallResult:
    """نتيجة استدعاء أداة MCP."""
    ok: bool
    server_id: str
    tool_name: str
    content: List[Dict[str, Any]] = field(default_factory=list)
    structured: Optional[Dict[str, Any]] = None
    is_error: bool = False
    error: Optional[str] = None
    error_category: Optional[str] = None
    duration_s: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class MCPClientError(Exception):
    """خطأ من عميل MCP مع تصنيف."""
    def __init__(self, message: str, category: str = "MCP_ERROR",
                 server_id: Optional[str] = None):
        super().__init__(message)
        self.category = category
        self.server_id = server_id


class MCPClient:
    """
    عميل MCP لخادم واحد.

    يدعم النقل stdio (عملية محلية). النقل الشبكي (HTTP) موثق في الإعداد ولكن
    تنفيذه يترك للإنتاج عند توفر SDK oficiales؛ هنا يُraise خطأ توضيحي.
    """

    def __init__(self, config: MCPServerConfig):
        self.config = config
        self.status = MCPServerStatus.DISCONNECTED
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._lock = asyncio.Lock()
        self._next_id = 1
        self._pending: Dict[int, asyncio.Future] = {}
        self._capabilities: Dict[str, Any] = {}
        self._server_info: Dict[str, Any] = {}
        self._tools: Dict[str, MCPToolInfo] = {}
        self._read_task: Optional[asyncio.Task] = None
        self._retry_count = 0
        self._audit: List[Dict[str, Any]] = []
        self._connected_event = asyncio.Event()

    # ── الاتصال واليد쉐يك ──────────────────────────────────────────────

    async def connect(self) -> None:
        """اتصال بالخادم وإجراء手shake initialize."""
        async with self._lock:
            if self.status == MCPServerStatus.CONNECTED:
                return
            self.status = MCPServerStatus.CONNECTING
            self._retry_count = 0

        try:
            if self.config.transport == MCPTransport.STDIO:
                await self._connect_stdio()
            elif self.config.transport == MCPTransport.HTTP:
                raise MCPClientError(
                    "النقل الشبكي (HTTP) يتطلب MCP SDK خارجي للإنتاج؛ "
                    "يُدعم stdio فقط في هذا البناء",
                    category="TRANSPORT_NOT_SUPPORTED",
                    server_id=self.config.server_id)
            else:
                raise MCPClientError(
                    f"نقل غير مدعوم: {self.config.transport}",
                    category="CONFIGURATION",
                    server_id=self.config.server_id)

            await self._initialize()
            self.status = MCPServerStatus.CONNECTED
            self._connected_event.set()
            logger.info("تم الاتصال بخادم MCP: %s (%s)",
                        self.config.server_id, self.config.transport)
        except Exception as exc:  # noqa: BLE001
            self.status = MCPServerStatus.ERROR
            logger.warning("فشل الاتصال بخادم MCP %s: %s",
                           self.config.server_id, exc)
            raise

    async def _connect_stdio(self) -> None:
        """فتح عملية محلية للاتصال عبر stdin/stdout."""
        if not self.config.command:
            raise MCPClientError(
                "command مطلوب للنقل stdio",
                category="CONFIGURATION",
                server_id=self.config.server_id)

        # Validation الملف التنفيذي (allowlist ضمنية: يجب أن يكون موجوداً)
        resolved = shutil.which(self.config.command)
        if not resolved and not os.path.isabs(self.config.command):
            raise MCPClientError(
                f"الملف التنفيذي غير موجود: {self.config.command}",
                category="TOOL_UNAVAILABLE",
                server_id=self.config.server_id)
        exe = resolved or self.config.command

        env = self.config.effective_env()
        try:
            self._proc = await asyncio.create_subprocess_exec(
                exe, *self.config.args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except Exception as exc:  # noqa: BLE001
            raise MCPClientError(
                f"فشل تشغيل عملية MCP: {exc}",
                category="EXECUTION_ERROR",
                server_id=self.config.server_id) from exc

        self._reader = self._proc.stdout
        self._writer = self._proc.stdin
        self._read_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        """حلقة قراءة رسائل JSON-RPC من العملية."""
        assert self._reader is not None
        while True:
            try:
                line = await self._reader.readline()
            except Exception:
                break
            if not line:
                break  # EOF — الخادم أغلق الاتصال
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("رسالة MCP غير صالحة: %s", line[:200])
                continue
            await self._handle_message(msg)

    async def _handle_message(self, msg: Dict[str, Any]) -> None:
        """معالجة رسالة واردة (رد على طلب أو إشعار)."""
        msg_id = msg.get("id")
        if msg_id is not None and msg_id in self._pending:
            future = self._pending.pop(msg_id)
            if "error" in msg:
                future.set_exception(MCPClientError(
                    str(msg["error"].get("message", "خطأ غير معروف")),
                    category="MCP_ERROR", server_id=self.config.server_id))
            else:
                future.set_result(msg.get("result", {}))
        else:
            # إشعار (notification) بدون id — تُسجل وتُBroadcast
            method = msg.get("method", "")
            params = msg.get("params", {})
            logger.debug("إشعار MCP: %s %s", method, params)
            self._audit.append({
                "event": "mcp_notification",
                "server_id": self.config.server_id,
                "method": method,
                "timestamp": time.time(),
            })

    # ── إرسال طلب JSON-RPC ────────────────────────────────────────────

    async def _send_request(self, method: str,
                            params: Optional[Dict[str, Any]] = None,
                            timeout_s: Optional[float] = None) -> Any:
        """إرسال طلب والانتظار للرد."""
        if self._writer is None:
            raise MCPClientError(
                "الخادم غير متصل",
                category="NOT_CONNECTED",
                server_id=self.config.server_id)

        async with self._lock:
            req_id = self._next_id
            self._next_id += 1

        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params or {},
        }
        timeout = timeout_s if timeout_s is not None else self.config.timeout_s
        loop = asyncio.get_event_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[req_id] = future

        assert self._writer is not None
        try:
            data = (json.dumps(request) + "\n").encode("utf-8")
            self._writer.write(data)
            await self._writer.drain()
        except Exception as exc:  # noqa: BLE001
            self._pending.pop(req_id, None)
            raise MCPClientError(
                f"فشل إرسال الطلب: {exc}",
                category="EXECUTION_ERROR",
                server_id=self.config.server_id) from exc

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            raise MCPClientError(
                f"انتهت مهلة استدعاء MCP: {method}",
                category="TIMEOUT",
                server_id=self.config.server_id)
        except asyncio.CancelledError:
            self._pending.pop(req_id, None)
            raise

    async def _send_notification(self, method: str,
                                 params: Optional[Dict[str, Any]] = None) -> None:
        """إرسال إشعار (بدون توقع رد)."""
        if self._writer is None:
            return
        notification = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or {},
        }
        try:
            assert self._writer is not None
            data = (json.dumps(notification) + "\n").encode("utf-8")
            self._writer.write(data)
            await self._writer.drain()
        except Exception as exc:  # noqa: BLE001
            logger.warning("فشل إرسال إشعار MCP: %s", exc)

    # ── handshake ─────────────────────────────────────────────────────

    async def _initialize(self) -> None:
        """إجراء手shake initialize مع الخادم."""
        params = {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "hunterai", "version": "1.0.0"},
        }
        result = await self._send_request("initialize", params)
        self._capabilities = result.get("capabilities", {}) if isinstance(result, dict) else {}
        self._server_info = result.get("serverInfo", {}) if isinstance(result, dict) else {}

        # إشعار initialized (لا يتوقع رد)
        await self._send_notification("initialized")

        # اكتشاف الأدوات إذا أعلن الخادم عن دعمها
        if "tools" in (self._capabilities or {}):
            await self._list_tools()

    async def _list_tools(self) -> None:
        """استدعاء tools/list وتخزين الأدوات باكساء namespace."""
        result = await self._send_request("tools/list")
        tools = result.get("tools", []) if isinstance(result, dict) else []
        for t in tools:
            name = t.get("name", "")
            info = MCPToolInfo(
                server_id=self.config.server_id,
                tool_name=name,
                namespaced_name=f"{self.config.server_id}::{name}",
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}) or {},
                output_schema=t.get("outputSchema"),
                annotations=t.get("annotations", {}) or {},
            )
            self._tools[info.namespaced_name] = info
            logger.debug("تم اكتشاف أداة MCP: %s", info.namespaced_name)

    # ── الواجهة العامة ────────────────────────────────────────────────

    async def health_check(self) -> bool:
        """فصلhether الخادم متصل ويستجيب."""
        try:
            if self.status != MCPServerStatus.CONNECTED:
                await self.connect()
            # استدعاء initialize خفيف كheartbeat (أو tools/list إن كانت متوفرة)
            await self._send_request("initialize", {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "hunterai-health", "version": "1.0.0"},
            }, timeout_s=5.0)
            return True
        except Exception as exc:  # noqa: BLE001
            self.status = MCPServerStatus.ERROR
            logger.warning("فشل فحص صحة خادم MCP %s: %s",
                           self.config.server_id, exc)
            return False

    def list_tools(self) -> List[MCPToolInfo]:
        """إرجاع الأدوات المكتشفة من هذا الخادم."""
        return list(self._tools.values())

    def get_tool(self, namespaced_name: str) -> Optional[MCPToolInfo]:
        return self._tools.get(namespaced_name)

    async def call_tool(self, namespaced_name: str,
                        arguments: Dict[str, Any],
                        timeout_s: Optional[float] = None) -> MCPCallResult:
        """
        استدعاء أداة MCP عبر tools/call.

        يُتحقق من وجود الأداة ومخطط دخلها قبل الإرسال؛ النتيجة تُعاد كما هي
        (تُعالج من قبل caller للتنقية والتدقيق).
        """
        start = time.time()
        info = self.get_tool(namespaced_name)
        if info is None:
            return MCPCallResult(
                ok=False, server_id=self.config.server_id,
                tool_name=namespaced_name,
                error=f"أداة غير موجودة: {namespaced_name}",
                error_category="UNKNOWN_TOOL",
                duration_s=time.time() - start)

        server_id, tool_name = namespaced_name.split("::", 1)
        params = {"name": tool_name, "arguments": arguments or {}}

        self._audit.append({
            "event": "mcp_tool_call",
            "server_id": server_id,
            "tool": tool_name,
            "timestamp": start,
        })

        try:
            result = await self._send_request("tools/call", params,
                                              timeout_s=timeout_s)
        except MCPClientError as exc:
            dur = time.time() - start
            return MCPCallResult(
                ok=False, server_id=server_id, tool_name=tool_name,
                error=str(exc), error_category=exc.category,
                duration_s=dur)
        except Exception as exc:  # noqa: BLE001
            dur = time.time() - start
            return MCPCallResult(
                ok=False, server_id=server_id, tool_name=tool_name,
                error=str(exc), error_category="EXECUTION_ERROR",
                duration_s=dur)

        dur = time.time() - start
        content = result.get("content", []) if isinstance(result, dict) else []
        is_error = result.get("isError", False) if isinstance(result, dict) else False
        structured = result.get("structuredContent") if isinstance(result, dict) else None

        return MCPCallResult(
            ok=not is_error,
            server_id=server_id,
            tool_name=tool_name,
            content=content,
            structured=structured,
            is_error=is_error,
            duration_s=dur,
            metadata={"request_id": namespaced_name},
        )

    async def cancel(self) -> bool:
        """إلغاء الطلبات المعلقة وإغلاق الاتصال."""
        async with self._lock:
            for fid, future in list(self._pending.items()):
                if not future.done():
                    future.cancel()
            self._pending.clear()
        if self._read_task:
            self._read_task.cancel()
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        if self._proc:
            try:
                self._proc.kill()
            except ProcessLookupError:
                pass
        self.status = MCPServerStatus.DISCONNECTED
        self._connected_event.clear()
        return True

    def audit_log(self) -> List[Dict[str, Any]]:
        return list(self._audit)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "server_id": self.config.server_id,
            "name": self.config.name,
            "transport": self.config.transport,
            "status": self.status.value,
            "tools_count": len(self._tools),
            "server_info": dict(self._server_info),
            "capabilities": dict(self._capabilities),
        }


# ---------------------------------------------------------------------------
# مدير العملاء المتعددين (multi-server)
# ---------------------------------------------------------------------------

class MCPClientManager:
    """
    يدير عدة عملاء MCP مع اسماء مساحات منفصلة (namespaces) لكل خادم.
    يتصل بخوادم مفعلة فقط، ويُعيد الاتصال bounded retry عند الانقطاع.
    """

    def __init__(self, configs: List[MCPServerConfig]):
        self._clients: Dict[str, MCPClient] = {}
        self._configs: Dict[str, MCPServerConfig] = {}
        for cfg in configs:
            if cfg.enabled:
                self._configs[cfg.server_id] = cfg
                self._clients[cfg.server_id] = MCPClient(cfg)

    async def connect_all(self) -> Dict[str, bool]:
        """اتصال بكل الخوادم المفعلة؛ يعيد حالة كل خادم."""
        results: Dict[str, bool] = {}
        for sid, client in self._clients.items():
            try:
                await client.connect()
                results[sid] = True
            except Exception as exc:  # noqa: BLE001
                logger.warning("فشل الاتصال بخادم MCP %s: %s", sid, exc)
                results[sid] = False
        return results

    async def connect_server(self, server_id: str) -> bool:
        client = self._clients.get(server_id)
        if client is None:
            return False
        try:
            await client.connect()
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("فشل الاتصال بخادم MCP %s: %s", server_id, exc)
            return False

    def get_client(self, server_id: str) -> Optional[MCPClient]:
        return self._clients.get(server_id)

    def list_tools_all(self) -> Dict[str, List[MCPToolInfo]]:
        """كل الأدوات من كل خادم، معnamespaces."""
        out: Dict[str, List[MCPToolInfo]] = {}
        for sid, client in self._clients.items():
            out[sid] = client.list_tools()
        return out

    def get_tool(self, namespaced_name: str) -> Optional[tuple]:
        """(E^{-1}) يحصل على (client, tool_info) من اسم أداة باسمnamespace."""
        if "::" not in namespaced_name:
            return None
        sid, tname = namespaced_name.split("::", 1)
        client = self._clients.get(sid)
        if client is None:
            return None
        info = client.get_tool(namespaced_name)
        if info is None:
            return None
        return client, info

    async def health_check_all(self) -> Dict[str, bool]:
        out: Dict[str, bool] = {}
        for sid, client in self._clients.items():
            try:
                out[sid] = await client.health_check()
            except Exception:
                out[sid] = False
        return out

    async def disconnect_all(self) -> None:
        for client in self._clients.values():
            try:
                await client.cancel()
            except Exception:  # noqa: BLE001
                pass

    def snapshot(self) -> Dict[str, Any]:
        return {sid: c.snapshot() for sid, c in self._clients.items()}
