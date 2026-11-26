"""
عميل MCP (Model Context Protocol) — مرحلة E + Phase 4 Hardening.
==================================================================
Adapted security primitives from PentesterFlow (commit ``0759d87``, Apache-2.0 License):
- ``mcpServerFingerprint`` / ``mcp_server_fingerprint`` (from ``src/tools/mcpServers.ts``):
  stable SHA-256 over spawn-relevant config fields (``command``, ``args``, ``env``)
  to detect silently-edited server definitions and re-trigger launch consent.
- ``boundContent`` / ``bound_content`` (from ``src/tools/mcp.ts``):
  recursive size/block/depth cap applied BEFORE JSON serialization so a hostile
  or compromised MCP server cannot cause memory exhaustion or stack overflow.

ضوابط أمنية:
- مخرجات خوادم MCP تُعامل كبيانات غير موثوقة وتُقيَّد حجماً وعمقاً وتُنقَّى بـ ``SecretSanitizer``.
- كل استدعاء أداة يمر بـ ``PolicyGate`` و ``StrictScopeEngine`` عند إرفاقهما (fail-closed).
- تشغيل خادم MCP عبر stdio يتحقق من بصمة الموافقة (SHA-256 launch consent) عند التفعيل.
- إشعار التهيئة القياسي ``notifications/initialized`` وفق MCP 2024-11-05.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Set, Tuple
from urllib.parse import urlparse

from core.mcp_config import MCPServerConfig, MCPServerStatus, MCPTransport
from core.secret_sanitizer import SecretSanitizer

logger = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2024-11-05"
MCP_RESULT_CHAR_CAP = 128 * 1024
MCP_MAX_CONTENT_BLOCKS = 200
MCP_MAX_DEPTH = 32


# ---------------------------------------------------------------------------
# PentesterFlow (Apache-2.0, commit 0759d87) adapted MCP hardening primitives
# ---------------------------------------------------------------------------

def mcp_server_fingerprint(server: MCPServerConfig | Mapping[str, Any]) -> str:
    """Stable SHA-256 fingerprint of spawn-relevant MCP server config fields
    (``command``, ``args``, ``env`` — everything stdio transport executes).

    Detects when a server definition has changed since the operator last
    approved it so silently-edited commands/args re-trigger launch consent.
    """
    if isinstance(server, Mapping):
        command = server.get("command") or ""
        args = list(server.get("args") or [])
        env = dict(server.get("env") or {})
    else:
        command = server.command or ""
        args = list(server.args or [])
        env = dict(server.env or {})

    material = json.dumps(
        {"command": command, "args": args, "env": env},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# CamelCase alias matching PentesterFlow's exported helper name
mcpServerFingerprint = mcp_server_fingerprint


def bound_content(
    content: Any,
    cap: int = MCP_RESULT_CHAR_CAP,
    *,
    max_blocks: int = MCP_MAX_CONTENT_BLOCKS,
    max_depth: int = MCP_MAX_DEPTH,
    _depth: int = 0,
) -> Any:
    """Recursively bound string lengths, sequence lengths, and nesting depth of
    untrusted MCP content BEFORE serialization."""
    if _depth >= max_depth:
        if isinstance(content, str):
            return content[:cap] if len(content) > cap else content
        if isinstance(content, (dict, list, tuple)):
            return "[... max depth exceeded ...]"
        return content

    if isinstance(content, str):
        return content[:cap] if len(content) > cap else content

    if isinstance(content, (list, tuple)):
        head = [
            bound_content(item, cap, max_blocks=max_blocks, max_depth=max_depth, _depth=_depth + 1)
            for item in content[:max_blocks]
        ]
        if len(content) > max_blocks:
            head.append(
                {
                    "type": "text",
                    "text": f"[... {len(content) - max_blocks} more content blocks truncated ...]",
                }
            )
        return head

    if isinstance(content, dict):
        items = list(content.items())
        out_dict = {
            str(k): bound_content(
                v, cap, max_blocks=max_blocks, max_depth=max_depth, _depth=_depth + 1
            )
            for k, v in items[:max_blocks]
        }
        if len(items) > max_blocks:
            out_dict["__truncated_keys__"] = len(items) - max_blocks
        return out_dict

    return content


# CamelCase alias matching PentesterFlow's exported helper name
boundContent = bound_content


def truncate_mcp_string(text: str, cap: int = MCP_RESULT_CHAR_CAP) -> str:
    if len(text) <= cap:
        return text
    return f"{text[:cap]}\n[... truncated {len(text) - cap} chars ...]"


class MCPConsentStore:
    """Tracks operator-approved SHA-256 MCP server fingerprints (in-memory or JSON file)."""

    def __init__(self, store_path: Optional[Path] = None) -> None:
        self._store_path = Path(store_path) if store_path else None
        self._approved: Dict[str, str] = {}
        if self._store_path and self._store_path.is_file():
            try:
                data = json.loads(self._store_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._approved = {str(k): str(v) for k, v in data.items()}
            except Exception as exc:
                logger.warning("Failed to load MCP consent store %s: %s", self._store_path, exc)

    def approve(self, server_id: str, fingerprint: str) -> None:
        self._approved[server_id] = fingerprint
        self._persist()

    def approve_config(self, config: MCPServerConfig | Mapping[str, Any]) -> str:
        sid = config["server_id"] if isinstance(config, Mapping) else config.server_id
        fp = mcp_server_fingerprint(config)
        self.approve(str(sid), fp)
        return fp

    def revoke(self, server_id: str) -> None:
        self._approved.pop(server_id, None)
        self._persist()

    def is_approved(self, server_id: str, fingerprint: str) -> bool:
        return self._approved.get(server_id) == fingerprint

    def _persist(self) -> None:
        if not self._store_path:
            return
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        self._store_path.write_text(
            json.dumps(self._approved, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _extract_target_from_args(arguments: Mapping[str, Any]) -> str:
    for key in ("target", "url", "uri", "host", "domain", "endpoint", "base_url"):
        val = arguments.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


@dataclass
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
    عميل MCP لخادم واحد مع ضوابط الموافقة (SHA-256 launch fingerprint)،
    وبوابة السياسة (PolicyGate)، ومحرك النطاق (StrictScopeEngine)،
    وتقييد/تنقية المخرجات (boundContent + SecretSanitizer).
    """

    def __init__(
        self,
        config: MCPServerConfig,
        *,
        policy_gate: Optional[Any] = None,
        scope_engine: Optional[Any] = None,
        consent_store: Optional[MCPConsentStore] = None,
        consent_callback: Optional[Callable[[str, str, MCPServerConfig], bool]] = None,
        require_launch_consent: bool = False,
        result_char_cap: int = MCP_RESULT_CHAR_CAP,
    ):
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
        self.policy_gate = policy_gate
        self.scope_engine = scope_engine
        self.consent_store = consent_store
        self.consent_callback = consent_callback
        self.require_launch_consent = bool(require_launch_consent or consent_store is not None or consent_callback is not None)
        self.result_char_cap = max(1024, int(result_char_cap))
        self.fingerprint: str = mcp_server_fingerprint(config)

    def verify_launch_consent(self) -> str:
        """Verify SHA-256 fingerprint launch consent before spawning a stdio server."""
        current_fp = mcp_server_fingerprint(self.config)
        self.fingerprint = current_fp
        if not self.require_launch_consent:
            return current_fp

        if self.consent_store and self.consent_store.is_approved(self.config.server_id, current_fp):
            return current_fp

        if self.consent_callback is not None:
            approved = bool(self.consent_callback(self.config.server_id, current_fp, self.config))
            if approved:
                if self.consent_store:
                    self.consent_store.approve(self.config.server_id, current_fp)
                return current_fp

        self._audit.append(
            {
                "event": "mcp_launch_consent_denied",
                "server_id": self.config.server_id,
                "fingerprint": current_fp,
                "timestamp": time.time(),
            }
        )
        raise MCPClientError(
            f"MCP server '{self.config.server_id}' launch consent required or config fingerprint changed ({current_fp[:12]})",
            category="CONSENT_REQUIRED",
            server_id=self.config.server_id,
        )

    def _enforce_call_policy(
        self, server_id: str, tool_name: str, arguments: Dict[str, Any]
    ) -> Optional[Tuple[str, str]]:
        """Evaluate ``PolicyGate`` and ``StrictScopeEngine`` (fail closed).

        Returns ``(error_category, reason)`` if denied, or ``None`` if allowed.
        """
        target = _extract_target_from_args(arguments)

        if self.policy_gate is not None:
            try:
                from core.control_plane.policy_gate import ActionCategory, ActionRequest

                req = ActionRequest(
                    category=ActionCategory.TERMINAL_COMMAND if not target else ActionCategory.HTTP_REQUEST,
                    target=target or "local_terminal",
                    url=target if target.startswith(("http://", "https://")) else None,
                    command=f"mcp:{server_id}::{tool_name}",
                    reason=f"MCPClient.call_tool:{server_id}::{tool_name}",
                    requested_by_model="mcp_client",
                    metadata={"server_id": server_id, "tool": tool_name},
                )
                decision = self.policy_gate.evaluate(req)
                if not decision.allowed:
                    return ("POLICY_DENIED", f"PolicyGate denied MCP call: {decision.reason}")
            except Exception as exc:
                return ("POLICY_ERROR", f"PolicyGate error (fail-closed): {exc}")

        if target:
            try:
                from core.scope_engine import ScopePolicy, StrictScopeEngine, validate_http_url_target

                in_scope = list(self.scope_engine.in_scope) if self.scope_engine is not None else None
                out_of_scope = list(self.scope_engine.out_of_scope) if self.scope_engine is not None else None
                allow_loopback = bool(
                    self.scope_engine is not None
                    and getattr(self.scope_engine.policy, "allow_private_ips_override", False)
                )
                fail_closed = bool(
                    self.scope_engine is not None
                    and getattr(self.scope_engine.policy, "fail_closed", False)
                )
                ok_url, url_reason = validate_http_url_target(
                    target,
                    in_scope=in_scope,
                    out_of_scope=out_of_scope,
                    allow_loopback=allow_loopback,
                    resolve_dns=False,
                    fail_closed=fail_closed,
                )
                if not ok_url:
                    return ("SCOPE_VIOLATION", f"SSRF/scheme invariant denied target '{target}': {url_reason}")

                parsed = urlparse(target if "://" in target else f"http://{target}")
                host = parsed.hostname or target
                if self.scope_engine is not None:
                    allowed, reason = self.scope_engine.is_allowed(
                        target=host,
                        path=parsed.path or "",
                        port=parsed.port,
                    )
                    if not allowed:
                        return ("SCOPE_VIOLATION", f"StrictScopeEngine denied target '{target}': {reason}")
                else:
                    # Always enforce inviolable checks (IMDS / loopback / reserved)
                    inv_engine = StrictScopeEngine(ScopePolicy(allowed_domains=[host]))
                    inv_ok, inv_reason = inv_engine.check_inviolable(host)
                    if not inv_ok:
                        return ("SCOPE_VIOLATION", f"Inviolable scope denied target '{target}': {inv_reason}")
            except Exception as exc:
                return ("SCOPE_ERROR", f"Scope validation error (fail-closed): {exc}")

        return None

    # ── الاتصال واليد쉐يك ──────────────────────────────────────────────

    async def connect(self) -> None:
        """اتصال بالخادم وإجراء handshake initialize + notifications/initialized."""
        async with self._lock:
            if self.status == MCPServerStatus.CONNECTED:
                return
            self.status = MCPServerStatus.CONNECTING
            self._retry_count = 0

        try:
            self.verify_launch_consent()
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
                break
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
        loop = asyncio.get_running_loop()
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
        """إجراء handshake initialize ثم إشعار notifications/initialized."""
        params = {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "hunterai", "version": "2.0.0"},
        }
        result = await self._send_request("initialize", params)
        self._capabilities = result.get("capabilities", {}) if isinstance(result, dict) else {}
        self._server_info = result.get("serverInfo", {}) if isinstance(result, dict) else {}

        # Standard MCP 2024-11-05 initialized notification
        await self._send_notification("notifications/initialized")

        if "tools" in (self._capabilities or {}):
            await self._list_tools()

    async def _list_tools(self) -> None:
        """استدعاء tools/list وتخزين الأدوات بـ namespace."""
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
        """فحص ما إذا كان الخادم متصلاً ويستجيب."""
        try:
            if self.status != MCPServerStatus.CONNECTED:
                await self.connect()
            await self._send_request("ping", {}, timeout_s=5.0)
            return True
        except Exception as exc:  # noqa: BLE001
            self.status = MCPServerStatus.ERROR
            logger.warning("فشل فحص صحة خادم MCP %s: %s",
                           self.config.server_id, exc)
            return False

    def list_tools(self) -> List[MCPToolInfo]:
        return list(self._tools.values())

    def get_tool(self, namespaced_name: str) -> Optional[MCPToolInfo]:
        return self._tools.get(namespaced_name)

    async def call_tool(self, namespaced_name: str,
                        arguments: Dict[str, Any],
                        timeout_s: Optional[float] = None) -> MCPCallResult:
        """استدعاء أداة MCP عبر tools/call مع فرض PolicyGate + StrictScopeEngine + boundContent + SecretSanitizer."""
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
        safe_args = dict(arguments or {})

        denial = self._enforce_call_policy(server_id, tool_name, safe_args)
        if denial is not None:
            err_cat, err_msg = denial
            self._audit.append({
                "event": "mcp_tool_denied",
                "server_id": server_id,
                "tool": tool_name,
                "category": err_cat,
                "reason": err_msg,
                "timestamp": time.time(),
            })
            return MCPCallResult(
                ok=False,
                server_id=server_id,
                tool_name=tool_name,
                is_error=True,
                error=err_msg,
                error_category=err_cat,
                duration_s=time.time() - start,
            )

        params = {"name": tool_name, "arguments": safe_args}

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
                error=SecretSanitizer.sanitize_text(str(exc)),
                error_category=exc.category,
                duration_s=dur)
        except Exception as exc:  # noqa: BLE001
            dur = time.time() - start
            return MCPCallResult(
                ok=False, server_id=server_id, tool_name=tool_name,
                error=SecretSanitizer.sanitize_text(str(exc)),
                error_category="EXECUTION_ERROR",
                duration_s=dur)

        dur = time.time() - start
        raw_content = result.get("content", []) if isinstance(result, dict) else []
        is_error = bool(result.get("isError", False)) if isinstance(result, dict) else False
        raw_structured = result.get("structuredContent") if isinstance(result, dict) else None

        # Bound BEFORE serialization/sanitization to defeat oversized or deeply nested payloads
        bounded_content = bound_content(raw_content, self.result_char_cap)
        sanitized_content = SecretSanitizer.sanitize_data(bounded_content)
        bounded_structured = (
            SecretSanitizer.sanitize_data(bound_content(raw_structured, self.result_char_cap))
            if raw_structured is not None
            else None
        )

        return MCPCallResult(
            ok=not is_error,
            server_id=server_id,
            tool_name=tool_name,
            content=sanitized_content if isinstance(sanitized_content, list) else [sanitized_content],
            structured=bounded_structured,
            is_error=is_error,
            duration_s=dur,
            metadata={"request_id": namespaced_name, "fingerprint": self.fingerprint},
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
            "fingerprint": self.fingerprint,
            "server_info": dict(self._server_info),
            "capabilities": dict(self._capabilities),
        }


# ---------------------------------------------------------------------------
# مدير العملاء المتعددين (multi-server)
# ---------------------------------------------------------------------------

class MCPClientManager:
    """
    يدير عدة عملاء MCP مع مساحات أسماء منفصلة (namespaces) لكل خادم.
    """

    def __init__(
        self,
        configs: List[MCPServerConfig],
        *,
        policy_gate: Optional[Any] = None,
        scope_engine: Optional[Any] = None,
        consent_store: Optional[MCPConsentStore] = None,
        require_launch_consent: bool = False,
    ):
        self._clients: Dict[str, MCPClient] = {}
        self._configs: Dict[str, MCPServerConfig] = {}
        for cfg in configs:
            if cfg.enabled:
                self._configs[cfg.server_id] = cfg
                self._clients[cfg.server_id] = MCPClient(
                    cfg,
                    policy_gate=policy_gate,
                    scope_engine=scope_engine,
                    consent_store=consent_store,
                    require_launch_consent=require_launch_consent,
                )

    async def connect_all(self) -> Dict[str, bool]:
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
        out: Dict[str, List[MCPToolInfo]] = {}
        for sid, client in self._clients.items():
            out[sid] = client.list_tools()
        return out

    def get_tool(self, namespaced_name: str) -> Optional[tuple]:
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
