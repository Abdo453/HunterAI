"""
سجل الأدوات المركب (Tool Registry) — Phase B.

يُوفّر طبقة تنظيمية فوق ``tools.tool_manager.ToolManager`` القائمة (لا يُستبدل):
كل أداة لها تعريف منظم (tool ID مستقر، مخطط دخل/مخرج، إذن مطلوب، تصنيف مخاطرة،
مهلة، حد أقصى للإخراج، whether approval required، whether enabled).

التنفيذ يتبع التسلسل الإلزامي من المواصفة:
  1. استقبال اقتراح استدعاء الأداة
  2. حل tool ID ضد سجل الأدوات المسجّل
  3. التحقق من الوسائط ضد المخطط
  4. التحقق من إذن العامل
  5. التحقق من النطاق المستهدف (إن كان ذا صلة)
  6. تطبيق سياسة المخاطرة
  7. طلب موافقة بشرية إذا لزم الأمر
  8. التنفيذ عبر back-end مناسب
  9. فرض المهلة وحدود الإخراج
  10. تنقية وتطبيع النتيجة
  11. تخزين حدث تدقيق مقصوص
  12. إرجاع النتيجة للعامل الطالب

ضوابط أمنية:
- النموذج لا يستطيع تنفيذ دالة لمجرد ابتكاس اسم أداة (يُرفض المجهول).
- لا يُقيّم أي سلسلة نموذجية ككود.
- لا يُدخل مدخلات غير موثوقة في أوامر shell كنصوص.
- تُستخدم مصفوفات وسيطات (argument arrays) للتنفيذ؛ shell string فقط عند
  आवश्यकता مع عدّاد أوامر مراقب.
- allowlist صريحة للملفات التنفيذية المعتمدة.
- لا تُكشف الأسرار في الأحداث أو السجلات.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import shlex
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from core.sandbox import LocalSandbox

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# تعريفات البيانات
# ---------------------------------------------------------------------------

class RiskLevel(str):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolCategory(str, Enum):
    """تصنيف الأدوات الأمنية."""
    RECON = "recon"
    DNS = "dns"
    HTTP = "http"
    PORTS = "ports"
    CRAWLING = "crawling"
    FUZZING = "fuzzing"
    JAVASCRIPT = "javascript"
    API = "api"
    VULN = "vuln"
    CLOUD = "cloud"
    REPORTING = "reporting"


@dataclass(frozen=True)
class ToolDefinition:
    """تعريف أداة منظم — الوحدة الأساسية للسجل."""
    tool_id: str                    # معرّف مستقر (مثل "nmap.scan")
    name: str                       # اسم بشري可读
    description: str
    input_schema: Dict[str, Any]    # مخطط دخل بسيط (type/required/properties/enum)
    output_schema: Optional[Dict[str, Any]] = None
    backend: str = "cli"            # "cli" | "mcp" | "builtin" | "http"
    executable: Optional[str] = None   # مسار الملف التنفيذي (لـ cli)
    allowed_executables: Sequence[str] = field(default_factory=list)  # allowlist
    required_permissions: Sequence[str] = field(default_factory=list) # أذونات العامل
    risk_level: str = RiskLevel.MEDIUM
    timeout_s: float = 60.0
    max_output_bytes: int = 1_000_000
    approval_required: bool = False
    enabled: bool = True
    scope_relevant: bool = False    # هل يحتاج فحص نطاق الهدف


@dataclass
class ToolResult:
    """نتيجة موحدة لتنفيذ أداة."""
    ok: bool
    tool_id: str
    output: Any = None
    raw_output: str = ""
    exit_code: Optional[int] = None
    duration_s: float = 0.0
    error: Optional[str] = None
    error_category: Optional[str] = None
    audit_event_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthContext:
    """سياق إذن لعامل يُطلب منه تنفيذ أداة."""
    worker_id: str
    worker_role: str
    granted_permissions: Sequence[str] = field(default_factory=list)
    in_scope_targets: Sequence[str] = field(default_factory=list)
    out_of_scope_targets: Sequence[str] = field(default_factory=list)
    approve_high_risk: bool = False   # هل لدى العامل صلاحية الموافقة على المخاطر العالية
    scope_enforcer: Optional[Any] = None  # مفرض نطاق الشبكة (إن وُجد)


class ToolError(Exception):
    """خطأ من سجل الأدوات مع تصنيف."""
    def __init__(self, message: str, category: str = "TOOL_ERROR",
                 tool_id: Optional[str] = None):
        super().__init__(message)
        self.category = category
        self.tool_id = tool_id


class ApprovalRequired(ToolError):
    """يُرفع عندما تتطلب الأداة موافقة بشرية ولم تُعطَ بعد."""
    def __init__(self, tool_id: str, operation: str):
        super().__init__(
            f"human approval required for {tool_id}: {operation}",
            category="APPROVAL_REQUIRED", tool_id=tool_id)


# ---------------------------------------------------------------------------
# واجهة الأداة
# ---------------------------------------------------------------------------

class Tool(ABC):
    """واجهة أداة موحدة — كل أداة مسجّلة تُطبّق هذه العقود."""

    def __init__(self, definition: ToolDefinition,
                 scope_enforcer: Optional[Any] = None,
                 sandbox: Optional[Any] = None):
        self.defn = definition
        self.scope_enforcer = scope_enforcer
        self.sandbox = sandbox

    @abstractmethod
    def describe(self) -> ToolDefinition:
        """إرجاع تعريف الأداة."""

    @abstractmethod
    def validate_input(self, arguments: Dict[str, Any]) -> None:
        """التحقق من الوسائط ضد المخطط؛ يرفع ToolError عند عدم الصلاحية."""

    @abstractmethod
    def authorize(self, ctx: AuthContext, arguments: Dict[str, Any]) -> None:
        """التحقق من إذن العامل والنطاق والسياسة؛ يرفع ToolError عند الرفض."""

    @abstractmethod
    async def execute(self, arguments: Dict[str, Any],
                      ctx: AuthContext) -> ToolResult:
        """تنفيذ الأداة وإرجاع نتيجة موحّدة."""

    @abstractmethod
    async def cancel(self, run_id: str) -> bool:
        """إلغاء تنفيذ قيد التنفيذ."""
        return False

    @abstractmethod
    async def health_check(self) -> bool:
        """فصلhether الأداة قابلة للتنفيذ (مثلاً الملف التنفيذي موجود)."""
        return False


# ---------------------------------------------------------------------------
# أداة سطر أوامر آمنة (الم backend الافتراضي)
# ---------------------------------------------------------------------------

class CliTool(Tool):
    """أداة تُنفّذ كProcess خارجي عبر مصفوفات وسيطات (لا shell strings)."""

    def describe(self) -> ToolDefinition:
        return self.defn

    def validate_input(self, arguments: Dict[str, Any]) -> None:
        schema = self.defn.input_schema or {}
        required = schema.get("required", [])
        for key in required:
            if key not in arguments:
                raise ToolError(
                    f"معامل مطلوب مفقود: {key}", category="VALIDATION",
                    tool_id=self.defn.tool_id)
        properties = schema.get("properties", {})
        for key, value in arguments.items():
            if key not in properties:
                raise ToolError(
                    f"معامل غير معروف: {key}", category="VALIDATION",
                    tool_id=self.defn.tool_id)
            expected = properties[key].get("type")
            if expected and not _type_ok(value, expected):
                raise ToolError(
                    f"نوع غير صحيح لـ {key}: متوقع {expected}",
                    category="VALIDATION", tool_id=self.defn.tool_id)
            enum_values = properties[key].get("enum")
            if enum_values is not None and value not in enum_values:
                raise ToolError(
                    f"قيمة غير مسموحة لـ {key}: {value}",
                    category="VALIDATION", tool_id=self.defn.tool_id)

    def authorize(self, ctx: AuthContext, arguments: Dict[str, Any]) -> None:
        # 1. إذن العامل
        for perm in self.defn.required_permissions:
            if perm not in ctx.granted_permissions:
                raise ToolError(
                    f"العامل {ctx.worker_id} لا يملك الإذن: {perm}",
                    category="PERMISSION_DENIED", tool_id=self.defn.tool_id)
        # 2. مخاطرة عالية تحتاج موافقة صريحة
        if self.defn.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) \
                and not ctx.approve_high_risk:
            raise ApprovalRequired(self.defn.tool_id, self.defn.name)
        # 3. نطاق الهدف (إن كان ذا صلة)
        if self.defn.scope_relevant:
            target = arguments.get("target") or arguments.get("url") or ""
            if target:
                enforcer = (ctx.scope_enforcer
                            or getattr(self, "scope_enforcer", None))
                if enforcer is not None:
                    allowed, reason = enforcer.enforce_target(target)
                    if not allowed:
                        raise ToolError(
                            f"الهدف خارج النطاق المصرح به: {target} ({reason})",
                            category="SCOPE_VIOLATION",
                            tool_id=self.defn.tool_id)
                elif not _target_in_scope(target, ctx):
                    raise ToolError(
                        f"الهدف خارج النطاق المصرح به: {target}",
                        category="SCOPE_VIOLATION", tool_id=self.defn.tool_id)

    async def execute(self, arguments: Dict[str, Any],
                      ctx: AuthContext) -> ToolResult:
        definition = self.defn
        exe = definition.executable
        if not exe:
            raise ToolError("لا يوجد ملف تنفيذي معرف للأداة",
                            category="CONFIGURATION", tool_id=definition.tool_id)

        # allowlist صريحة
        if definition.allowed_executables and exe not in definition.allowed_executables:
            raise ToolError(
                f"الملف التنفيذي غير مصرح به: {exe}",
                category="PERMISSION_DENIED", tool_id=definition.tool_id)

        # بناء 명령 كمصفوفة وسيطات (لا shell string)
        argv = self._build_argv(arguments)
        # Validation إضافية: لا مسارات traversal في الوسائط
        for part in argv:
            if ".." in str(part) or str(part).startswith("/"):
                raise ToolError(
                    f"وسيط محظور (مسار مطلق/transversal): {part}",
                    category="VALIDATION", tool_id=definition.tool_id)

        run_id = f"tool-{uuid.uuid4().hex[:8]}"
        # 8. التنفيذ عبر back-end مناسب (sandbox إن وُجد، وإلا تنفيذ مباشر آمن)
        sandbox = getattr(self, "sandbox", None) or LocalSandbox()
        try:
            sb_result = await sandbox.run(
                argv,
                timeout_s=definition.timeout_s,
                max_output_bytes=definition.max_output_bytes,
            )
            out = sb_result.stdout.encode("utf-8", errors="replace")
            err = sb_result.stderr.encode("utf-8", errors="replace")
            ret = sb_result.exit_code or 0
            dur = sb_result.duration_s
            sandbox_error = sb_result.error
            sandbox_category = sb_result.error_category
        except FileNotFoundError:
            return ToolResult(ok=False, tool_id=definition.tool_id,
                              error=f"الملف التنفيذي غير موجود: {exe}",
                              error_category="TOOL_UNAVAILABLE")
        except Exception as exc:
            return ToolResult(ok=False, tool_id=definition.tool_id,
                              error=str(exc), error_category="EXECUTION_ERROR")

        stdout_limited = _limit_bytes(out, definition.max_output_bytes)
        stderr_limited = _limit_bytes(err, definition.max_output_bytes)

        text_out = stdout_limited.decode("utf-8", errors="replace")
        text_err = stderr_limited.decode("utf-8", errors="replace")

        ok = ret == 0 and not text_err
        error = sandbox_error or (text_err if ret != 0 else None)
        error_category = sandbox_category or ("NONZERO_EXIT" if ret != 0 else None)
        return ToolResult(
            ok=ok, tool_id=definition.tool_id,
            output=text_out,
            raw_output=text_out,
            exit_code=ret,
            duration_s=round(dur, 3),
            error=error,
            error_category=error_category,
            metadata={
                "argv": argv,
                "stderr": text_err,
                "sandbox": type(sandbox).__name__,
            },
            audit_event_id=run_id,
        )

    async def cancel(self, run_id: str) -> bool:
        # الإلغاء الفعلي يتطلب الاحتفاظ بالمراجع إلى العمليات؛ تم تركه قابل للتوسيع.
        return False

    async def health_check(self) -> bool:
        exe = self.defn.executable
        if not exe:
            return False
        return shutil.which(exe) is not None

    # -- مساعدات داخلية --
    def _build_argv(self, arguments: Dict[str, Any]) -> List[str]:
        """يبني مصفوفة وسيطات من الوسائط مع تجنب shell injection."""
        exe = self.defn.executable
        argv = [exe]
        arg_map = self.defn.input_schema or {}
        properties = arg_map.get("properties", {})
        for key, value in arguments.items():
            prop = properties.get(key, {})
            flag = prop.get("cli_flag")
            if prop.get("cli_positional"):
                # وسيطة موقعية تُمرر كما هي (آمنة: ليست جزءاً من أمر shell)
                if flag:
                    argv.append(flag)
                if isinstance(value, list):
                    for item in value:
                        argv.append(str(item))
                else:
                    argv.append(str(value))
                continue
            if flag is None:
                flag = f"--{key}"
            if isinstance(value, bool):
                if value:
                    argv.append(flag)
            elif isinstance(value, list):
                argv.append(flag)
                for item in value:
                    argv.append(str(item))
            else:
                argv.append(flag)
                argv.append(str(value))
        return argv


# ---------------------------------------------------------------------------
# السجل المركزي
# ---------------------------------------------------------------------------

class ToolRegistry:
    """سجل أدوات مركب — مسجّل، أنظر، تحقّق، فوّض، نفّذ، اجلس."""

    def __init__(
        self,
        capability_matrix: Optional[Any] = None,
        tool_manager: Optional[Any] = None,
        config_path: Optional[str] = None,
    ):
        self._tools: Dict[str, Tool] = {}
        self._definitions: Dict[str, ToolDefinition] = {}
        self._audit: List[Dict[str, Any]] = []
        self._tool_manager = tool_manager
        self.capability_matrix = capability_matrix
        self.config_path = config_path
        self._register_default_tools()

    # ── التسجيل والاستعلام ───────────────────────────────────────────────
    def register(self, tool: Tool) -> None:
        definition = tool.describe()
        if not definition.tool_id:
            raise ToolError("أداة بدون tool_id لا يمكن تسجيلها",
                            category="CONFIGURATION")
        self._tools[definition.tool_id] = tool
        self._definitions[definition.tool_id] = definition
        logger.info("تم تسجيل الأداة: %s (خطر=%s)", definition.tool_id,
                    definition.risk_level)

    def get(self, tool_id: str) -> Optional[Tool]:
        return self._tools.get(tool_id)

    def get_tool(self, tool_id: str) -> Optional[Tool]:
        """توافقٍ للخلف مع المُستدعى القدامى (``reg.get_tool``)."""
        return self.get(tool_id)

    def is_action_allowed(self, tool_name: str) -> Tuple[bool, Optional[str]]:
        """يحقّق إن كانت الأداة مسموحة تحت مصفوفة القدرات الحالية (to match HEAD)."""
        t = self.get_tool(tool_name)
        if not t:
            # أدوات غير مسجّلة تُخضع لسياسة PolicyGate بدلاً من السجل
            return True, None
        defn = getattr(t, "defn", t)
        cm = self.capability_matrix
        active = bool(getattr(cm, "active_testing", False)) if cm else False
        requires_auth = bool(getattr(defn, "approval_required", False) or getattr(defn, "requires_authorization", False))
        if requires_auth and not active:
            return False, f"Tool '{getattr(defn, 'name', tool_name)}' requires explicit authorization (--authorized flag required)."
        if str(getattr(defn, "risk_level", "")).lower() == RiskLevel.HIGH and not active:
            return False, f"High-risk tool '{getattr(defn, 'name', tool_name)}' blocked because active testing is not authorized."
        return True, None

    def check_permissions(
        self, tool_id: str, project_permissions: Optional[List[str]] = None
    ) -> Tuple[bool, Optional[str]]:
        """تفويض الأداة حسب مصفوفة القدرات وصلاحيات المشروع (to match HEAD)."""
        allowed_by_cap, reason = self.is_action_allowed(tool_id)
        if not allowed_by_cap:
            return False, reason
        if project_permissions is not None:
            t = self.get_tool(tool_id)
            defn = getattr(t, "defn", t) if t else None
            tool_perms = list(getattr(defn, "required_permissions", []) or []) if defn else ["recon"]
            if not tool_perms:
                tool_perms = ["recon"]
            if not any(p in tool_perms for p in project_permissions):
                return False, f"المشروع يفتقر إلى الصلاحيات {tool_perms} للأداة '{tool_id}'."
        return True, None

    def _register_default_tools(self) -> None:
        """تسجيل الأدوات الأساسية (core) حتى يكون السجل صالحاً فور الإنشاء.

        يعيد السلوك الذي كان موجوداً قبل إعادة كتابة السجل (تسجيل افتراضي
        لـ nmap/httpx/subfinder ...) حتى لا تفشل بوابة GATE-02 على سجل فارغ.
        """
        core_tools = [
            # (tool_id, name, executable, risk_level, requires_authorization)
            ("nmap", "Network port scanner & service fingerprinter", "nmap", RiskLevel.MEDIUM, False),
            ("httpx", "HTTP probing & technology detection", "httpx", RiskLevel.LOW, False),
            ("subfinder", "Passive subdomain enumeration", "subfinder", RiskLevel.LOW, False),
            ("masscan", "Ultra-fast asynchronous port discovery", "masscan", RiskLevel.MEDIUM, False),
            ("naabu", "Fast SYN/CONNECT port scanner", "naabu", RiskLevel.MEDIUM, False),
            ("nuclei", "Vulnerability scanner with templated nuclei", "nuclei", RiskLevel.HIGH, True),
        ]
        for tool_id, name, executable, risk, requires_auth in core_tools:
            definition = ToolDefinition(
                tool_id=tool_id,
                name=name,
                description=f"{name} — core security scanner",
                input_schema={"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]},
                backend="cli",
                executable=executable,
                required_permissions=["recon"],
                risk_level=risk,
                timeout_s=300.0,
                approval_required=requires_auth,
                enabled=True,
                scope_relevant=True,
            )
            self.register(CliTool(definition))

    def require(self, tool_id: str) -> Tool:
        """جلب أداة أو رفع استثناء إن لم تكن مسجّلة (fail-closed)."""
        tool = self.get(tool_id)
        if tool is None:
            raise ToolError(f"أداة غير مسجّلة: {tool_id}",
                            category="UNKNOWN_TOOL", tool_id=tool_id)
        return tool

    def definition(self, tool_id: str) -> Optional[ToolDefinition]:
        return self._definitions.get(tool_id)

    def list_tools(self, *, enabled_only: bool = False) -> List[ToolDefinition]:
        out = []
        for tid, tool in self._tools.items():
            d = tool.describe()
            if enabled_only and not d.enabled:
                continue
            out.append(d)
        return sorted(out, key=lambda d: d.tool_id)

    def is_enabled(self, tool_id: str) -> bool:
        d = self._definitions.get(tool_id)
        return bool(d and d.enabled)

    # ── التحقق والتفويض والتنفيذ (التسلسل الإلزامي) ─────────────────────
    async def call_tool(self, tool_id: str, arguments: Dict[str, Any],
                        ctx: AuthContext,
                        approval_handler: Optional[Callable[[str, str],
                                                            bool]] = None) -> ToolResult:
        """
        تنفيذ أداة عبر التسلسل الإلزامي من المواصفة.
        approval_handler(tool_id, operation) -> bool يُستدعى فقط عند approval_required.
        """
        audit_id = f"audit-{uuid.uuid4().hex[:8]}"
        start = time.time()

        def audit(event: str, detail: Dict[str, Any]) -> None:
            self._audit.append({
                "audit_id": audit_id, "event": event,
                "tool_id": tool_id, "worker": ctx.worker_id,
                "timestamp": time.time(), **detail})

        # 1. استقبال الاقتراح (تمّ استلامه)
        # 2. حل tool ID ضد السجل
        tool = self.get(tool_id)
        if tool is None:
            audit("unknown_tool", {"reason": "not_registered"})
            raise ToolError(f"أداة غير مسجّلة: {tool_id}",
                            category="UNKNOWN_TOOL", tool_id=tool_id)
        definition = tool.describe()

        # 3. هل مفعلة؟
        if not definition.enabled:
            audit("disabled_tool", {})
            raise ToolError(f"الأداة معطلة: {tool_id}",
                            category="DISABLED", tool_id=tool_id)

        # 4. التحقق من الوسائط ضد المخطط
        try:
            tool.validate_input(arguments)
        except ToolError as exc:
            audit("validation_failed", {"reason": str(exc)})
            raise

        # 5. تفويض العامل + نطاق + سياسة مخاطرة
        try:
            tool.authorize(ctx, arguments)
        except ApprovalRequired as exc:
            # 7. طلب موافقة بشرية قبل التنفيذ
            if approval_handler is None:
                audit("approval_required_no_handler", {})
                raise
            try:
                if asyncio.iscoroutinefunction(approval_handler):
                    approved = await approval_handler(tool_id, definition.name)
                else:
                    approved = approval_handler(tool_id, definition.name)
            except Exception as exc:  # noqa: BLE001
                audit("approval_handler_error", {"reason": str(exc)})
                raise ToolError("فشل معالج الموافقة", category="APPROVAL_ERROR",
                                tool_id=tool_id) from exc
            if not approved:
                audit("approval_rejected", {})
                raise ToolError("تم رفض الموافقة البشرية",
                                category="APPROVAL_REJECTED", tool_id=tool_id)
            audit("approval_granted", {"operation": definition.name})
        except ToolError as exc:
            audit("authorization_failed", {"reason": str(exc)})
            raise

        # 6. (سياسة المخاطرة تُطبّق داخل authorize عبر risk_level)
        audit("authorized", {"risk_level": definition.risk_level})

        # 8. التنفيذ عبر back-end مناسب
        try:
            result = await tool.execute(arguments, ctx)
        except ToolError:
            raise
        except Exception as exc:  # noqa: BLE001
            audit("execution_exception", {"reason": str(exc)})
            return ToolResult(ok=False, tool_id=tool_id,
                              error=str(exc), error_category="EXECUTION_ERROR",
                              audit_event_id=audit_id,
                              metadata={"duration_s": time.time() - start})

        # 9. المهلة وحدود الإخراج تُطبّق داخل CliTool.execute
        # 10. تنقية النتيجة قبل الإرجاع (لا أسرار خام)
        sanitized = _redact_secrets(str(result.output or ""))
        result.output = sanitized
        result.raw_output = _redact_secrets(result.raw_output)
        result.audit_event_id = audit_id
        result.metadata["duration_s"] = round(time.time() - start, 3)

        # 11. حدث تدقيق مقصوص
        audit("executed", {
            "ok": result.ok, "exit_code": result.exit_code,
            "duration_s": result.metadata["duration_s"],
            "error": result.error,
        })

        # 12. إرجاع النتيجة
        return result

    def audit_log(self) -> List[Dict[str, Any]]:
        return list(self._audit)

    def health_check_all(self) -> Dict[str, bool]:
        out: Dict[str, bool] = {}
        for tid, tool in self._tools.items():
            try:
                out[tid] = asyncio.get_event_loop().run_until_complete(
                    tool.health_check())
            except Exception:
                out[tid] = False
        return out


# ---------------------------------------------------------------------------
# مساعدات داخلية
# ---------------------------------------------------------------------------

def _type_ok(value: Any, expected: Optional[str]) -> bool:
    if expected is None:
        return True
    if expected == "string":
        return isinstance(value, str)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    return True


def _target_in_scope(target: str, ctx: AuthContext) -> bool:
    """فحص بسيط للنطاق المستهدف ضد سياق العامل."""
    host = target.split("://", 1)[-1].split("/", 1)[0].split(":")[0].lower()
    for allowed in ctx.in_scope_targets:
        a = allowed.lower()
        if a == "*" or host == a or host.endswith("." + a.lstrip("*.")):
            return True
    for blocked in ctx.out_of_scope_targets:
        b = blocked.lower()
        if b == "*" or host == b or host.endswith("." + b.lstrip("*.")):
            return False
    # fail-closed: إن وُجد نطاق صريح والهدف لا يطابق أي قاعدة → مرفوض
    return False


def _limit_bytes(data: Optional[bytes], limit: int) -> bytes:
    if data is None:
        return b""
    if len(data) <= limit:
        return data
    return data[:limit] + b"\n...[output truncated]..."


_SECRET_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9]{10,})"),
    re.compile(r"(Bearer\s+[A-Za-z0-9._\-]{10,})"),
    re.compile(r"(ghp_[A-Za-z0-9]{10,})"),
    re.compile(r"(password\s*[:=]\s*\S+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*\S+)", re.IGNORECASE),
]


def _redact_secrets(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("***", text)
    return text


class CapabilityMatrix:
    """مصفوفة القدرات (مخزّن خفيف لبوابة القدرات).

    تُنشأ بـ ``CapabilityMatrix(authorized=bool)`` وتُستعمل من خط الأنابيب
    لتحديد إن كان التواصل النشط مسموحاً لهدف معيّن.yesi
    """

    def __init__(self, authorized: bool = False, **_: Any):
        self.authorized = bool(authorized)
        self.active_testing = bool(authorized)

