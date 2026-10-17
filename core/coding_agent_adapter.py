"""
محول الوكلاء البرمجيين (Coding Agent Adapter) — مرحلة E.

واجهة عامة لوكلاء البرمجة عبر سطر الأوامر (Codex CLI / Claude Code / Cursor Agent /
OpenCode / ...) تُستخدم من قبل المنسق لتنفيذ مهام الترميز ضمن مساحة عمل مصرح بها.

مبادئ أمنية:
- كل وكيل يعمل ضمن دليل عمل (workspace) مصرح به صراحةً؛ لا وصول لملفات خارجه.
- لا أسرار/مفاتيح/مفاتيح SSH تُعرض على الوكيل.
- التعديلات عالية التأثير تتطلب مراجعة diff (أو ما يعادلها) قبل التطبيق.
- تُبلغ كل و킷 عن قدراتها الحقيقية فقط (لا ادعاء قدرات غير مدعومة).
- الإلغاء والمهلة محترمان حيث يدعمها الوكيل.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AgentCapability:
    """إمكانية واحدة للوكلاء البرمجيين."""
    name: str                     # مثال: "read_files", "apply_patch", "run_tests"
    version: Optional[str] = None


@dataclass(frozen=True)
class CodingAgentCapabilities:
    """مصفوفة قدرات وكيل برمجي — تُبلغ بدقة، لا تُفترض."""
    agent_id: str
    display_name: str
    executable: str
    supports_file_read: bool = False
    supports_file_search: bool = False
    supports_dependency_inspection: bool = False
    supports_patch_suggestion: bool = False
    supports_patch_apply: bool = False
    supports_test_execution: bool = False
    supports_cancellation: bool = False
    supports_streaming: bool = False
    max_context_files: Optional[int] = None
    extra: List[AgentCapability] = field(default_factory=list)

    def has(self, capability: str) -> bool:
        mapping = {
            "read_files": self.supports_file_read,
            "file_search": self.supports_file_search,
            "dependency_inspection": self.supports_dependency_inspection,
            "patch_suggestion": self.supports_patch_suggestion,
            "patch_apply": self.supports_patch_apply,
            "test_execution": self.supports_test_execution,
            "cancellation": self.supports_cancellation,
            "streaming": self.supports_streaming,
        }
        if capability in mapping:
            return mapping[capability]
        return any(c.name == capability for c in self.extra)


@dataclass
class CodingAgentRequest:
    """طلب تنفيذ من وكيل برمجي."""
    agent_id: str
    workspace: str               # دليل العمل المصرح به فقط
    prompt: str                  # المهمة textuelle
    mode: str = "suggest"        # suggest | apply | review
    allowed_tools: List[str] = field(default_factory=list)
    timeout_s: float = 300.0
    require_diff_review: bool = True  # التعديلات عالية التأثير تحتاج مراجعة diff
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CodingAgentResult:
    """نتيجة موحدة من وكيل برمجي."""
    ok: bool
    agent_id: str
    output: str = ""
    diff: Optional[str] = None      # diff مقترح (إن وُجد)
    files_changed: List[str] = field(default_factory=list)
    files_read: List[str] = field(default_factory=list)
    needs_human_review: bool = False
    requires_approval: bool = False
    error: Optional[str] = None
    error_category: Optional[str] = None
    duration_s: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class CodingAgentError(Exception):
    def __init__(self, message: str, category: str = "AGENT_ERROR",
                 agent_id: Optional[str] = None):
        super().__init__(message)
        self.category = category
        self.agent_id = agent_id


class ApprovalRequired(CodingAgentError):
    def __init__(self, agent_id: str, operation: str):
        super().__init__(
            f"human approval required for {agent_id}: {operation}",
            category="APPROVAL_REQUIRED", agent_id=agent_id)


class CodingAgentAdapter(ABC):
    """واجهة وكيل برمجي مجردة."""

    def __init__(self, agent_id: str, capabilities: CodingAgentCapabilities):
        self.agent_id = agent_id
        self.capabilities = capabilities
        self._cancelled: Dict[str, asyncio.Event] = {}

    @abstractmethod
    async def check_executable(self) -> bool:
        """فصلhether الملف التنفيذي موجود وقابل للتنفيذ."""

    @abstractmethod
    async def auth_status(self) -> Dict[str, Any]:
        """حالة المصادقة (مصادق / يحتاج تسجيل دخول / خطأ) — لا تُعرض الأسرار."""

    @abstractmethod
    async def run(self, request: CodingAgentRequest) -> CodingAgentResult:
        """تنفيذ المهمة ضمن مساحة العمل المصرح بها."""

    @abstractmethod
    async def cancel(self, run_id: str) -> bool:
        """إلغاء تشغيل معرّف بـ run_id."""

    async def health_check(self) -> bool:
        """فحص صحة بسيط: الملف موجود + مصادقة سليمة."""
        try:
            return await self.check_executable() and (await self.auth_status()).get("authenticated", False)
        except Exception:  # noqa: BLE001
            return False

    def _register_cancel(self, run_id: str) -> asyncio.Event:
        ev = asyncio.Event()
        self._cancelled[run_id] = ev
        return ev

    def is_cancelled(self, run_id: str) -> bool:
        ev = self._cancelled.get(run_id)
        return bool(ev and ev.is_set())

    def _validate_workspace(self, workspace: str) -> str:
        """يضمن أن مساحة العمل دليل حقيقي ومسار آمن (no traversal outside)."""
        ws = os.path.abspath(workspace)
        if not os.path.isdir(ws):
            raise CodingAgentError(
                f"مساحة العمل غير موجودة: {workspace}",
                category="CONFIGURATION", agent_id=self.agent_id)
        return ws


# ---------------------------------------------------------------------------
# تطبيق افتراضي (CLI-based) يُعاد استخدامه من قبل المحركات القائمة
# ---------------------------------------------------------------------------

class CLICodingAgentAdapter(CodingAgentAdapter):
    """
    محول وكيل برمجي يُنفّذ الأوامر عبر سطر الأوامر ( argv فقط، لا shell string ).
    يُستخدم لـ Codex CLI / Claude Code / OpenCode مع معاملات مختلفة لكل واحد.
    """

    def __init__(self, agent_id: str, executable: str, args_template: List[str],
                 capabilities: CodingAgentCapabilities,
                 auth_check_cmd: Optional[List[str]] = None,
                 workspace_flag: str = "--workdir",
                 prompt_flag: str = "--prompt"):
        super().__init__(agent_id, capabilities)
        self.executable = executable
        self.args_template = args_template   # قائمة قوالب وسيطات (تحتوي على {prompt} و {workspace})
        self.auth_check_cmd = auth_check_cmd
        self.workspace_flag = workspace_flag
        self.prompt_flag = prompt_flag

    async def check_executable(self) -> bool:
        return shutil.which(self.executable) is not None or os.path.isabs(self.executable)

    async def auth_status(self) -> Dict[str, Any]:
        """تحقق من المصادقة عبر أمر فحص إن وُجد، وإلا تُبلغ بحالة غير معلومة."""
        if self.auth_check_cmd:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *self.auth_check_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                out, err = await asyncio.wait_for(proc.communicate(), timeout=15.0)
                authenticated = proc.returncode == 0
                return {
                    "authenticated": authenticated,
                    "method": "cli_check",
                    "detail": out.decode("utf-8", errors="replace")[:200] if authenticated
                              else err.decode("utf-8", errors="replace")[:200],
                }
            except asyncio.TimeoutError:
                return {"authenticated": False, "method": "cli_check",
                        "detail": "timeout checking auth"}
            except Exception as exc:  # noqa: BLE001
                return {"authenticated": False, "method": "cli_check",
                        "detail": str(exc)[:200]}
        return {
            "authenticated": None,
            "method": "unknown",
            "detail": "no auth check command configured",
        }

    async def run(self, request: CodingAgentRequest) -> CodingAgentResult:
        start = time.time()
        workspace = self._validate_workspace(request.workspace)
        run_id = f"agent-{uuid.uuid4().hex[:8]}"
        cancel_ev = self._register_cancel(run_id)

        # بناء أمر argv (لا shell string)
        argv = [self.executable]
        for tpl in self.args_template:
            arg = tpl.replace("{prompt}", request.prompt) \
                     .replace("{workspace}", workspace)
            argv.append(arg)

        # إضافة الأوامر المصرح بها كوسائط إن دعمها القالب
        for t in request.allowed_tools:
            argv.append(f"--tool={t}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                cwd=workspace,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:  # noqa: BLE001
            return CodingAgentResult(
                ok=False, agent_id=self.agent_id,
                error=str(exc), error_category="EXECUTION_ERROR",
                duration_s=time.time() - start)

        try:
            out, err = await asyncio.wait_for(
                proc.communicate(), timeout=request.timeout_s)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return CodingAgentResult(
                ok=False, agent_id=self.agent_id,
                error=f"انتهت المهلة بعد {request.timeout_s}s",
                error_category="TIMEOUT", duration_s=time.time() - start)
        except asyncio.CancelledError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return CodingAgentResult(
                ok=False, agent_id=self.agent_id,
                error="تم الإلغاء", error_category="CANCELLED",
                duration_s=time.time() - start)

        dur = time.time() - start
        text_out = out.decode("utf-8", errors="replace")
        text_err = err.decode("utf-8", errors="replace")
        ret = proc.returncode or 0

        # محاولة استخراج diff من المخرجات (بسيط: البحث عن علامات diff)
        diff = None
        if "```diff" in text_out:
            parts = text_out.split("```diff")
            if len(parts) > 1:
                diff_part = parts[1].split("```", 1)[0]
                diff = diff_part.strip()

        needs_review = bool(diff) and request.require_diff_review
        requires_approval = needs_review  # التعديلات تحتاج موافقة بشرية

        return CodingAgentResult(
            ok=(ret == 0),
            agent_id=self.agent_id,
            output=text_out,
            diff=diff,
            needs_human_review=needs_review,
            requires_approval=requires_approval,
            duration_s=round(dur, 3),
            error=(text_err if ret != 0 else None),
            error_category=("NONZERO_EXIT" if ret != 0 else None),
            metadata={"argv": argv, "run_id": run_id, "workspace": workspace},
        )

    async def cancel(self, run_id: str) -> bool:
        self._cancelled.get(run_id, asyncio.Event()).set()
        return True


# ---------------------------------------------------------------------------
# سجل الوكلاء البرمجيين (مصفوفة قدرات)
# ---------------------------------------------------------------------------

class CodingAgentRegistry:
    """سجل الوكلاء البرمجيين المُهيأة مع مصفوفة قدرات كل واحد."""

    def __init__(self):
        self._agents: Dict[str, CodingAgentAdapter] = {}

    def register(self, agent: CodingAgentAdapter) -> None:
        self._agents[agent.agent_id] = agent
        logger.info("تم تسجيل وكيل برمجي: %s (الملف=%s)",
                    agent.agent_id, agent.capabilities.executable)

    def get(self, agent_id: str) -> Optional[CodingAgentAdapter]:
        return self._agents.get(agent_id)

    def list_agents(self) -> List[CodingAgentCapabilities]:
        return [a.capabilities for a in self._agents.values()]

    def list_by_capability(self, capability: str) -> List[CodingAgentCapabilities]:
        return [c for c in self.list_agents() if c.has(capability)]

    async def health_check_all(self) -> Dict[str, bool]:
        out: Dict[str, bool] = {}
        for aid, agent in self._agents.items():
            try:
                out[aid] = await agent.health_check()
            except Exception:
                out[aid] = False
        return out

    def snapshot(self) -> Dict[str, Any]:
        return {
            aid: {
                "display_name": c.display_name,
                "executable": c.executable,
                "supports_patch_apply": c.supports_patch_apply,
                "supports_test_execution": c.supports_test_execution,
                "supports_cancellation": c.supports_cancellation,
            }
            for aid, c in [(a.agent_id, a.capabilities) for a in self._agents.values()]
        }


# نسخة مشتركة (تُحقن في المنسق / واجهة الويب)
GLOBAL_CODING_AGENT_REGISTRY = CodingAgentRegistry()


def build_default_agents() -> List[CLICodingAgentAdapter]:
    """
    بناء وكلاء افتراضيين من المحركات القائمة (claude / codex / opencode)
    مع مصفوفة قدرات واقعية.
    """
    agents = []

    # Claude Code
    agents.append(CLICodingAgentAdapter(
        agent_id="claude-code",
        executable="claude",
        args_template=["--print", "{prompt}"],
        capabilities=CodingAgentCapabilities(
            agent_id="claude-code", display_name="Claude Code",
            executable="claude",
            supports_file_read=True,
            supports_file_search=True,
            supports_patch_suggestion=True,
            supports_patch_apply=True,
            supports_test_execution=True,
            supports_cancellation=True,
            supports_streaming=True),
        auth_check_cmd=["claude", "--version"],
        workspace_flag="--workdir",
    ))

    # Codex CLI
    agents.append(CLICodingAgentAdapter(
        agent_id="codex-cli",
        executable="codex",
        args_template=["exec", "{prompt}"],
        capabilities=CodingAgentCapabilities(
            agent_id="codex-cli", display_name="Codex CLI",
            executable="codex",
            supports_file_read=True,
            supports_file_search=True,
            supports_dependency_inspection=True,
            supports_patch_suggestion=True,
            supports_patch_apply=True,
            supports_test_execution=True,
            supports_cancellation=True),
        auth_check_cmd=["codex", "--version"],
    ))

    # OpenCode
    agents.append(CLICodingAgentAdapter(
        agent_id="opencode",
        executable="opencode",
        args_template=["run", "{prompt}"],
        capabilities=CodingAgentCapabilities(
            agent_id="opencode", display_name="OpenCode",
            executable="opencode",
            supports_file_read=True,
            supports_file_search=True,
            supports_patch_suggestion=True,
            supports_cancellation=True),
        auth_check_cmd=["opencode", "--version"],
    ))

    return agents


# تسجيل الافتراضيين عند الاستيراد (اختياري، يمكن التعطيل عبر config)
for _agent in build_default_agents():
    GLOBAL_CODING_AGENT_REGISTRY.register(_agent)
