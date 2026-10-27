"""
Context-Intensive Executor — وكيل التنفيذ المكثف بالسياق (المُحدّث)
=========================================================
ينفذ الأوامر عبر CommandExecutor (CommandKB + DeterministicFilter)
ويكتب الملاحظات إلى TaskClueCache دون أن يلوث ذاكرة التخطيط (TDG).
"""

from __future__ import annotations

import logging
import time
from typing import Optional, Dict, Any, List

from agents.security_intelligence.memory_manager import MemoryManager
from core.command_kb.registry import CommandRegistry, bootstrap_command_kb
from core.command_executor import CommandExecutor, CommandExecutionResult
from core.verification import DeterministicFilter
from core.command_kb.compatibility import EnvironmentCompatibilityChecker
from core.command_kb.models import CommandSafetyLevel

log = logging.getLogger("agents.orchestration.context_executor")


class ToolResult:
    """نتيجة تنفيذ أداة أو أمر (واجهة متوافقة مع GlobalOrchestrator)"""
    def __init__(
        self,
        success: bool,
        output: str = "",
        evidence: Optional[List[str]] = None,
        error: Optional[str] = None,
        tool: str = "unknown",
        command: str = "",
        target: str = "",
    ):
        self.success = success
        self.output = output
        self.evidence = evidence or []
        self.error = error
        self.tool = tool
        self.command = command
        self.target = target
        self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output,
            "evidence": self.evidence,
            "error": self.error,
            "tool": self.tool,
            "command": self.command,
            "target": self.target,
            "timestamp": self.timestamp,
        }


class ContextIntensiveExecutor:
    """
    مسؤوليات:
    1. استقبال مهمة من GlobalOrchestrator.
    2. اختيار الأمر الأنسب من CommandKB بناءً على عنوان المهمة.
    3. التحقق الحتمي عبر DeterministicFilter قبل التنفيذ.
    4. تنفيذ الأمر عبر CommandExecutor.
    5. كتابة النتيجة وملاحظات البيئة (clues) إلى TaskClueCache.
    6. إبلاغ GlobalOrchestrator بالإنجاز أو الفشل مع السبب.
    """

    def __init__(
        self,
        memory: MemoryManager,
        command_registry: Optional[CommandRegistry] = None,
        verification_filter: Optional[DeterministicFilter] = None,
        target: str = "unknown",
    ):
        self.memory = memory
        self.target = target
        self.command_registry = command_registry or bootstrap_command_kb()

        # إعداد محقّق التوافق والفلتر الحتمي
        compatibility_checker = EnvironmentCompatibilityChecker(
            open_ports={},
            discovered_endpoints=[],
            current_privileges=[],
        )
        self.verification_filter = verification_filter or DeterministicFilter(
            compatibility_checker=compatibility_checker,
            allowed_targets=[target] if target != "unknown" else [],
            block_destructive_by_default=True,
        )

        self.command_executor = CommandExecutor(
            command_registry=self.command_registry,
            verification_filter=self.verification_filter,
        )
        log.info(f"[EXEC] ContextIntensiveExecutor initialized for target {target}")

    # ------------------------------------------------------------------ #
    # التنفيذ الرئيسي
    # ------------------------------------------------------------------ #
    async def execute_task(
        self,
        task_title: str,
        task_description: str = "",
        tool_hint: Optional[str] = None,
        target: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ToolResult:
        """
        تنفيذ مهمة واحدة.
        """
        target = target or self.target
        context = context or {}
        task_id = context.get("task_id", "unknown")

        # ── الخطوة 1: اختيار الأمر الأنسب من CommandKB ──
        command_entry = self._select_command(task_title, tool_hint, target, context)
        if not command_entry:
            msg = f"No suitable command found in CommandKB for task: {task_title}"
            log.warning(f"[EXEC] {msg}")
            return ToolResult(
                success=False,
                output=msg,
                error="NO_COMMAND",
                tool="none",
                command=task_description,
                target=target,
            )

        # ── الخطوة 2: تجهيز placeholders للتنفيذ ──
        placeholders = {"target": target}
        if context.get("port"):
            placeholders["port"] = str(context["port"])
        if context.get("url"):
            placeholders["url"] = context["url"]
        if context.get("wordlist"):
            placeholders["wordlist"] = context["wordlist"]

        # ── الخطوة 3: التنفيذ عبر CommandExecutor (يتضمن DeterministicFilter) ──
        log.info(f"[EXEC] Executing {command_entry.tool} on {target}: {command_entry.description}")
        self.memory.task_clue.add_task_command(
            task_id=task_id,
            command=f"{command_entry.tool} {task_description}",
        )

        exec_result = await self.command_executor.execute_command(
            command_id=command_entry.id,
            target=target,
            placeholders=placeholders,
        )

        # ── الخطوة 4: تحويل النتيجة إلى ToolResult ──
        if exec_result.success:
            output = exec_result.stdout or exec_result.stderr or "Command executed successfully"
            evidence = [exec_result.stdout] if exec_result.stdout else []
            tool_result = ToolResult(
                success=True,
                output=output,
                evidence=evidence,
                tool=command_entry.tool,
                command=exec_result.rendered_command,
                target=target,
            )
        else:
            output = exec_result.stderr or exec_result.stdout or "Command failed"
            tool_result = ToolResult(
                success=False,
                output=output,
                error=exec_result.error or "execution_failed",
                tool=command_entry.tool,
                command=exec_result.rendered_command,
                target=target,
            )

        # ── الخطوة 5: كتابة الملاحظات إلى TaskClueCache ──
        self._record_clues(task_title, target, command_entry.tool, tool_result, context, exec_result)

        return tool_result

    # ------------------------------------------------------------------ #
    # اختيار الأمر من CommandKB
    # ------------------------------------------------------------------ #
    def _select_command(
        self,
        task_title: str,
        tool_hint: Optional[str],
        target: str,
        context: Dict[str, Any],
    ):
        """
        اختيار الأمر الأنسب من CommandKB بناءً على عنوان المهمة.
        """
        # إذا حُددت أداة Specifically، ابحث عن أوامرها
        if tool_hint:
            cmds = self.command_registry.find_by_tool(tool_hint)
            if cmds:
                return cmds[0]  # أخذ أول أمر متاح للأداة

        # Otherwise، ابحث عن أمر يتوافق مع عنوان المهمة
        title_lower = task_title.lower()
        for cmd in self.command_registry.all_commands():
            if any(tag in title_lower for tag in cmd.tags):
                return cmd
            if cmd.tool.lower() in title_lower:
                return cmd

        # fallback: أمر safe عام
        safe_cmds = self.command_registry.find_by_safety(CommandSafetyLevel.SAFE)
        if safe_cmds:
            return safe_cmds[0]

        return None

    # ------------------------------------------------------------------ #
    # تسجيل الأدلة (Clues) في الكاش المشترك
    # ------------------------------------------------------------------ #
    def _record_clues(
        self,
        task_title: str,
        target: str,
        tool: str,
        result: ToolResult,
        context: Dict[str, Any],
        exec_result: CommandExecutionResult,
    ) -> None:
        task_id = context.get("task_id", "unknown")

        # تحديث حالة المهمة في الكاش
        state = self.memory.task_clue.get_task_state(task_id)
        if state:
            if result.success:
                state.status = "done"
            else:
                state.status = "failed"
                state.failure_reason = result.error or "unknown"
            state.last_updated = time.time()

        # إذا نجح، استخرج أدلة من المخرجات
        if result.success and result.output:
            clue_type = self._infer_clue_type(tool, result.output)
            self.memory.task_clue.add_clue(
                target=target,
                source_tool=tool,
                clue_type=clue_type,
                content=result.output[:500],
                evidence_ref=[exec_result.command_id],
                related_task_ids=[task_id],
                confidence=0.85,
            )
            log.debug(f"[EXEC] Recorded clue ({clue_type}) for {target}")

        # إذا فشل، سجل في FailureEpisodicMemory للمراجعة
        if not result.success:
            self.memory.failure_episodic.record_failure(
                task_id=task_id,
                target=target,
                tool=tool,
                command=result.command,
                reason=result.error or "execution failed",
                evidence=[result.output] if result.output else [],
                context=context,
            )

    @staticmethod
    def _infer_clue_type(tool: str, output: str) -> str:
        output_lower = output.lower()
        if "open" in output_lower or "port" in output_lower:
            return "open_port"
        if "http" in output_lower or "server" in output_lower:
            return "service"
        if "vuln" in output_lower or "cve" in output_lower:
            return "vulnerability"
        if "parameter" in output_lower or "param" in output_lower:
            return "parameter"
        return "observation"
