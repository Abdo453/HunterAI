"""محرك OpenAI Codex CLI.

codex exec يستقبل مهمة واحدة ويعيد JSONL.
العزل الأصلي: --sandbox read-only|workspace-write|danger-full-access.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from engines.base import EngineDriver
from engines.types import EngineResult, LaunchContext, StreamStep


class CodexDriver(EngineDriver):
    name = "codex"
    display_name = "OpenAI Codex"
    env_bin_override = "HUNTER_CODEX_BIN"

    secure_prompt_transport = True
    persistent_stdin_prompt = False
    offline_web_isolation = True   # غياب --search = لا ويب (opt-in)
    supports_resume = True
    supports_streaming = True

    NATIVE_SANDBOX_MODES = ("read-only", "workspace-write", "danger-full-access")

    def validate_launch(self, launch: LaunchContext) -> None:
        mode = (launch.sandbox_mode or "").strip()
        if mode and mode not in self.NATIVE_SANDBOX_MODES:
            raise ValueError(f"codex: وضع sandbox غير مدعوم: {mode!r}")

    def build_execute(
        self, prompt: str, session: Optional[str] = None, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        launch = launch or LaunchContext()
        self.validate_launch(launch)
        argv: List[str] = [self.bin, "exec", "--json"]
        if launch.model:
            argv += ["-m", launch.model]
        if launch.sandbox_mode:
            argv += ["--sandbox", launch.sandbox_mode]
        elif not launch.interactive:
            # وضع آمن افتراضي للوكلاء: قراءة فقط إلا если طُلب غير ذلك صراحة
            argv += ["--sandbox", "read-only"]
        if web_access:
            argv += ["--search"]
        if session:
            argv += ["--last", ""]  # placeholder؛ codex يستأنف عبر resume أدناه
            argv = argv[:-2]
        argv += ["--", prompt]
        return argv

    def build_execute_stdin(
        self, prompt: str, session: Optional[str] = None, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        # codex exec يقبل الـ prompt كموقع آخر؛ stdin piping غير مضمون在此 — نرجع غير مدعوم
        from engines.base import SecurePromptUnsupported
        raise SecurePromptUnsupported("codex يمرّر الـ prompt كمعلمة فقط")

    def build_resume(
        self, prompt: str, session: str, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        launch = launch or LaunchContext()
        argv: List[str] = [self.bin, "exec", "resume", session, "--json"]
        if launch.model:
            argv += ["-m", launch.model]
        if web_access:
            argv += ["--search"]
        argv += ["--", prompt]
        return argv

    def _hello_argv(self) -> List[str]:
        return [self.bin, "exec", "--json", "--", self._HELLO_PROMPT]

    def parse(self, stdout: str, stderr: str) -> EngineResult:
        result = EngineResult(ok=False)
        text_parts: List[str] = []
        session_id = ""
        last_event: Dict = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                if line:
                    text_parts.append(line)
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            last_event = obj
            etype = obj.get("type", "")
            if etype == "session.created" or "session_id" in obj:
                session_id = str(obj.get("session_id") or session_id)
            if etype in ("item.completed", "agent_message", "message"):
                item = obj.get("item") or obj
                text = item.get("text") or item.get("content") or ""
                if isinstance(text, str) and text:
                    text_parts.append(text)
            usage = obj.get("usage") or obj.get("token_usage") or {}
            if usage:
                result.input_tokens = usage.get("input_tokens") or usage.get("input")
                result.output_tokens = usage.get("output_tokens") or usage.get("output")

        result.output_text = "\n".join(text_parts).strip()
        result.session_id = session_id
        result.raw = last_event or {"stderr_tail": stderr[-500:] if stderr else ""}
        result.ok = bool(result.output_text or session_id)
        if not result.ok and stderr:
            result.error = stderr.strip()[-400:]
        return result

    def parse_stream_line(self, line: str) -> Optional[StreamStep]:
        line = line.strip()
        if not line.startswith("{"):
            return None
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None
        etype = obj.get("type", "")
        if "command" in str(obj.get("item", "")) or etype in ("exec_command_begin", "tool_call"):
            item = obj.get("item") or {}
            return StreamStep(kind="tool_call", tool_name="shell",
                              tool_input=item.get("command") or item, raw=obj)
        if etype in ("item.completed", "agent_message"):
            item = obj.get("item") or {}
            text = item.get("text") or ""
            if text:
                return StreamStep(kind="text", text=text, raw=obj)
        if etype == "turn.completed":
            return StreamStep(kind="status", text="مكتمل", raw=obj)
        return None
