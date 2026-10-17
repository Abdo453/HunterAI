"""محرك Claude Code CLI.

يفترض أن الحساب مسجّل داخليًا في claude CLI أو عبر ANTHROPIC_API_KEY.
يستخدم الوضع غير التفاعلي (-p) مع JSON output للتطبيع.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from engines.base import EngineDriver
from engines.types import EngineResult, LaunchContext, StreamStep


class ClaudeCodeDriver(EngineDriver):
    name = "claude"
    display_name = "Claude Code"
    env_bin_override = "HUNTER_CLAUDE_BIN"

    secure_prompt_transport = True   # -p يقبل الـ prompt من stdin
    persistent_stdin_prompt = True   # بدون --continue لا يُحفظ تلقائيًا في print mode
    offline_web_isolation = True     # --disallowedTools يعزل WebSearch/WebFetch
    supports_resume = True
    supports_streaming = True

    # أنماط صلاحيات claude الأصلية
    NATIVE_PERMISSION_MODES = ("default", "acceptEdits", "plan", "bypassPermissions")

    def validate_launch(self, launch: LaunchContext) -> None:
        mode = (launch.permission_mode or "").strip()
        if mode and mode not in self.NATIVE_PERMISSION_MODES:
            raise ValueError(f"claude: وضع صلاحيات غير مدعوم: {mode!r}")

    def build_execute(
        self, prompt: str, session: Optional[str] = None, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        launch = launch or LaunchContext()
        self.validate_launch(launch)
        argv: List[str] = [self.bin, "-p", prompt, "--output-format", "json"]
        if session:
            argv += ["--resume", session]
        if launch.model:
            argv += ["--model", launch.model]
        if launch.permission_mode:
            argv += ["--permission-mode", launch.permission_mode]
        if not web_access:
            argv += ["--disallowedTools", "WebSearch,WebFetch"]
        return argv

    def build_execute_stdin(
        self, prompt: str, session: Optional[str] = None, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        launch = launch or LaunchContext()
        self.validate_launch(launch)
        argv: List[str] = [self.bin, "-p", "--output-format", "json"]
        if session:
            argv += ["--resume", session]
        if launch.model:
            argv += ["--model", launch.model]
        if launch.permission_mode:
            argv += ["--permission-mode", launch.permission_mode]
        if not web_access:
            argv += ["--disallowedTools", "WebSearch,WebFetch"]
        return argv

    def build_resume(
        self, prompt: str, session: str, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        return self.build_execute(
            prompt, session, web_access=web_access, stream=stream, launch=launch)

    def _hello_argv(self) -> List[str]:
        return [self.bin, "-p", self._HELLO_PROMPT, "--output-format", "json"]

    def parse(self, stdout: str, stderr: str) -> EngineResult:
        data: Dict = {}
        text_parts: List[str] = []
        result = EngineResult(ok=False)
        saw_json = False
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                text_parts.append(line)
                continue
            saw_json = True
            if isinstance(obj, dict):
                if "result" in obj:
                    data = obj
                    if isinstance(obj.get("result"), str):
                        text_parts.append(obj["result"])
                elif obj.get("type") == "assistant":
                    for block in obj.get("message", {}).get("content", []):
                        if isinstance(block, dict) and block.get("type") == "text":
                            text_parts.append(block.get("text", ""))

        result.output_text = "\n".join(p for p in text_parts if p).strip()
        result.session_id = str(data.get("session_id") or "")
        result.cost_usd = data.get("total_cost_usd")
        usage = data.get("usage") or {}
        result.input_tokens = usage.get("input_tokens")
        result.output_tokens = usage.get("output_tokens")
        result.raw = data or {"stderr_tail": stderr[-500:] if stderr else ""}
        # claude بوضع --output-format json يجب أن يُخرج JSON دائمًا؛ مخرجات
        # غير JSON تعني إما binary مختلفًا أو إخراجًا غير متوقع ⇒ فشل صامت.
        result.ok = bool(saw_json and (result.session_id or result.output_text))
        if not result.ok:
            tail = (stderr or stdout).strip()[-400:]
            result.error = result.error or (
                "مخرجات غير متوقعة (لا JSON): " + tail if tail else "لا مخرجات")
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
        etype = obj.get("type")
        if etype == "assistant":
            for block in obj.get("message", {}).get("content", []):
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text" and block.get("text"):
                    return StreamStep(kind="text", text=block["text"], raw=obj)
                if block.get("type") == "tool_use":
                    return StreamStep(
                        kind="tool_call", tool_name=block.get("name", ""),
                        tool_input=block.get("input"), raw=obj)
        if etype == "user":
            for block in obj.get("message", {}).get("content", []):
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    return StreamStep(
                        kind="tool_result",
                        text=str(block.get("content", ""))[:2000], raw=obj)
        if etype == "result":
            return StreamStep(kind="status", text="مكتمل", raw=obj)
        return None

    def env_extra(self) -> Dict[str, str]:
        return {}
