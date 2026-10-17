"""محرك OpenCode CLI.

opencode run يستقبل مهمة واحدة غير تفاعلية.
يقبل model بصيغة provider/model و endpoint مخصص عبر OPENCODE_* env.
"""
from __future__ import annotations

import json
from typing import Dict, List, Optional

from engines.base import EngineDriver, SecurePromptUnsupported
from engines.types import EngineResult, LaunchContext, StreamStep


class OpenCodeDriver(EngineDriver):
    name = "opencode"
    display_name = "OpenCode"
    env_bin_override = "HUNTER_OPENCODE_BIN"

    secure_prompt_transport = False
    persistent_stdin_prompt = False
    offline_web_isolation = False
    supports_resume = True
    supports_streaming = True

    def build_execute(
        self, prompt: str, session: Optional[str] = None, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        launch = launch or LaunchContext()
        argv: List[str] = [self.bin, "run"]
        if session:
            argv += ["--session", session]
        if launch.model:
            argv += ["--model", launch.model]
        argv += ["--format", "json"]
        argv += [prompt]
        return argv

    def build_execute_stdin(
        self, prompt: str, session: Optional[str] = None, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        raise SecurePromptUnsupported("opencode run يمرّر الـ prompt كمعلمة فقط")

    def build_resume(
        self, prompt: str, session: str, *,
        web_access: bool = True, stream: bool = False,
        launch: Optional[LaunchContext] = None,
    ) -> List[str]:
        return self.build_execute(
            prompt, session, web_access=web_access, stream=stream, launch=launch)

    def _hello_argv(self) -> List[str]:
        return [self.bin, "run", "--format", "json", self._HELLO_PROMPT]

    def env_extra(self) -> Dict[str, str]:
        return {}

    def parse(self, stdout: str, stderr: str) -> EngineResult:
        result = EngineResult(ok=False)
        text_parts: List[str] = []
        session_id = ""
        last: Dict = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                text_parts.append(line)
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            last = obj
            if "sessionID" in obj or "session_id" in obj:
                session_id = str(obj.get("sessionID") or obj.get("session_id") or "")
            text = obj.get("text") or obj.get("message") or ""
            if isinstance(text, str) and text and obj.get("type") in (None, "message", "text"):
                text_parts.append(text)
        result.output_text = "\n".join(text_parts).strip()
        result.session_id = session_id
        result.raw = last or {"stderr_tail": stderr[-500:] if stderr else ""}
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
        if obj.get("type") in ("tool", "tool_use"):
            return StreamStep(kind="tool_call",
                              tool_name=str(obj.get("tool") or obj.get("name") or ""),
                              tool_input=obj.get("state"), raw=obj)
        text = obj.get("text") or ""
        if isinstance(text, str) and text:
            return StreamStep(kind="text", text=text, raw=obj)
        return None
