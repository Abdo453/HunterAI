"""سجل المحركات + أغلفة الملفات الشخصية (Profiles) والنماذج المخصصة."""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from engines.base import EngineDriver
from engines.drivers.claude import ClaudeCodeDriver
from engines.drivers.codex import CodexDriver
from engines.drivers.opencode import OpenCodeDriver
from engines.types import EngineResult, LaunchContext, StreamStep

DRIVERS: Dict[str, EngineDriver] = {
    "claude": ClaudeCodeDriver(),
    "codex": CodexDriver(),
    "opencode": OpenCodeDriver(),
}


def available_engines() -> List[str]:
    return sorted(DRIVERS)


def get_driver(name: str) -> EngineDriver:
    try:
        return DRIVERS[name]
    except KeyError:
        raise ValueError(
            f"محرك غير معروف {name!r}: المتاح = {sorted(DRIVERS)}") from None


class ModelBoundDriver(EngineDriver):
    """غلاف يربط محركًا بنموذج/وضع/سياق محدّد من ملف personal profile."""

    def __init__(self, base: EngineDriver, profile: Dict[str, Any]) -> None:
        self.base = base
        self.profile = dict(profile)
        self.name = base.name
        self.display_name = base.display_name
        self.env_bin_override = base.env_bin_override
        self.secure_prompt_transport = base.secure_prompt_transport
        self.persistent_stdin_prompt = base.persistent_stdin_prompt
        self.offline_web_isolation = base.offline_web_isolation
        self.supports_resume = base.supports_resume
        self.supports_streaming = base.supports_streaming
        self._bin = None

    @property
    def bin(self) -> str:
        return self.base.bin

    def _launch(self, launch: Optional[LaunchContext]) -> LaunchContext:
        launch = launch or LaunchContext()
        if not launch.model and self.profile.get("model"):
            launch.model = str(self.profile["model"])
        if not launch.permission_mode and self.profile.get("permission_mode"):
            launch.permission_mode = str(self.profile["permission_mode"])
        if not launch.sandbox_mode and self.profile.get("sandbox_mode"):
            launch.sandbox_mode = str(self.profile["sandbox_mode"])
        return launch

    def build_execute(self, prompt, session=None, *, web_access=True,
                      stream=False, launch=None) -> List[str]:
        return self.base.build_execute(
            prompt, session, web_access=web_access, stream=stream,
            launch=self._launch(launch))

    def build_execute_stdin(self, prompt, session=None, *, web_access=True,
                            stream=False, launch=None) -> List[str]:
        return self.base.build_execute_stdin(
            prompt, session, web_access=web_access, stream=stream,
            launch=self._launch(launch))

    def build_resume(self, prompt, session, *, web_access=True,
                     stream=False, launch=None) -> List[str]:
        return self.base.build_resume(
            prompt, session, web_access=web_access, stream=stream,
            launch=self._launch(launch))

    def parse(self, stdout: str, stderr: str) -> EngineResult:
        return self.base.parse(stdout, stderr)

    def parse_stream_line(self, line: str) -> Optional[StreamStep]:
        return self.base.parse_stream_line(line)

    def _hello_argv(self) -> List[str]:
        base_hello = self.base._hello_argv()
        if base_hello:
            return self.base.build_execute(
                self._HELLO_PROMPT, None, web_access=False,
                launch=self._launch(None))
        return []

    def env_extra(self) -> Dict[str, str]:
        env = dict(self.base.env_extra())
        # حقن endpoint مخصص إن وُجد
        base_url = str(self.profile.get("base_url") or "").strip()
        if base_url:
            if self.name == "claude":
                env.setdefault("ANTHROPIC_BASE_URL", base_url)
            elif self.name == "opencode":
                env.setdefault("OPENCODE_BASE_URL", base_url)
        api_key = str(self.profile.get("api_key") or "").strip()
        if api_key:
            key_env = {"claude": "ANTHROPIC_API_KEY"}.get(self.name, "OPENAI_API_KEY")
            env.setdefault(key_env, api_key)
            if self.name == "claude":
                env.setdefault("ANTHROPIC_AUTH_TOKEN", api_key)
        return env


def driver_for(profile: Dict[str, Any] | str) -> EngineDriver:
    if isinstance(profile, dict):
        base = get_driver(str(profile.get("engine") or profile.get("name") or ""))
        return ModelBoundDriver(base, profile)
    return get_driver(str(profile))
