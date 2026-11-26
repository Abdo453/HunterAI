"""Global test configuration.

The platform's DEFAULT runtime mode is *unrestricted* (owner full permissions).
The security test-suite, however, must keep exercising the fail-closed
governance paths (scope invariants, policy gate, approval gates). We therefore
force GOVERNED mode for the test session.

Tests that specifically validate unrestricted mode flip the switch back with
``monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
try:
    import scripts as _scripts_pkg

    _repo_scripts = str(_REPO_ROOT / "scripts")
    if hasattr(_scripts_pkg, "__path__") and _repo_scripts not in _scripts_pkg.__path__:
        _scripts_pkg.__path__.insert(0, _repo_scripts)
except Exception:
    pass

os.environ["HUNTER_UNRESTRICTED"] = "0"
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hunter_backend.settings")

from hunter_backend.testing import ASGISyncClient, make_async_client  # noqa: E402,F401


# Some modules load the repository .env at import time.  A live key leaking
# into a later test makes heuristic/AI fallbacks nondeterministic and can cause
# real network calls.  Tests that need a key set it explicitly with
# monkeypatch/patch.dict, which runs after this fixture.
_LIVE_LLM_KEYS = (
    "GEMINI_API_KEY",
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "GROQ_API_KEY",
    "TASKADE_API_KEY",
    "GEMINI_MODEL",
    "OPENAI_MODEL",
    "ANTHROPIC_MODEL",
    "DEEPSEEK_MODEL",
    "GROQ_MODEL",
    "OPENROUTER_MODEL",
)


@pytest.fixture(autouse=True)
def _isolate_live_llm_keys(monkeypatch):
    for key in _LIVE_LLM_KEYS:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture()
def asgi_client():
    """Provide an ``ASGISyncClient`` for synchronous Django/ASGI HTTP endpoint tests."""
    with ASGISyncClient() as client:
        yield client


@pytest.fixture()
def isolated_platform_client(tmp_path, monkeypatch):
    """Provide an ``ASGISyncClient`` backed by an isolated temporary SQLite WAL store."""
    import core.platform_store as ps
    import hunter_backend.runtime as rt
    from core.run_control import GLOBAL_RUN_CONTROLLER

    db_file = tmp_path / "platform_state.sqlite3"
    att_dir = tmp_path / "copilot_attachments"
    att_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("HUNTER_PLATFORM_DB_PATH", str(db_file))
    monkeypatch.setenv("HUNTER_COPILOT_ATTACHMENTS_DIR", str(att_dir))

    prev_store = ps._GLOBAL_PLATFORM_STORE
    prev_wired = rt._WIRED
    prev_ctrl_hook = GLOBAL_RUN_CONTROLLER.on_state_change
    prev_runs = dict(GLOBAL_RUN_CONTROLLER._runs)

    ps._GLOBAL_PLATFORM_STORE = None
    rt.EVENT_BUS._history.clear()
    rt._WIRED = False
    GLOBAL_RUN_CONTROLLER.on_state_change = None
    GLOBAL_RUN_CONTROLLER._runs.clear()

    with ASGISyncClient() as client:
        yield client

    GLOBAL_RUN_CONTROLLER.stop_all()
    GLOBAL_RUN_CONTROLLER._runs.clear()
    GLOBAL_RUN_CONTROLLER._runs.update(prev_runs)
    GLOBAL_RUN_CONTROLLER.on_state_change = prev_ctrl_hook
    rt._WIRED = prev_wired
    if ps._GLOBAL_PLATFORM_STORE is not None:
        ps._GLOBAL_PLATFORM_STORE.close()
    ps._GLOBAL_PLATFORM_STORE = prev_store
    rt.EVENT_BUS._history.clear()
