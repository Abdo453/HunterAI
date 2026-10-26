"""Global test configuration.

The platform's DEFAULT runtime mode is *unrestricted* (owner full permissions).
The security test-suite, however, must keep exercising the fail-closed
governance paths (scope invariants, policy gate, approval gates). We therefore
force GOVERNED mode for the test session.

Tests that specifically validate unrestricted mode flip the switch back with
``monkeypatch.setenv("HUNTER_UNRESTRICTED", "1")``.
"""
import os

import pytest

os.environ["HUNTER_UNRESTRICTED"] = "0"


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
)


@pytest.fixture(autouse=True)
def _isolate_live_llm_keys(monkeypatch):
    for key in _LIVE_LLM_KEYS:
        monkeypatch.delenv(key, raising=False)
