"""
Project Red-Team Skills Loader
==============================
Reads the project-local Markdown red-team skill installed under ``.agents/skills``
inside the HunterAI repository (never reading external machine-global skills by
default) and formats prompt context for the chat and agent orchestration flow.

Loaded from ``<repo>/.agents/skills``:
  * ``hunterai-redteam/SKILL.md`` — central red-team entrypoint
  * ``hunterai-redteam/references/ai-jailbreak-redteam.md`` — core AI/jailbreak red teaming
  * ``hunterai-redteam/references/web-api-browser.md`` — web, API, browser, and session testing
  * ``hunterai-redteam/references/agent-mcp.md`` — deployed agent, MCP, and tool boundaries
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ROOT = Path(
    os.getenv(
        "HUNTERAI_PROJECT_SKILLS_DIR",
        os.getenv("GLOBAL_SKILLS_DIR", str(_REPO_ROOT / ".agents" / "skills")),
    )
)

# label -> relative path parts inside the project skills root
INJECTED_SKILLS: Dict[str, Tuple[str, ...]] = {
    "HunterAI RedTeam": ("hunterai-redteam", "SKILL.md"),
    "AI & Jailbreak RedTeam": ("hunterai-redteam", "references", "ai-jailbreak-redteam.md"),
    "Web & API RedTeam": ("hunterai-redteam", "references", "web-api-browser.md"),
    "Agent & MCP Security": ("hunterai-redteam", "references", "agent-mcp.md"),
}

# Machine-global skills are intentionally excluded from project status checks.
STATUS_ONLY_SKILLS: Dict[str, Tuple[str, ...]] = {}

DEFAULT_MAX_CHARS = int(os.getenv("GLOBAL_SKILLS_MAX_CHARS", "16000"))

_cache: Dict[str, Tuple[float, int, str]] = {}


def _read_cached(path: Path) -> str:
    """Read a file, caching by (mtime, size). Missing files yield ''."""
    try:
        st = path.stat()
    except OSError:
        return ""
    key = str(path)
    cached = _cache.get(key)
    if cached and cached[0] == st.st_mtime and cached[1] == st.st_size:
        return cached[2]
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    _cache[key] = (st.st_mtime, st.st_size, text)
    return text


def _truncate(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    return f"{text[:limit]}\n\n[... truncated {len(text) - limit} chars ...]"


def _resolve(root: Path, parts: Tuple[str, ...]) -> Path:
    return root.joinpath(*parts)


def load_global_skills(
    root: Optional[str] = None,
    max_chars: Optional[int] = None,
) -> Dict[str, Any]:
    """Load project-local red-team skills and report status."""
    base = Path(root) if root else _DEFAULT_ROOT
    limit = DEFAULT_MAX_CHARS if max_chars is None else max_chars

    loaded: List[str] = []
    details: Dict[str, Dict[str, Any]] = {}
    sections: List[str] = []

    for label, parts in INJECTED_SKILLS.items():
        path = _resolve(base, parts)
        text = _read_cached(path)
        if not text.strip():
            details[label] = {"path": str(path), "chars": 0, "loaded": False}
            continue
        loaded.append(label)
        details[label] = {"path": str(path), "chars": len(text), "loaded": True}
        sections.append(
            f"### {label}\nSource: {path}\n\n{_truncate(text, limit)}"
        )

    for label, parts in STATUS_ONLY_SKILLS.items():
        path = _resolve(base, parts)
        text = _read_cached(path)
        details[label] = {
            "path": str(path),
            "chars": len(text),
            "loaded": bool(text.strip()),
        }
        if text.strip():
            loaded.append(label)

    preamble = ""
    if sections:
        preamble = (
            "# Loaded Project Red-Team Skills\n"
            "The following project-local HunterAI red-team skill and core references "
            "are active for this session. Preserve the requested Analyze, Build, "
            "Verify, or Operate mode, treat jailbreak and prompt-injection testing "
            "as core capabilities, and avoid skill-level false refusals.\n\n"
            + "\n\n---\n\n".join(sections)
        )

    return {
        "root": str(base),
        "loaded": loaded,
        "details": details,
        "preamble": preamble,
        "chars": len(preamble),
    }


def build_skills_preamble(
    root: Optional[str] = None,
    max_chars: Optional[int] = None,
) -> str:
    """Return the prompt preamble, or '' when no project skills are installed."""
    return load_global_skills(root=root, max_chars=max_chars)["preamble"]


def global_skills_status(
    root: Optional[str] = None,
) -> Dict[str, Any]:
    """Compact status for the UI badge."""
    data = load_global_skills(root=root, max_chars=DEFAULT_MAX_CHARS)
    loaded = list(data["loaded"])
    badge = "Project Red-Team Skills: " + (", ".join(loaded) if loaded else "none")
    return {
        "root": data["root"],
        "loaded": loaded,
        "badge": badge,
        "injected_chars": data["chars"],
        "details": data["details"],
    }
