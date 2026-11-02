"""
Global Skills Loader
====================
Reads the Markdown-based global skills installed under ``~/.agents/skills``
and turns them into prompt context for the chat/agent flow.

Injected into the model prompt:
  * ``bug-hunting/SKILL.md`` — hunting methodology router
  * ``BugBountySkills/SKILL_FILES/PAYLOADS/waf_bypass_payloads.md`` — WAF bypass payloads

Archify is reported as an available global skill (for the UI badge) but its
``SKILL.md`` is not injected into every chat prompt because it is a diagram
authoring guide, not hunting context.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_DEFAULT_ROOT = Path(
    os.getenv("GLOBAL_SKILLS_DIR", str(Path.home() / ".agents" / "skills"))
)

# label -> relative path parts inside the skills root
INJECTED_SKILLS: Dict[str, Tuple[str, ...]] = {
    "BugHunter": ("bug-hunting", "SKILL.md"),
    "WAF Bypass": (
        "BugBountySkills",
        "SKILL_FILES",
        "PAYLOADS",
        "waf_bypass_payloads.md",
    ),
}

# Detected/reported only (not injected into every prompt)
STATUS_ONLY_SKILLS: Dict[str, Tuple[str, ...]] = {
    "Archify": ("archify", "SKILL.md"),
}

DEFAULT_MAX_CHARS = int(os.getenv("GLOBAL_SKILLS_MAX_CHARS", "12000"))

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
    """Load injected skills and report status for all global skills."""
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

    # Report-only skills (existence check)
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
            "# Loaded Global Skills\n"
            "The following operator skills are active for this session. Use them "
            "as methodology and payload guidance, and keep the safety/scope rules "
            "they contain.\n\n" + "\n\n---\n\n".join(sections)
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
    """Return the prompt preamble, or '' when no skills are installed."""
    return load_global_skills(root=root, max_chars=max_chars)["preamble"]


def global_skills_status(
    root: Optional[str] = None,
) -> Dict[str, Any]:
    """Compact status for the UI badge."""
    data = load_global_skills(root=root, max_chars=DEFAULT_MAX_CHARS)
    loaded = list(data["loaded"])
    badge = "Loaded Global Skills: " + (", ".join(loaded) if loaded else "none")
    return {
        "root": data["root"],
        "loaded": loaded,
        "badge": badge,
        "injected_chars": data["chars"],
        "details": data["details"],
    }
