"""Automated isolation tests for external upstream reference codebases.

Verifies Phase 0 isolation boundaries:
- Git ignore coverage for `/external/` and local runtime secrets.
- Docker build context exclusion for `/external/`.
- Python packaging (`setuptools`) and `pytest` collection exclusion of `external`.
- Skill discovery (`tools/install_opencode_skills.py`, `core/skill_registry.py`,
  and `SkillMatrixViewer`) loads zero skills from `external/`.
- Zero `.py` or `.go` source files outside `external/` import forbidden
  upstream modules (`github.com/vxcontrol/cloud`, `external.pentesterflow`,
  or `external.pentagi`).
"""

from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

try:
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    try:
        import tomli as tomllib  # type: ignore[import-not-found,no-redef]
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]

REPO_ROOT = Path(__file__).resolve().parent.parent
EXTERNAL_ROOT = (REPO_ROOT / "external").resolve()
SELF_PATH = Path(__file__).resolve()

SKIP_SCAN_DIRS = {
    "external",
    ".git",
    "node_modules",
    ".next",
    "out",
    "skills_library",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
}

FORBIDDEN_AGPL_IMPORT = "github.com/" + "vxcontrol/cloud"
FORBIDDEN_EXTERNAL_PY_PREFIXES = (
    "external." + "pentesterflow",
    "external." + "pentagi",
)
FORBIDDEN_PY_IMPORT_RE = re.compile(
    r"(?:^|\n)\s*(?:from|import)\s+(?:external\.(?:pentesterflow|pentagi))\b"
)


def _is_under_external(path_value: str | Path) -> bool:
    candidate = Path(path_value)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    resolved = candidate.resolve(strict=False)
    return resolved == EXTERNAL_ROOT or resolved.is_relative_to(EXTERNAL_ROOT)


def _iter_repo_source_files() -> list[Path]:
    matched: list[Path] = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_SCAN_DIRS]
        root_path = Path(root)
        for filename in files:
            if filename.endswith((".py", ".go")):
                full_path = (root_path / filename).resolve()
                if full_path != SELF_PATH:
                    matched.append(full_path)
    return sorted(matched)


def test_gitignore_blocks_external_references():
    gitignore = REPO_ROOT / ".gitignore"
    assert gitignore.is_file(), ".gitignore must exist at repository root"

    lines = [line.strip() for line in gitignore.read_text(encoding="utf-8").splitlines()]
    assert "/external/" in lines, ".gitignore must explicitly list /external/"

    probe_paths = [
        "external/pentesterflow-agent/LICENSE",
        "external/pentesterflow-agent/README.md",
        "external/pentagi/LICENSE",
        "external/pentagi/README.md",
        "data/root_controller/.django_secret",
        "data/control_settings.json",
    ]
    for rel_path in probe_paths:
        proc = subprocess.run(
            ["git", "check-ignore", "-q", rel_path],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, f"git check-ignore did not ignore {rel_path}"


def test_dockerignore_blocks_external_references():
    dockerignore = REPO_ROOT / ".dockerignore"
    assert dockerignore.is_file(), ".dockerignore must exist at repository root"

    lines = [line.strip() for line in dockerignore.read_text(encoding="utf-8").splitlines()]
    assert "/external/" in lines, ".dockerignore must explicitly exclude /external/"


def test_pyproject_excludes_external_from_packaging_and_pytest():
    pyproject_path = REPO_ROOT / "pyproject.toml"
    assert pyproject_path.is_file(), "pyproject.toml must exist at repository root"

    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))

    setuptools_excludes = (
        data.get("tool", {})
        .get("setuptools", {})
        .get("packages", {})
        .get("find", {})
        .get("exclude", [])
    )
    assert "external*" in setuptools_excludes, (
        "pyproject.toml [tool.setuptools.packages.find].exclude must contain 'external*'"
    )

    norecursedirs = (
        data.get("tool", {})
        .get("pytest", {})
        .get("ini_options", {})
        .get("norecursedirs", [])
    )
    assert "external" in norecursedirs, (
        "pyproject.toml [tool.pytest.ini_options].norecursedirs must contain 'external'"
    )


def test_skill_discovery_and_viewer_load_zero_external_skills(monkeypatch: pytest.MonkeyPatch):
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "install_opencode_skills.py"), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"install_opencode_skills.py --check failed (rc={proc.returncode}): "
        f"{proc.stdout}\n{proc.stderr}"
    )

    from core.skill_registry import SkillRegistry
    from core.skills.skill_matrix_viewer import SkillMatrixViewer

    registry = SkillRegistry()
    registry.discover(force=True)
    for meta in registry.get_all():
        assert not _is_under_external(meta.skill_file), (
            f"SkillRegistry loaded external skill {meta.name} from {meta.skill_file}"
        )

    monkeypatch.chdir(REPO_ROOT)
    all_viewer_skills = SkillMatrixViewer.list_all_skills()
    assert len(all_viewer_skills) > 0, "SkillMatrixViewer should load canonical skills"
    for item in all_viewer_skills:
        filepath = item.get("filepath")
        if filepath:
            assert not _is_under_external(filepath), (
                f"SkillMatrixViewer loaded external skill {item.get('name')} from {filepath}"
            )


def test_no_source_files_import_forbidden_external_or_agpl_modules():
    violations: list[str] = []

    for src_path in _iter_repo_source_files():
        rel_path = src_path.relative_to(REPO_ROOT).as_posix()
        text = src_path.read_text(encoding="utf-8", errors="replace")

        if FORBIDDEN_AGPL_IMPORT in text:
            violations.append(f"{rel_path}: references forbidden AGPL module {FORBIDDEN_AGPL_IMPORT}")

        if src_path.suffix == ".go":
            for forbidden in FORBIDDEN_EXTERNAL_PY_PREFIXES:
                if forbidden in text:
                    violations.append(f"{rel_path}: references {forbidden}")
            continue

        # Python AST import check + regex fallback
        try:
            tree = ast.parse(text, filename=rel_path)
        except SyntaxError:
            if FORBIDDEN_PY_IMPORT_RE.search(text):
                violations.append(f"{rel_path}: imports forbidden external module")
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith(FORBIDDEN_EXTERNAL_PY_PREFIXES):
                        violations.append(f"{rel_path}:{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module.startswith(FORBIDDEN_EXTERNAL_PY_PREFIXES):
                    violations.append(f"{rel_path}:{node.lineno}: from {module} import ...")
                elif module == "external":
                    for alias in node.names:
                        if alias.name in {"pentesterflow", "pentagi"}:
                            violations.append(
                                f"{rel_path}:{node.lineno}: from external import {alias.name}"
                            )

    go_mod = REPO_ROOT / "backend" / "go.mod"
    if go_mod.is_file():
        go_mod_text = go_mod.read_text(encoding="utf-8", errors="replace")
        if FORBIDDEN_AGPL_IMPORT in go_mod_text:
            violations.append(f"backend/go.mod: references forbidden AGPL module {FORBIDDEN_AGPL_IMPORT}")

    assert not violations, "Forbidden external/AGPL imports detected:\n" + "\n".join(violations)
