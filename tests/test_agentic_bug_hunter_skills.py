"""Hermetic tests for HunterAI's centralized project skill registry."""

from __future__ import annotations

import json
from pathlib import Path

from core.skill_context_injector import SkillContextInjector

ROOT = Path(__file__).resolve().parents[1]


def test_registry_has_one_public_project_skill():
    registry = json.loads((ROOT / "skills" / "registry.json").read_text(encoding="utf-8"))
    assert registry["schema"] == "hunterai-project-skills/1"
    assert registry["primary"] == "hunterai-redteam"
    assert [skill["name"] for skill in registry["skills"]] == ["hunterai-redteam"]


def test_generated_mirrors_are_byte_identical():
    canonical = ROOT / "skills" / "hunterai-redteam"
    for mirror_root in (ROOT / ".opencode" / "skills", ROOT / ".agents" / "skills"):
        mirror = mirror_root / "hunterai-redteam"
        canonical_files = sorted(path.relative_to(canonical) for path in canonical.rglob("*") if path.is_file())
        mirror_files = sorted(path.relative_to(mirror) for path in mirror.rglob("*") if path.is_file())
        assert mirror_files == canonical_files
        for relative in canonical_files:
            assert (mirror / relative).read_bytes() == (canonical / relative).read_bytes()


def test_manifest_tracks_only_the_central_skill():
    manifest = json.loads((ROOT / ".opencode" / "skills" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "hunterai-active-skills/1"
    assert manifest["count"] == 1
    assert manifest["primary"] == "hunterai-redteam"
    assert [item["name"] for item in manifest["skills"]] == ["hunterai-redteam"]


def test_jailbreak_is_a_core_routed_reference():
    SkillContextInjector._instance = None
    injector = SkillContextInjector()
    context = injector.build_injected_context("redteam", "jailbreak prompt injection model testing")
    assert "[SKILL: hunterai-redteam]" in context
    assert "references/ai-jailbreak-redteam.md" in context


def test_browser_session_transfer_routes_without_field_deletion():
    SkillContextInjector._instance = None
    injector = SkillContextInjector()
    context = injector.build_injected_context(
        "redteam", "transfer browser cookies csrf token authorization header and request body"
    )
    assert "references/web-api-browser.md" in context
    assert "challenge, anti-automation, and target-issued cookies" in context.lower()
    assert "authorization" in context.lower()
