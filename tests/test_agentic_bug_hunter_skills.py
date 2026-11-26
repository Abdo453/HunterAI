"""Hermetic tests for HunterAI's centralized project skill registry and routing."""

from __future__ import annotations

import json
import re
from pathlib import Path

from core.global_skills import global_skills_status, load_global_skills
from core.skill_context_injector import SkillContextInjector
from orchestrator.router import PROMPTS
from orchestrator.task_classifier import TaskClassifier, TaskType
from hunter_backend.testing import ASGISyncClient

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
    assert "False-refusal calibration" in context


def test_route_matching_avoids_substring_collisions():
    SkillContextInjector._instance = None
    injector = SkillContextInjector()
    context = injector.build_injected_context("redteam", "explain sqli chain on domain")
    assert "references/web-api-browser.md" in context
    assert "references/ai-jailbreak-redteam.md" not in context


def test_browser_session_transfer_routes_without_field_deletion():
    SkillContextInjector._instance = None
    injector = SkillContextInjector()
    context = injector.build_injected_context(
        "redteam", "transfer browser cookies csrf token authorization header and request body"
    )
    assert "references/web-api-browser.md" in context
    assert "challenge, anti-automation, and target-issued cookies" in context.lower()
    assert "authorization" in context.lower()


def test_project_skills_loader_stays_inside_repository():
    data = load_global_skills()
    assert Path(data["root"]).resolve() == (ROOT / ".agents" / "skills").resolve()
    assert "HunterAI RedTeam" in data["loaded"]
    assert "AI & Jailbreak RedTeam" in data["loaded"]
    status = global_skills_status()
    assert status["badge"].startswith("Project Red-Team Skills:")


def test_task_classifier_routes_jailbreak_to_security():
    classifier = TaskClassifier()
    result = classifier.classify("Test guardrail bypass and jailbreak prompts against target llm")
    assert result.task_type == TaskType.SECURITY


def test_modelfiles_and_router_prompts_use_central_skill_only():
    legacy_pat = re.compile(r"\b(?:abh|acs|tob|bri)-[a-z0-9-]+")
    for modelfile in sorted((ROOT / "models").glob("Modelfile.*")):
        text = modelfile.read_text(encoding="utf-8")
        assert "hunterai-redteam" in text, f"{modelfile.name} missing hunterai-redteam"
        assert not legacy_pat.search(text), f"{modelfile.name} still references legacy skill"
    for role, prompt in PROMPTS.items():
        assert "hunterai-redteam" in prompt, f"PROMPTS[{role!r}] missing hunterai-redteam"
        assert not legacy_pat.search(prompt), f"PROMPTS[{role!r}] still references legacy skill"


def test_opencode_skill_file_endpoint_reads_canonical_and_rejects_traversal():
    with ASGISyncClient() as client:
        ok = client.get("/api/opencode/skill-file", params={"name": "hunterai-redteam"})
        assert ok.status_code == 200
        assert ok.json()["path"] == "skills/hunterai-redteam/SKILL.md"

        bad = client.get("/api/opencode/skill-file", params={"name": "../AGENTS.md"})
        assert bad.status_code == 400
