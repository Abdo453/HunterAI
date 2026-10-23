# -*- coding: utf-8 -*-
"""
اختبارات الـ CI workflow (Phase 8) — تحقق offline من بنية الـ YAML والخطوات.
العقد المدمج: السويت offline (not slow + استثناءات صريحة) + خطوتا الإبستميكس
من الـ workflow القديم (live session + specification suite) + بوابة الجاهزية.
كل سكربت مُشار إليه لازم يكون موجود فعلًا في الـ repo.
"""
from pathlib import Path

import yaml

REPO = Path(".")
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"


def _load() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _runs(doc: dict):
    return [s.get("run", "") for s in doc["jobs"]["test"]["steps"]]


class TestCIWorkflow:
    def test_file_exists_and_parses(self):
        assert WORKFLOW.is_file(), f"مفقود: {WORKFLOW}"
        assert isinstance(_load(), dict)

    def test_name_and_triggers(self):
        doc = _load()
        # PyYAML (YAML 1.1) يفرّغ مفتاح on → boolean True
        assert doc["name"] == "CI / Epistemic Regression Pipeline"
        triggers = doc.get("on", doc.get(True))
        assert triggers is not None
        assert "push" in triggers and "pull_request" in triggers
        assert triggers["push"]["branches"] == ["main", "master"]

    def test_core_suite_with_marker_and_exclusions(self):
        runs = "\n".join(_runs(_load()))
        pytest_steps = [r for r in runs.split("\n") if "pytest" in r
                        or "--ignore" in r or "not slow" in r]
        assert pytest_steps
        combined = runs
        assert "pytest tests/" in combined
        assert '-m "not slow"' in combined
        assert "--ignore=tests/benchmarks" in combined
        assert "--ignore=tests/v27" in combined
        assert "--ignore=tests/integration" in combined

    def test_epistemic_steps_preserved_and_scripts_exist(self):
        """خطوتا الـ workflow الأصلى — لا يُهجَّر معمل التحقق الإبستمي."""
        combined = "\n".join(_runs(_load()))
        assert "run_unified_live_session.py" in combined
        assert "run_causal_validation_arena.py" in combined
        assert (REPO / "run_unified_live_session.py").is_file()
        assert (REPO / "run_causal_validation_arena.py").is_file()

    def test_readiness_smoke_step_present(self):
        """بوابة الجاهزية (Phase 1) جزء من الـ CI — إثبات محلي على كل runner."""
        combined = "\n".join(_runs(_load()))
        assert "-m core.readiness" in combined
        assert "ci_readiness_report.json" in combined

    def test_timeout_and_python_version_matrix(self):
        doc = _load()
        job = doc["jobs"]["test"]
        assert job.get("timeout-minutes") in (30, 45, 60)
        matrix = job["strategy"]["matrix"]["python-version"]
        assert "3.11" in [str(v) for v in matrix]

    def test_no_risky_line_continuations(self):
        """backticks (PowerShell) جوّا bash runner = كارثة صامتة — ممنوعة."""
        raw = WORKFLOW.read_text(encoding="utf-8")
        run_blocks = raw.split("run: |")[1:]
        for block in run_blocks:
            assert "`" not in block, "لا backticks داخل run blocks لـ bash"
