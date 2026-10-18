# -*- coding: utf-8 -*-
"""
اختبارات السجل الموحد لكل تنفيذ أداة (Phase 2 — unified tool-execution ledger).
MasterToolRegistry.execute_artifact يكتب ToolExecutionRecord كامل الخط
(command/stage/target/endpoint/output_excerpt + artifact_reference) في EvidenceStore.
كلهم بـ ToolManager مزيف — صفر عمليات حقيقية.
"""
import asyncio
import json
import shutil
import tempfile

import pytest

from tools.tool_manager import ToolResult
from hunter_ai.pipeline.tool_specs import MasterToolRegistry
from core.evidence_store import EvidenceStore


class _FakeToolManager:
    """ToolManager وهمي يرجع ToolResult جاهز — بدون أي تنفيذ حقيقي."""

    def __init__(self, stdout="sub1.example.test\nsub2.example.test",
                 returncode=0, error=None):
        self._stdout = stdout
        self._returncode = returncode
        self._error = error
        self.calls = []

    def is_available(self, tool_name: str) -> bool:
        return True

    async def execute(self, cmd, timeout=None):
        self.calls.append({"cmd": cmd, "timeout": timeout})
        return ToolResult(
            tool=cmd.split()[0] if cmd.split() else "mock",
            command=cmd, stdout=self._stdout, stderr="",
            returncode=self._returncode, duration=0.02, error=self._error,
            output_file=None,
        )

    def _save_tool_output(self, tool, command, output, parsed_json, item_count, duration):
        return None


class _FakeEngagementMgr:
    """EngagementManager وهمي — يكفي أن save_tool_artifact يرجع meta."""
    raw_output_file = "data/tool_outputs/mock_subfinder_1.raw.txt"

    def save_tool_artifact(self, **kw):
        return type("Meta", (), {"raw_output_file": self.raw_output_file,
                                 "status": kw.get("status")})()


@pytest.fixture
def store(tmp_path):
    s = EvidenceStore(root_dir=str(tmp_path))
    yield s
    shutil.rmtree(tmp_path, ignore_errors=True)


def _registry(store, fake_tm=None, run_id="run-u1"):
    reg = MasterToolRegistry(tool_manager=fake_tm or _FakeToolManager())
    reg.evidence_store = store
    reg.run_id = run_id
    return reg


@pytest.mark.asyncio
async def test_successful_tool_writes_full_trace_record(store):
    reg = _registry(store)
    parsed, meta = await reg.execute_artifact(
        "subfinder", {"domain": "example.test"},
        engagement_mgr=_FakeEngagementMgr(), stage="01_PASSIVE_RECON",
        input_source="run()",
    )
    assert parsed == ["sub1.example.test", "sub2.example.test"]
    recs = store._read_all("tool_execution")
    assert recs, "must write a unified tool execution record"
    last = recs[-1]
    assert last["tool_id"] == "subfinder"
    assert last["command"].startswith("subfinder -d example.test")
    assert last["stage"] == "01_PASSIVE_RECON"
    assert last["target"] == "example.test"
    assert "example.test" in last["output_excerpt"]
    assert last["artifact_reference"] == _FakeEngagementMgr.raw_output_file
    # سجل مزدوج append-only: started ثم finished
    started = [r for r in recs if r["execution_id"] == last["execution_id"]]
    assert len(started) == 2
    assert started[0]["status"] == "started"
    assert started[1]["status"] == "finished"
    assert started[1]["exit_code"] == 0


@pytest.mark.asyncio
async def test_failed_tool_records_failed_status(store):
    fake = _FakeToolManager(stdout="", returncode=1, error="connection refused")
    reg = _registry(store, fake)
    await reg.execute_artifact(
        "subfinder", {"domain": "example.test"},
        engagement_mgr=_FakeEngagementMgr(), stage="01_PASSIVE_RECON",
    )
    recs = store._read_all("tool_execution")
    finished = [r for r in recs if r["status"] == "finished" or r["status"] == "failed"]
    assert finished, "failure must be recorded, not swallowed"
    last_finished = [r for r in finished if r["status"] == "failed"]
    assert last_finished, "tool failure must land as status=failed"
    assert last_finished[-1]["exit_code"] == 1


@pytest.mark.asyncio
async def test_missing_evidence_store_never_breaks_scan():
    """بدون store — السجل يحيرقد البيونتيب تكمل. لا crash."""
    reg = MasterToolRegistry(tool_manager=_FakeToolManager())
    reg.evidence_store = None
    parsed, meta = await reg.execute_artifact(
        "subfinder", {"domain": "example.test"},
        engagement_mgr=_FakeEngagementMgr(), stage="01_PASSIVE_RECON",
    )
    assert parsed == ["sub1.example.test", "sub2.example.test"]


@pytest.mark.asyncio
async def test_broken_store_never_breaks_scan(store, monkeypatch):
    """store منفجر → telemetry فقط، الفحص يكمل سليمًا."""
    reg = _registry(store)

    def boom(*a, **kw):
        raise RuntimeError("store exploded")

    monkeypatch.setattr(store, "record_tool_execution", boom)
    parsed, _ = await reg.execute_artifact(
        "subfinder", {"domain": "example.test"},
        engagement_mgr=_FakeEngagementMgr(), stage="01_PASSIVE_RECON",
    )
    assert parsed == ["sub1.example.test", "sub2.example.test"]


@pytest.mark.asyncio
async def test_secrets_redacted_in_command_excerpt(store):
    """سر داخل الأمر/الإخراج لا يدخل السجل الموحد يعرفًا كما هو."""
    fake = _FakeToolManager(stdout="hit with token sk-abcdef123456 inside")
    reg = _registry(store, fake)

    # نستخدم أداة بـ command template فيه ما يمكن أن يحمل سرًا — نحقن قيمة سرية بمزاجة
    context = {"command": 'curl -H "Authorization: Bearer eyJhbGciPack.eyJhbGciPack" https://api.example.test/x',
               "url": "https://api.example.test/x"}
    # pragma: flag — حتى وقت التسجيل، فقط أقِل ما يُفصًى
    await reg.execute_artifact(
        "curl_probe", context,
        engagement_mgr=_FakeEngagementMgr(), stage="99_TEST",
    )
    recs = store._read_all("tool_execution")
    joined = json.dumps(recs)
    assert "sk-abcdef123456" not in joined
    assert "***" in joined


@pytest.mark.asyncio
async def test_backward_compatible_record_via_list(store):
    """القراءة الموحدة عبر list_court_verdicts لا تتأثر — ذريم السجل الجديد."""
    # سطر قديم بدون الحقول الجديدة يُحمَّل عادي
    legacy = {"execution_id": "TE-LEGACYX", "run_id": "run-old",
              "worker_id": "w", "tool_id": "nmap", "status": "started"}
    store._append("tool_execution", legacy)
    ok = store.finish_tool_execution("TE-LEGACYX", "finished", 0)
    assert ok is True
    recs = store._read_all("tool_execution")
    legacy_final = [r for r in recs if r["execution_id"] == "TE-LEGACYX"][-1]
    assert legacy_final["status"] == "finished"
    assert legacy_final.get("command", "") == ""
