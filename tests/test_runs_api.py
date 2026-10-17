"""
اختبارات smoke لنقاط تشغيل التطبيق (Phase H).
يختبر: GET /api/runs/{id}/events | /evidence | /findings
مع تشغيل فعلي عبر منسق المهام + متجر الأدلة.
"""
import pytest
import httpx

from ui.web.app import app
from core.global_state import GLOBAL_COORDINATOR, GLOBAL_EVIDENCE_STORE


@pytest.mark.asyncio
async def test_run_events_evidence_findings_flow():
    # إعادة تعيين الحالات بين الاختبارات
    GLOBAL_COORDINATOR._runs.clear()
    GLOBAL_COORDINATOR._event_log.clear()
    async def fake_executor(task_id, worker, subtask):
        await __import__("asyncio").sleep(0)
        return {"ok": True, "target": subtask.target}

    GLOBAL_COORDINATOR.set_executor(fake_executor)

    run_id = await GLOBAL_COORDINATOR.submit_run(
        goal="scan example.com",
        scope={"target": "example.com"},
    )

    # انتظر الانتهاء
    import asyncio
    for _ in range(200):
        ctx = GLOBAL_COORDINATOR.get_run(run_id)
        if ctx and ctx.finished_at:
            break
        await asyncio.sleep(0.05)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        # الأحداث
        res = await client.get(f"/api/runs/{run_id}/events")
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["run_id"] == run_id
        assert data["count"] >= 1
        types = [e["event_type"] for e in data["events"]]
        assert "RUN_CREATED" in types
        assert "RUN_FINISHED" in types

        # الأدلة
        res = await client.get(f"/api/runs/{run_id}/evidence")
        assert res.status_code == 200, res.text
        ev_data = res.json()
        assert ev_data["run_id"] == run_id

        # النتائج
        res = await client.get(f"/api/runs/{run_id}/findings")
        assert res.status_code == 200, res.text
        fd = res.json()
        assert fd["run_id"] == run_id
        assert "findings_count" in fd
        assert "findings" in fd

        # تشغيل غير موجود ⇒ 404 على الأحداث
        res = await client.get("/api/runs/does-not-exist/events")
        assert res.status_code == 404


@pytest.mark.asyncio
async def test_evidence_store_secret_redaction_through_api():
    from core.evidence_store import EvidenceStore
    import tempfile, shutil
    root = tempfile.mkdtemp(prefix="redact_api_")
    try:
        store = EvidenceStore(root_dir=root)
        store.add_evidence(
            run_id="run-redact", source_worker="w", source_tool="t",
            evidence_type="observation",
            content="leak sk-abcdef123456 here",
        )
        rec = store.list_evidence(run_id="run-redact")[0]
        assert "sk-abcdef123456" not in rec.sanitized_content
        assert "***" in rec.sanitized_content
    finally:
        shutil.rmtree(root, ignore_errors=True)
