"""Phase 2 verification suite: canonical runtime, checkpoints, persistence, config, API contracts, and CLI fixes."""

from __future__ import annotations

import ast
import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import httpx
import pytest

from core.config.manager import ConfigManager
from core.copilot_service import MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_EXCERPT_CHARS, CopilotService
from core.persist.atomic_file import atomic_write_bytes, atomic_write_json, atomic_write_text
from core.persist.workspace_files import (
    WorkspaceFileStore,
    is_within_dir,
    resolve_cached_path,
    sanitize_filename,
)
from core.platform_store import INTERRUPTED_RUN_NOTE, PlatformStore
from core.policy.red_team import AuthorizationGrant, Profile, ScopeTarget, save_grant
from core.runtime.agent_manager import AgentManager, InputReply, run_without_cancel
from core.runtime.event_bus import PersistentEventBus
from core.runtime.orchestrator import RuntimeOrchestrator
from core.runtime.state_machine import (
    InvalidStateTransitionError,
    LifecycleState,
    assert_transition,
    can_transition,
    to_canonical_status,
    to_legacy_status,
)
from hunter_backend.testing import ASGISyncClient

_REPO_ROOT = Path(__file__).resolve().parent.parent


# ── 1. Canonical 7-State Lifecycle & Legacy Adapter ───────────────────────────


def test_canonical_seven_state_transitions_and_legacy_adapter() -> None:
    expected_states = {"QUEUED", "RUNNING", "WAITING", "PAUSED", "COMPLETED", "FAILED", "CANCELLED"}
    assert {s.value for s in LifecycleState} == expected_states

    # Legal forward transitions
    assert assert_transition(LifecycleState.QUEUED, LifecycleState.RUNNING) == LifecycleState.RUNNING
    assert assert_transition(LifecycleState.RUNNING, LifecycleState.WAITING) == LifecycleState.WAITING
    assert assert_transition(LifecycleState.WAITING, LifecycleState.RUNNING) == LifecycleState.RUNNING
    assert assert_transition(LifecycleState.RUNNING, LifecycleState.PAUSED) == LifecycleState.PAUSED
    assert assert_transition(LifecycleState.PAUSED, LifecycleState.RUNNING) == LifecycleState.RUNNING
    assert assert_transition(LifecycleState.RUNNING, LifecycleState.COMPLETED) == LifecycleState.COMPLETED

    # Illegal terminal -> active transitions must raise
    for terminal in (LifecycleState.COMPLETED, LifecycleState.FAILED, LifecycleState.CANCELLED):
        assert not can_transition(terminal, LifecycleState.RUNNING)
        with pytest.raises(InvalidStateTransitionError):
            assert_transition(terminal, LifecycleState.RUNNING, entity_id="run_test")

    # Bidirectional legacy mapping
    assert to_canonical_status("pending")[0] == LifecycleState.QUEUED
    assert to_legacy_status(LifecycleState.QUEUED) == "pending"

    assert to_canonical_status("stopped")[0] == LifecycleState.CANCELLED
    assert to_legacy_status(LifecycleState.CANCELLED) == "stopped"

    canon_int, meta_int = to_canonical_status("interrupted")
    assert canon_int == LifecycleState.PAUSED
    assert meta_int["recoverable"] is True
    assert to_legacy_status(LifecycleState.PAUSED, recoverable=True) == "paused"
    assert (
        to_legacy_status(LifecycleState.PAUSED, recoverable=True, prefer_interrupted_alias=True)
        == "interrupted"
    )


# ── 2. Flow -> Task -> Subtask Checkpoints & Startup Crash Recovery ───────────


def test_store_migrations_checkpoints_and_pentagi_crash_recovery(tmp_path: Path) -> None:
    store = PlatformStore(db_path=tmp_path / "recovery.sqlite3")
    try:
        # Additive schema tables exist and migration is recorded
        migrations = store.list_schema_migrations()
        assert any(m["version"] == 1 and m["name"] == "phase2_canonical_runtime_tables" for m in migrations)

        # Create in-flight run, task, running subtask, and active Copilot turn
        run = store.upsert_run(
            kind="pipeline",
            target="https://recover.example.com",
            status="running",
            current_phase="WEB",
            progress=0.45,
        )
        rid = run["run_id"]
        task = store.upsert_task_node(
            task_id="task_rec_1",
            run_id=rid,
            title="Web Audit",
            role="web",
            status="RUNNING",
        )
        sub = store.upsert_subtask_node(
            subtask_id="sub_rec_1",
            task_id=task["task_id"],
            run_id=rid,
            title="Endpoint Probing",
            status="RUNNING",
        )
        conv = store.create_conversation(
            title="Active Turn Before Crash",
            run_id=rid,
            metadata={"turn_status": "running", "active_turn": True},
        )
        store.record_cost_entry(
            run_id=rid,
            task_id=task["task_id"],
            provider="ollama",
            model="qwen2.5:14b",
            input_tokens=120,
            output_tokens=80,
            cost_usd=0.0025,
        )

        # Startup crash recovery
        reconciled = store.reconcile_interrupted_runs(active_run_ids=[])
        assert len(reconciled) == 1
        assert reconciled[0]["run_id"] == rid
        assert reconciled[0]["status"] == "paused"
        assert reconciled[0]["canonical_status"] == "PAUSED"
        assert reconciled[0]["recoverable"] is True

        # Checkpoint was recorded
        cp = store.get_latest_checkpoint(rid)
        assert cp is not None
        assert cp["phase"] == "WEB"
        assert cp["recoverable"] is True

        # Running subtask was reset to QUEUED; running task moved to recoverable PAUSED
        subs = store.list_subtask_nodes(run_id=rid)
        assert len(subs) == 1
        assert subs[0]["subtask_id"] == sub["subtask_id"]
        assert subs[0]["status"] == "QUEUED"
        tasks = store.list_task_nodes(rid)
        assert tasks[0]["status"] == "PAUSED"
        assert tasks[0]["recoverable"] is True

        # Active Copilot turn marked WAITING with interrupted_run_note
        conv_after = store.get_conversation(conv["conversation_id"])
        assert conv_after is not None
        assert conv_after["metadata"]["turn_status"] == "WAITING"
        assert conv_after["metadata"]["interrupted_run_note"] == INTERRUPTED_RUN_NOTE
        msgs = store.list_messages(conv["conversation_id"])
        assert any(m["content"] == INTERRUPTED_RUN_NOTE for m in msgs)

        # Legacy status filter compatibility for 'interrupted' and canonical 'PAUSED'
        assert any(r["run_id"] == rid for r in store.list_runs(status="interrupted"))
        assert any(r["run_id"] == rid for r in store.list_runs(status="PAUSED"))

        # Idempotent re-run does not duplicate recovery
        reconciled_again = store.reconcile_interrupted_runs(active_run_ids=[])
        assert reconciled_again == []

        # Cost ledger summarizes accurately
        summary = store.summarize_costs(run_id=rid)
        assert summary["entries"] == 1
        assert summary["input_tokens"] == 120
        assert summary["output_tokens"] == 80
        assert summary["total_cost_usd"] == pytest.approx(0.0025)

        # Read-only list_approvals defaults to expire_stale=False (never takes write lock on expired rows)
        apr = store.create_approval(action_type="RUN_TOOL", target="example.com", ttl_seconds=60.0)
        # Backdate expires_at directly to test read-only default vs explicit expire_stale=True
        with store._lock:
            store._conn.execute(
                "UPDATE approvals SET expires_at = ? WHERE approval_id = ?",
                (time.time() - 10.0, apr["approval_id"]),
            )
            store._conn.commit()
        ro_list = store.list_approvals(status="pending")
        assert any(a["approval_id"] == apr["approval_id"] for a in ro_list)
        rw_list = store.list_approvals(status="pending", expire_stale=True)
        assert not any(a["approval_id"] == apr["approval_id"] for a in rw_list)
    finally:
        store.close()


# ── 3. AgentManager Concurrency Semaphore, Dependencies, Cancel & CAS HITL ────


def test_agent_manager_semaphore_dependencies_and_cas_input_reply(tmp_path: Path) -> None:
    async def _exercise() -> None:
        store = PlatformStore(db_path=tmp_path / "agents.sqlite3")
        bus = PersistentEventBus(store_provider=lambda: store)
        mgr = AgentManager(max_concurrent_agents=2, store=store, event_bus=bus)
        try:
            run = store.upsert_run(kind="pipeline", target="https://conc.example.com", status="running")
            rid = run["run_id"]
            task = mgr.create_task(run_id=rid, title="Concurrent Batch", role="scanner")

            # Concurrency bound test: 5 subtasks with semaphore=2 -> peak_active_count <= 2
            async def _work(sub: Any) -> Dict[str, Any]:
                await asyncio.sleep(0.04)
                return {"done": sub.subtask_id}

            subs = [
                mgr.create_subtask(run_id=rid, task_id=task.task_id, title=f"job-{i}")
                for i in range(5)
            ]
            # Add dependency: job-4 depends on job-0
            subs[4].depends_on.append(subs[0].subtask_id)
            completion_order: List[str] = []

            async def _tracked_work(sub: Any) -> Dict[str, Any]:
                res = await _work(sub)
                completion_order.append(sub.subtask_id)
                return res

            futs = [mgr.spawn_subtask(s, _tracked_work) for s in subs]
            await asyncio.gather(*futs)
            assert mgr.peak_active_count <= 2
            assert completion_order.index(subs[0].subtask_id) < completion_order.index(subs[4].subtask_id)

            # Atomic CAS InputReply: concurrent deliver calls -> exactly ONE wins
            wait_task = asyncio.create_task(mgr.request_human_input(rid, "Approve pivot?", timeout=2.0))
            await asyncio.sleep(0.03)
            assert mgr.pending_input_request(rid) is not None
            assert store.get_run(rid)["status"] == "waiting"
            first_win = mgr.reply_input(rid, "yes-once")
            second_win = mgr.reply_input(rid, "duplicate-ignored")
            assert first_win is True
            assert second_win is False
            answer = await wait_task
            assert answer == "yes-once"
            assert store.get_run(rid)["status"] == "running"

            # Direct InputReply CAS sanity
            box = InputReply(run_id="r1", prompt="p")
            assert box.deliver("alpha") is True
            assert box.deliver("beta") is False
            assert box.cancel() is False

            # Cancellation propagation cancels in-flight subtask & updates store via WithoutCancel
            slow_sub = mgr.create_subtask(run_id=rid, task_id=task.task_id, title="slow-cancel")

            async def _slow(_s: Any) -> None:
                await asyncio.sleep(10.0)

            slow_fut = mgr.spawn_subtask(slow_sub, _slow)
            await asyncio.sleep(0.03)
            n_cancelled = await mgr.cancel_run(rid, reason="Operator abort")
            assert n_cancelled >= 1
            assert slow_fut.done()
            persisted_subs = {s["subtask_id"]: s for s in store.list_subtask_nodes(run_id=rid)}
            assert persisted_subs[slow_sub.subtask_id]["status"] == "CANCELLED"

            # Bounded WithoutCancel executes cleanly
            val = await run_without_cancel(lambda x: x + 1, 41, timeout_s=2.0)
            assert val == 42

            # PersistentEventBus monotonic seq + Last-Event-ID replay
            e1 = await bus.publish("test.one", {"n": 1}, run_id=rid)
            e2 = await bus.publish("test.two", {"n": 2}, run_id=rid)
            assert e2["seq"] > e1["seq"]
            assert e2["run_seq"] == e1["run_seq"] + 1
            replayed = bus.backlog_since(str(e1["seq"]), run_id=rid)
            assert [e["seq"] for e in replayed] == [e2["seq"]]
        finally:
            store.close()

    asyncio.run(_exercise())


# ── 4. RuntimeOrchestrator Idempotency, Recovery & Go ARTEX Sync ──────────────


def test_runtime_orchestrator_idempotency_and_artex_sync(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HUNTER_PIPELINE_PHASE_DELAY_S", "0")

    async def _exercise() -> None:
        store = PlatformStore(db_path=tmp_path / "orch.sqlite3")
        bus = PersistentEventBus(store_provider=lambda: store)
        orch = RuntimeOrchestrator(store=store, event_bus=bus, artex_base_url="http://127.0.0.1:7071")
        try:
            # Verify backend routing
            assert orch.resolve_backend("pipeline", "live_scanner") == "live_scanner"
            assert orch.resolve_backend("pipeline", "hunter_pipeline") == "pipeline_orchestrator"
            assert orch.resolve_backend("omni", "omni_hunter") == "omni_hunter"
            assert orch.resolve_backend("vram", "vram_pipeline") == "vram_pipeline"
            assert orch.resolve_backend("artex", "go_core") == "go_artex"

            # Mock Go Core transport for go_artex dispatch + sync
            scan_posts = 0

            def _artex_handler(req: httpx.Request) -> httpx.Response:
                nonlocal scan_posts
                if req.url.path == "/api/v1/scan" and req.method == "POST":
                    scan_posts += 1
                    return httpx.Response(202, json={"status": "QUEUED", "scan_id": "scan-abc123", "target": "example.com"})
                if req.url.path == "/api/v1/engagements":
                    return httpx.Response(200, json=[{"id": "go-eng-1", "code": "ENG-01", "target_url": "https://example.com", "authorized_scope": "example.com", "status": "ACTIVE"}])
                if req.url.path == "/api/v1/assets":
                    return httpx.Response(200, json=[{"id": "a1", "kind": "SUBDOMAIN", "value": "api.example.com"}])
                if req.url.path == "/api/v1/findings":
                    return httpx.Response(200, json=[{"id": "f1", "title": "Candidate Finding", "status": "TRIAGED", "severity": "HIGH"}])
                if req.url.path == "/api/v1/tasks":
                    return httpx.Response(200, json=[{"id": "t1", "agent_role": "RECON", "title": "Subdomain Enum", "status": "COMPLETED", "priority": 8}])
                return httpx.Response(404, json={"error": "not found"})

            async with httpx.AsyncClient(
                base_url="http://127.0.0.1:7071",
                transport=httpx.MockTransport(_artex_handler),
            ) as mock_go:
                r1 = await orch.start_run(
                    kind="artex",
                    engine="artex",
                    target="example.com",
                    idempotency_key="idem-key-xyz",
                    go_client=mock_go,
                )
                r2 = await orch.start_run(
                    kind="artex",
                    engine="artex",
                    target="example.com",
                    idempotency_key="idem-key-xyz",
                    go_client=mock_go,
                )
                assert r2["run_id"] == r1["run_id"]
                assert r2["deduplicated"] is True

                task = orch._active_tasks.get(r1["run_id"])
                if task is not None:
                    await asyncio.wait_for(task, timeout=5.0)
                assert scan_posts == 1
                final_run = store.get_run(r1["run_id"])
                assert final_run is not None
                assert final_run["status"] == "completed"
                synced_findings = final_run["meta"]["discovered_findings"]
                assert len(synced_findings) == 1
                # Findings synced from Go ARTEX never bypass Evidence Court
                assert synced_findings[0]["status"] == "CANDIDATE"
        finally:
            store.close()

    asyncio.run(_exercise())


# ── 5. Atomic File Writer & Workspace File Containment ────────────────────────


def test_atomic_file_and_workspace_files_containment(tmp_path: Path) -> None:
    target_txt = tmp_path / "nested" / "snapshot.txt"
    atomic_write_text(target_txt, "alpha-content")
    assert target_txt.read_text(encoding="utf-8") == "alpha-content"

    target_json = tmp_path / "nested" / "state.json"
    atomic_write_json(target_json, {"ok": True, "seq": 7})
    assert json.loads(target_json.read_text(encoding="utf-8")) == {"ok": True, "seq": 7}

    target_bin = tmp_path / "nested" / "raw.bin"
    atomic_write_bytes(target_bin, b"\x00\x01\x02")
    assert target_bin.read_bytes() == b"\x00\x01\x02"
    # No leftover temp files
    assert not any(".tmp." in p.name for p in target_txt.parent.iterdir())

    # sanitize_filename rejects traversal, ADS colons, control chars, reserved names
    assert sanitize_filename("report_01.json") == "report_01.json"
    for bad in ("", "..", "a:Zone.Identifier", "evil\x00.txt", "CON.txt", "foo/bar/.."):
        with pytest.raises(ValueError):
            sanitize_filename(bad)

    # resolve_cached_path & is_within_dir
    ok_path = resolve_cached_path(tmp_path, "run_42", "uploads/evidence.txt")
    assert is_within_dir(ok_path, tmp_path / "flow-run_42-data")
    assert not is_within_dir(tmp_path / "outside.txt", tmp_path / "flow-run_42-data")
    for bad_rel in ("../secrets.env", "/etc/passwd", "uploads/../../escape.txt", "unknown_root/a.txt"):
        with pytest.raises((ValueError, PermissionError)):
            resolve_cached_path(tmp_path, "run_42", bad_rel)

    # WorkspaceFileStore size & count caps
    ws = WorkspaceFileStore(tmp_path, max_file_size=16, max_file_count=2, max_total_size=24)
    ws.write_file("run_42", "uploads/one.txt", b"1234567890")
    ws.write_file("run_42", "artifacts/two.txt", b"1234567890")
    assert len(ws.list_files("run_42")) == 2
    assert ws.read_file("run_42", "uploads/one.txt") == b"1234567890"
    with pytest.raises(ValueError, match="single-file limit"):
        ws.write_file("run_42", "uploads/big.txt", b"x" * 20)
    with pytest.raises(ValueError, match="maximum file count"):
        ws.write_file("run_42", "uploads/three.txt", b"1")
    with pytest.raises(ValueError, match="maximum total size"):
        ws.write_file("run_42", "uploads/one.txt", b"x" * 16)


# ── 6. ConfigManager Precedence & hunter.yaml Handling ────────────────────────


def test_config_manager_precedence_and_hunter_yaml(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("HUNTER_LLM_POLICY=local_first\n", encoding="utf-8")
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "control_settings.json").write_text(
        json.dumps({"max_concurrent_agents": 9, "llm_policy": "cloud_first", "profile": "safe"}),
        encoding="utf-8",
    )
    (tmp_path / "permissions.json").write_text(
        json.dumps({"fail_closed": True, "hard_invariants": {"denied": ["backdoor"], "examples": {"backdoor": "No shells"}}}),
        encoding="utf-8",
    )
    (tmp_path / "hunter.yaml").write_text(
        "target: https://api.demo.test\nprofile: api\nmode: passive\nlimits:\n  requests_per_second: 3.5\n",
        encoding="utf-8",
    )

    secret = b"unit-test-policy-secret-1234567890"
    grant_path = tmp_path / "data" / "root_controller" / "grant.json"
    grant_path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    grant = AuthorizationGrant.sign(
        secret,
        grant_id="G-01",
        authorized_by="TestLead",
        scope=[ScopeTarget("domain", "demo.test")],
        not_before=now - 60,
        not_after=now + 3600,
        profiles=[Profile.RED_TEAM],
    )
    save_grant(grant, str(grant_path))

    cfg = ConfigManager(
        base_dir=tmp_path,
        policy_secret=secret,
        environ={"HUNTER_MAX_CONCURRENT_AGENTS": "12"},
    )
    # Precedence: env > signed_policy > settings_store > hunter_yaml > default
    r_env = cfg.resolve_with_source("max_concurrent_agents")
    assert r_env.value == 12 and r_env.source == "env"

    r_policy = cfg.resolve_with_source("profile")
    assert r_policy.value == "red_team" and r_policy.source == "signed_policy"

    r_dotenv = cfg.resolve_with_source("llm_policy")
    assert r_dotenv.value == "local_first" and r_dotenv.source == "dotenv"

    r_yaml = cfg.resolve_with_source("rate_limit_rps")
    assert r_yaml.value == pytest.approx(3.5) and r_yaml.source == "hunter_yaml"

    r_def = cfg.resolve_with_source("web_port")
    assert r_def.value == 8000 and r_def.source == "default"

    assessment = cfg.get_assessment_config()
    assert assessment["target"] == "https://api.demo.test"
    assert assessment["mode"] == "passive"
    assert cfg.get_hard_invariants()[0]["action"] == "BACKDOOR"


# ── 7. Fixed Django API Contracts ─────────────────────────────────────────────


def test_django_phase2_api_contract_parity(tmp_path: Path, monkeypatch) -> None:
    import core.platform_store as ps
    import hunter_backend.apps.arsenal_api as arsenal_api
    import hunter_backend.runtime as rt

    db_path = tmp_path / "api_contracts.sqlite3"
    store = PlatformStore(db_path=db_path)
    prev_store = ps._GLOBAL_PLATFORM_STORE
    prev_go = rt._GO_CLIENT
    prev_orch = rt._RUNTIME_ORCHESTRATOR
    ps._GLOBAL_PLATFORM_STORE = store
    rt._WIRED = False
    rt._RUNTIME_ORCHESTRATOR = None

    monkeypatch.setattr(arsenal_api, "GRANT_PATH", tmp_path / "grant.json")
    monkeypatch.setattr(arsenal_api, "CHECKLIST_STATE_FILE", tmp_path / "checklist_state.json")
    monkeypatch.setenv("HUNTER_COPILOT_ATTACHMENTS_DIR", str(tmp_path / "attachments"))
    monkeypatch.setenv("HUNTER_PIPELINE_PHASE_DELAY_S", "0")

    try:
        with ASGISyncClient() as client:
            # 1. probe_artex_health: both health & upstream + truthful degraded status
            rt._GO_CLIENT = httpx.AsyncClient(
                base_url="http://127.0.0.1:7071",
                transport=httpx.MockTransport(
                    lambda req: httpx.Response(
                        503,
                        json={"status": "degraded", "database": "disconnected", "error": "pg down"},
                    )
                ),
            )
            h_deg = client.get("/api/platform/artex/health").json()
            assert h_deg["online"] is False
            assert h_deg["status"] == "degraded"
            assert h_deg["health"]["database"] == "disconnected"
            assert h_deg["upstream"]["database"] == "disconnected"

            # 2. /api/pipeline/graph & /api/control/swarm-telemetry use export_graph() (never to_dict())
            g_resp = client.get("/api/pipeline/graph")
            assert g_resp.status_code == 200
            g_body = g_resp.json()
            assert "error" not in g_body
            assert "nodes" in g_body["graph"] and "edges" in g_body["graph"]

            sw_resp = client.get("/api/control/swarm-telemetry")
            assert sw_resp.status_code == 200
            sw_body = sw_resp.json()
            assert "error" not in sw_body
            assert sw_body["swarm_status"] in {"ACTIVE", "STANDBY"}
            assert isinstance(sw_body["swarm_roster"], list) and len(sw_body["swarm_roster"]) > 0
            assert isinstance(sw_body["wiretap_events"], list)
            assert isinstance(sw_body["two_brain_diffs"], list)
            assert "nodes" in sw_body["graph"]

            # 3. /api/pipeline/vram/status reads currently_loaded_model
            from core.pipeline.vram_sequential_pipeline import vram_pipeline

            vram_pipeline.vram_mgr.currently_loaded_model = "qwen2.5-coder:14b"
            vram_body = client.get("/api/pipeline/vram/status").json()
            assert vram_body["active_model_in_vram"] == "qwen2.5-coder:14b"
            vram_pipeline.vram_mgr.currently_loaded_model = None

            # 4. /api/platform/overview: truthful assets count (0 when no hub_assets even if engagement exists)
            eng = store.upsert_engagement(target="https://truth.example.com", name="Truth")
            ov = client.get("/api/platform/overview").json()
            assert ov["counts"]["engagements"] >= 1
            assert ov["counts"]["assets"] == 0

            # 5. /api/omni/status & /api/omni/findings read from PlatformStore (not stale _OMNI_RUNS)
            rt._OMNI_RUNS.clear()
            omni_run = store.upsert_run(
                kind="omni",
                target="https://truth.example.com",
                engagement_id=eng["engagement_id"],
                status="completed",
                current_phase="DONE",
                progress=1.0,
                meta={"discovered_findings": [{"id": "fd-1", "title": "CORS Reflection", "endpoint": "https://truth.example.com/api", "severity": "MEDIUM"}]},
            )
            os_resp = client.get(f"/api/omni/status/{eng['engagement_id']}")
            assert os_resp.status_code == 200
            assert os_resp.json()["current_phase"] == "DONE"
            assert os_resp.json()["omni"]["run_id"] == omni_run["run_id"]
            of_resp = client.get(f"/api/omni/findings/{eng['engagement_id']}")
            assert of_resp.status_code == 200
            assert of_resp.json()["count"] == 1
            assert of_resp.json()["findings"][0]["title"] == "CORS Reflection"

            # 6. /api/control/checklists returns categories + progress_percent alongside catalog + state
            chk = client.get("/api/control/checklists").json()
            assert isinstance(chk["categories"], list) and len(chk["categories"]) > 0
            assert "progress_percent" in chk and isinstance(chk["progress_percent"], (int, float))
            assert "catalog" in chk and "state" in chk

            # 7. /api/control/redteam-policy returns current_profile, hard_invariants, expires_at, stringified scope
            rt_init = client.get("/api/control/redteam-policy").json()
            assert rt_init["current_profile"] == "STANDARD"
            assert isinstance(rt_init["hard_invariants"], list) and len(rt_init["hard_invariants"]) > 0
            client.post(
                "/api/control/redteam-policy/issue",
                json={"scope": "example.com,api.example.com", "authorized_by": "Audit", "days": 2},
            )
            rt_act = client.get("/api/control/redteam-policy").json()
            assert rt_act["current_profile"] == "RED_TEAM"
            assert rt_act["grant"]["expires_at"].endswith("Z")
            assert rt_act["grant"]["scope"] == ["example.com", "api.example.com"]

            # 8. /api/control/lead-board includes counts breakdown
            lb = client.get("/api/control/lead-board", params={"target": "example.com"}).json()
            assert "counts" in lb and "total" in lb["counts"]

            # 9. /api/control/browser includes connection_status, browser_type, chrome_binary
            br = client.get("/api/control/browser").json()
            assert "connection_status" in br and "browser_type" in br and "chrome_binary" in br
            assert "playwright_available" in br and "status" in br

            # 10. /api/control/tools/test returns output + truthful non-200 failure (never fake PASS)
            async def _fake_fail_cmd(cmd, timeout_s=10.0):
                return {"returncode": 127, "stdout": "", "stderr": "binary not found", "error": "not found"}

            monkeypatch.setattr(arsenal_api, "run_command_no_shell", _fake_fail_cmd)
            tt_fail = client.post("/api/control/tools/test", json={"tool_name": "nmap"})
            assert tt_fail.status_code == 503
            assert tt_fail.json()["ok"] is False
            assert "not found" in tt_fail.json()["output"]

            # 11. /api/editor/tree returns recursive tree with type="directory" and is_dir=True on safe roots
            tree_resp = client.get("/api/editor/tree")
            assert tree_resp.status_code == 200
            tree_items = tree_resp.json()["items"]
            dirs = [it for it in tree_items if it.get("is_dir") is True]
            assert len(dirs) > 0
            assert all(it["type"] == "directory" for it in dirs)
            # Traversal still blocked with 403
            assert client.get("/api/editor/tree", params={"folder": "../../etc"}).status_code == 403

            # 12. /api/control/seven-gate/evaluate returns top-level fields AND evaluation wrapper + field mapping
            sg_resp = client.post(
                "/api/control/seven-gate/evaluate",
                json={
                    "title": "Tenant IDOR in Order Export",
                    "asset": "https://example.com/api/v1/orders/1002",
                    "poc": "GET https://example.com/api/v1/orders/1002 with Session A token returns Session B invoice JSON.",
                    "impact": "Cross-tenant PII and invoice disclosure across accounts.",
                    "vulnerability_class": "idor",
                    "in_scope": ["example.com"],
                },
            )
            assert sg_resp.status_code == 200
            sg = sg_resp.json()
            assert sg["passed"] is True
            assert sg["score"] >= 0.85
            assert "missing_items" in sg and "triage_statement" in sg
            assert sg["evaluation"]["passed"] is True

            # 13. /api/control/agents serves real registered agent specs (not the 6-agent hardcoded stub)
            ag_resp = client.get("/api/control/agents").json()
            assert ag_resp["count"] > 6
            assert any(a.get("module", "").startswith("agents.") for a in ag_resp["agents"])

            # 14. POST /api/platform/runs/<id>/recover resumes a PAUSED recoverable run
            paused_run = store.upsert_run(
                kind="pipeline",
                target="https://recover.example.com",
                status="running",
                current_phase="SCOPE_VERIFIED",
            )
            store.reconcile_interrupted_runs(active_run_ids=[])
            rec_resp = client.post(f"/api/platform/runs/{paused_run['run_id']}/recover")
            assert rec_resp.status_code == 200
            assert rec_resp.json()["ok"] is True
            assert rec_resp.json()["recovered"] is True

            # 15. Reconciled attachment upload limits between view and CopilotService
            att_resp = client.post(
                "/api/copilot/attachments",
                json={"filename": "notes.txt", "content": "hello " * 2000},
            )
            assert att_resp.status_code == 201
            att_body = att_resp.json()
            assert att_body["max_bytes"] == MAX_ATTACHMENT_BYTES
            assert len(att_body["attachment"]["excerpt"]) <= MAX_ATTACHMENT_EXCERPT_CHARS
    finally:
        ps._GLOBAL_PLATFORM_STORE = prev_store
        rt._GO_CLIENT = prev_go
        rt._RUNTIME_ORCHESTRATOR = prev_orch
        rt._WIRED = False
        store.close()


# ── 8. CLI & Script Crash Fixes ───────────────────────────────────────────────


def test_cli_and_script_crash_fixes() -> None:
    # 1. pentest.py: no duplicate cmd_waf_autowafuzzer / cmd_waf_rl_train, waf-bypass-ladder binds properly
    src = (_REPO_ROOT / "pentest.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn_names = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)]
    assert fn_names.count("cmd_waf_autowafuzzer") == 1
    assert fn_names.count("cmd_waf_rl_train") == 1

    import pentest

    parser = pentest.build_parser()
    ns = parser.parse_args(["waf-bypass-ladder", "https://example.com", "<svg onload=alert(1)>"])
    assert ns.func is pentest.cmd_waf_bypass_ladder
    assert ns.target == "https://example.com"

    # 2. scripts/master_agent.py imports re cleanly
    import scripts.master_agent as master_agent

    assert hasattr(master_agent, "re")

    # 3. bugbounty_agent.py imports safely on Windows without os.geteuid crash
    import bugbounty_agent

    assert callable(bugbounty_agent.require_root)

    # 4. main.py defaults web port to 8000 (while keeping --port override)
    main_src = (_REPO_ROOT / "main.py").read_text(encoding="utf-8")
    assert 'os.getenv("WEB_PORT", "8000")' in main_src
