"""Unified RuntimeOrchestrator dispatching all execution engines with checkpoints & idempotency.

Routes managed runs across:
- ``live_scanner`` (default web/recon/pipeline/mission/omni fast path)
- ``PipelineOrchestrator`` (``hunter_ai.pipeline.HunterPipelineOrchestrator``)
- ``OmniHunterEngine`` (``core.engine.omni_hunter_engine.OmniHunterEngine``)
- ``VRAMSequentialPipeline`` (``core.pipeline.vram_sequential_pipeline.vram_pipeline``)
- Go ARTEX-Pro ``/api/v1/scan`` + ``sync_artex_to_store()``
- CLI ``EngineWorker`` (``engines.worker.EngineWorker``)

Provides idempotency-key deduplication, Flow->Task->Subtask checkpointing,
crash recovery resume (``recover_run``), and bounded cancellation-safe
finalization writes.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from core.config.manager import get_config_manager
from core.persist.atomic_file import atomic_write_json
from core.platform_store import PlatformStore, get_platform_store, new_id
from core.run_control import GLOBAL_RUN_CONTROLLER
from core.runtime.agent_manager import AgentManager, run_without_cancel
from core.runtime.event_bus import PersistentEventBus
from core.runtime.state_machine import LifecycleState, to_canonical_status

logger = logging.getLogger("hunter_ai.runtime.orchestrator")

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DATA_DIR = _REPO_ROOT / "data"
_REPORTS_DIR = _DATA_DIR / "reports"

_BACKEND_ALIASES: Dict[str, str] = {
    "live_scanner": "live_scanner",
    "live": "live_scanner",
    "native": "live_scanner",
    "pipeline": "live_scanner",
    "scan": "live_scanner",
    "recon": "live_scanner",
    "mission": "live_scanner",
    "hunter_pipeline": "pipeline_orchestrator",
    "pipeline_orchestrator": "pipeline_orchestrator",
    "omni_hunter": "omni_hunter",
    "omni_engine": "omni_hunter",
    "vram": "vram_pipeline",
    "vram_pipeline": "vram_pipeline",
    "vram_sequential": "vram_pipeline",
    "artex": "go_artex",
    "go_artex": "go_artex",
    "go_core": "go_artex",
    "cli_engine": "cli_engine",
}


class RuntimeOrchestrator:
    """Canonical unified engine dispatcher with idempotency, checkpoints, and Go ARTEX sync."""

    def __init__(
        self,
        *,
        store: Optional[PlatformStore] = None,
        event_bus: Optional[PersistentEventBus] = None,
        agent_manager: Optional[AgentManager] = None,
        artex_base_url: Optional[str] = None,
    ) -> None:
        self._store = store
        self._event_bus = event_bus or PersistentEventBus(store_provider=lambda: self.store)
        max_agents = get_config_manager().get_int("max_concurrent_agents", 5)
        self.agent_manager = agent_manager or AgentManager(
            max_concurrent_agents=max_agents,
            store=self._store,
            event_bus=self._event_bus,
        )
        self.artex_base_url = (
            artex_base_url
            or os.environ.get("HUNTERAI_ARTEX_URL")
            or get_config_manager().get("artex_url", "http://127.0.0.1:7071")
        ).rstrip("/")
        self._active_tasks: Dict[str, asyncio.Task[Any]] = {}

    @property
    def store(self) -> PlatformStore:
        return self._store if self._store is not None else get_platform_store()

    @property
    def event_bus(self) -> PersistentEventBus:
        return self._event_bus

    @staticmethod
    def resolve_backend(kind: str, engine: str, prompt: str = "") -> str:
        """Resolve which concrete execution backend handles ``(kind, engine, prompt)``."""
        eng_norm = (engine or "").strip().lower()
        kind_norm = (kind or "pipeline").strip().lower()
        if eng_norm in _BACKEND_ALIASES:
            return _BACKEND_ALIASES[eng_norm]
        if kind_norm in {"vram", "vram_pipeline"}:
            return "vram_pipeline"
        if kind_norm in {"artex", "go_artex", "go_core"}:
            return "go_artex"
        if kind_norm in {"hunter_pipeline", "pipeline_orchestrator"}:
            return "pipeline_orchestrator"
        if kind_norm == "engine":
            if prompt.strip():
                return "cli_engine"
            return "live_scanner"
        return "live_scanner"

    async def start_run(
        self,
        *,
        kind: str = "pipeline",
        target: str = "",
        engagement_id: Optional[str] = None,
        scope: Optional[List[str]] = None,
        out_of_scope: Optional[List[str]] = None,
        mode: str = "full",
        prompt: str = "",
        engine: str = "claude",
        model: str = "",
        coverage: float = 0.85,
        max_cycles: int = 10,
        force_fallback: bool = False,
        self_operate: bool = False,
        proxy: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        go_client: Optional[httpx.AsyncClient] = None,
        on_pipeline_state: Optional[Callable[[str, str, Optional[str]], None]] = None,
    ) -> Dict[str, Any]:
        """Start (or deduplicate via idempotency_key) a canonical managed run."""
        store = self.store
        clean_key = (idempotency_key or "").strip()
        if clean_key:
            existing_idem = await asyncio.to_thread(store.get_idempotency_key, clean_key)
            if existing_idem and existing_idem.get("run_id"):
                existing_run = await asyncio.to_thread(store.get_run, existing_idem["run_id"])
                if existing_run is not None:
                    dedup = dict(existing_run)
                    dedup["deduplicated"] = True
                    dedup["idempotency_key"] = clean_key
                    return dedup

        clean_target = (target or "").strip()
        if not clean_target and engagement_id:
            eng = await asyncio.to_thread(store.get_engagement, engagement_id)
            if eng:
                clean_target = str(eng.get("target") or "").strip()
        if not clean_target and kind != "engine":
            raise ValueError("target is required")

        eff_eid = engagement_id
        if not eff_eid and clean_target:
            ctx = await asyncio.to_thread(store.get_context)
            active_eid = ctx.get("active_engagement_id")
            active_eng = (
                await asyncio.to_thread(store.get_engagement, active_eid)
                if active_eid
                else None
            )
            if active_eng and active_eng.get("target") == clean_target:
                eff_eid = active_eid
            else:
                eng = await asyncio.to_thread(
                    store.upsert_engagement,
                    target=clean_target,
                    in_scope=scope or ([clean_target] if clean_target else []),
                    out_of_scope=out_of_scope or [],
                    status="authorized",
                    source=kind,
                )
                eff_eid = eng["engagement_id"]

        backend = self.resolve_backend(kind, engine, prompt)
        run_id = new_id("run")
        run_meta: Dict[str, Any] = {
            "mode": mode,
            "engine": engine,
            "backend": backend,
            "model": model,
            "prompt": prompt,
            "coverage": float(coverage),
            "max_cycles": int(max_cycles),
            "force_fallback": bool(force_fallback),
            "self_operate": bool(self_operate),
            "proxy": proxy,
            "in_scope": list(scope or ([clean_target] if clean_target else [])),
            "out_of_scope": list(out_of_scope or []),
            "idempotency_key": clean_key or None,
            "canonical_status": LifecycleState.RUNNING.value,
            "recoverable": False,
        }

        handle = GLOBAL_RUN_CONTROLLER.register(
            run_id,
            task=None,
            kind=kind,
            meta={"target": clean_target, **run_meta},
        )
        run_row = await asyncio.to_thread(
            store.upsert_run,
            run_id=run_id,
            kind=kind,
            target=clean_target,
            engagement_id=eff_eid,
            status="running",
            current_phase="DISPATCH",
            progress=0.0,
            meta=run_meta,
            started_at=time.time(),
        )
        await asyncio.to_thread(
            store.update_context,
            active_engagement_id=eff_eid,
            active_run_id=run_id,
        )
        await asyncio.to_thread(
            store.save_checkpoint,
            run_id=run_id,
            phase="DISPATCH",
            state={"progress": 0.0, "backend": backend, "target": clean_target, "meta": run_meta},
            recoverable=True,
            reason="Initial dispatch checkpoint",
        )
        await self._event_bus.publish(
            "run.started",
            {
                "run_id": run_id,
                "kind": kind,
                "target": clean_target,
                "backend": backend,
                "status": "running",
                "canonical_status": LifecycleState.RUNNING.value,
            },
            run_id=run_id,
            engagement_id=eff_eid,
            source=kind,
        )

        if clean_key:
            await asyncio.to_thread(
                store.save_idempotency_key,
                key=clean_key,
                scope="run_start",
                run_id=run_id,
                response={"run_id": run_id, "kind": kind, "target": clean_target},
            )

        task = self._launch_run_coroutine(
            run_id=run_id,
            handle=handle,
            backend=backend,
            kind=kind,
            target=clean_target,
            engagement_id=eff_eid,
            scope=run_meta["in_scope"],
            out_of_scope=run_meta["out_of_scope"],
            mode=mode,
            prompt=prompt,
            engine=engine,
            model=model,
            coverage=coverage,
            max_cycles=max_cycles,
            proxy=proxy,
            resume_phase=None,
            go_client=go_client,
            on_pipeline_state=on_pipeline_state,
        )
        self._active_tasks[run_id] = task
        return run_row

    async def recover_run(
        self,
        run_id: str,
        *,
        go_client: Optional[httpx.AsyncClient] = None,
        on_pipeline_state: Optional[Callable[[str, str, Optional[str]], None]] = None,
    ) -> Dict[str, Any]:
        """Resume a ``PAUSED`` / recoverable run cleanly from its persisted checkpoint."""
        store = self.store
        run = await asyncio.to_thread(store.get_run, run_id)
        if not run:
            raise KeyError(f"Run '{run_id}' not found")

        canon, meta_hint = to_canonical_status(run.get("status") or "paused")
        meta = dict(run.get("meta") or {})
        is_recoverable = bool(
            run.get("recoverable")
            or meta.get("recoverable")
            or meta_hint.get("recoverable")
            or canon == LifecycleState.PAUSED
        )
        if canon != LifecycleState.PAUSED or not is_recoverable:
            raise ValueError(
                f"Run '{run_id}' is in state {canon.value} (recoverable={is_recoverable}) and cannot be recovered"
            )

        checkpoint = await asyncio.to_thread(store.get_latest_checkpoint, run_id)
        resume_phase = str(
            (checkpoint or {}).get("phase")
            or run.get("current_phase")
            or "RECON"
        )
        kind = str(run.get("kind") or "pipeline")
        target = str(run.get("target") or "")
        engagement_id = run.get("engagement_id")
        engine = str(meta.get("engine") or "claude")
        prompt = str(meta.get("prompt") or "")
        mode = str(meta.get("mode") or "full")
        model = str(meta.get("model") or "")
        coverage = float(meta.get("coverage", 0.85))
        max_cycles = int(meta.get("max_cycles", 10))
        proxy = meta.get("proxy")
        scope = list(meta.get("in_scope") or ([target] if target else []))
        out_of_scope = list(meta.get("out_of_scope") or [])
        backend = str(meta.get("backend") or self.resolve_backend(kind, engine, prompt))

        updated_meta = {
            **meta,
            "recoverable": False,
            "recovered_from_phase": resume_phase,
            "recovered_at": time.time(),
            "canonical_status": LifecycleState.RUNNING.value,
        }
        updated = await asyncio.to_thread(
            store.update_run,
            run_id,
            status="running",
            current_phase=resume_phase,
            meta=updated_meta,
            error="",
        )
        handle = GLOBAL_RUN_CONTROLLER.register(
            run_id,
            task=None,
            kind=kind,
            meta={"target": target, **updated_meta},
        )
        await self._event_bus.publish(
            "run.recovered",
            {
                "run_id": run_id,
                "resumed_phase": resume_phase,
                "checkpoint_id": (checkpoint or {}).get("checkpoint_id"),
                "status": "running",
                "canonical_status": LifecycleState.RUNNING.value,
            },
            run_id=run_id,
            engagement_id=engagement_id,
            source="orchestrator",
        )
        task = self._launch_run_coroutine(
            run_id=run_id,
            handle=handle,
            backend=backend,
            kind=kind,
            target=target,
            engagement_id=engagement_id,
            scope=scope,
            out_of_scope=out_of_scope,
            mode=mode,
            prompt=prompt,
            engine=engine,
            model=model,
            coverage=coverage,
            max_cycles=max_cycles,
            proxy=proxy,
            resume_phase=resume_phase,
            go_client=go_client,
            on_pipeline_state=on_pipeline_state,
        )
        self._active_tasks[run_id] = task
        return updated or run

    def _launch_run_coroutine(
        self,
        *,
        run_id: str,
        handle: Any,
        backend: str,
        kind: str,
        target: str,
        engagement_id: Optional[str],
        scope: List[str],
        out_of_scope: List[str],
        mode: str,
        prompt: str,
        engine: str,
        model: str,
        coverage: float,
        max_cycles: int,
        proxy: Optional[str],
        resume_phase: Optional[str],
        go_client: Optional[httpx.AsyncClient],
        on_pipeline_state: Optional[Callable[[str, str, Optional[str]], None]],
    ) -> asyncio.Task[Any]:
        coro = self._execute_run(
            run_id=run_id,
            backend=backend,
            kind=kind,
            target=target,
            engagement_id=engagement_id,
            scope=scope,
            out_of_scope=out_of_scope,
            mode=mode,
            prompt=prompt,
            engine=engine,
            model=model,
            coverage=coverage,
            max_cycles=max_cycles,
            proxy=proxy,
            resume_phase=resume_phase,
            go_client=go_client,
            on_pipeline_state=on_pipeline_state,
        )
        task = asyncio.create_task(coro)
        handle.task = task
        handle.state = "running"
        handle.started_at = time.time()
        task.add_done_callback(lambda t, rid=run_id: GLOBAL_RUN_CONTROLLER._on_task_done(rid, t))
        task.add_done_callback(lambda _t, rid=run_id: self._active_tasks.pop(rid, None))
        return task

    async def _execute_run(
        self,
        *,
        run_id: str,
        backend: str,
        kind: str,
        target: str,
        engagement_id: Optional[str],
        scope: List[str],
        out_of_scope: List[str],
        mode: str,
        prompt: str,
        engine: str,
        model: str,
        coverage: float,
        max_cycles: int,
        proxy: Optional[str],
        resume_phase: Optional[str],
        go_client: Optional[httpx.AsyncClient],
        on_pipeline_state: Optional[Callable[[str, str, Optional[str]], None]],
    ) -> None:
        store = self.store
        root_task = self.agent_manager.create_task(
            run_id=run_id,
            title=f"{kind}:{backend} ({target or engine})",
            role=backend,
            input_data={"target": target, "mode": mode, "coverage": coverage, "max_cycles": max_cycles},
        )
        try:
            root_task.transition_to(LifecycleState.RUNNING)
            await asyncio.to_thread(
                store.upsert_task_node,
                task_id=root_task.task_id,
                run_id=run_id,
                title=root_task.title,
                role=root_task.role,
                status=root_task.state.value,
                started_at=root_task.started_at,
            )

            if backend == "vram_pipeline":
                result_meta = await self._run_vram_backend(run_id, target, engagement_id)
            elif backend == "omni_hunter":
                result_meta = await self._run_omni_hunter_backend(
                    run_id, target, engagement_id, scope, coverage, max_cycles
                )
            elif backend == "pipeline_orchestrator":
                result_meta = await self._run_hunter_pipeline_backend(
                    run_id, target, engagement_id, mode, proxy
                )
            elif backend == "go_artex":
                result_meta = await self._run_go_artex_backend(
                    run_id, target, engagement_id, go_client=go_client
                )
            elif backend == "cli_engine":
                result_meta = await self._run_cli_engine_backend(
                    run_id, target, engagement_id, engine, model, prompt, scope, out_of_scope
                )
            else:
                result_meta = await self._run_live_scanner_backend(
                    run_id=run_id,
                    root_task_id=root_task.task_id,
                    target=target,
                    mode=mode,
                    scope=scope,
                    out_of_scope=out_of_scope,
                    engagement_id=engagement_id,
                    kind=kind,
                    proxy=proxy,
                    resume_phase=resume_phase,
                    on_pipeline_state=on_pipeline_state,
                )

            if result_meta.get("cancelled"):
                await self._finalize_cancelled(run_id, root_task, target, on_pipeline_state)
                return

            existing_run = await asyncio.to_thread(store.get_run, run_id) or {}
            merged_meta = dict(existing_run.get("meta") or {})
            merged_meta.update(result_meta)
            merged_meta["canonical_status"] = LifecycleState.COMPLETED.value
            merged_meta["recoverable"] = False

            root_task.transition_to(LifecycleState.COMPLETED)
            await run_without_cancel(
                asyncio.to_thread,
                store.upsert_task_node,
                task_id=root_task.task_id,
                run_id=run_id,
                title=root_task.title,
                role=root_task.role,
                status=root_task.state.value,
                output_data={"scan_stats": merged_meta.get("scan_stats", {})},
                finished_at=root_task.finished_at,
            )
            await run_without_cancel(
                asyncio.to_thread,
                store.update_run,
                run_id,
                status="completed",
                current_phase="DONE",
                progress=1.0,
                meta=merged_meta,
                finished_at=time.time(),
            )
            await run_without_cancel(
                asyncio.to_thread,
                store.save_checkpoint,
                run_id=run_id,
                phase="DONE",
                state={"progress": 1.0, "backend": backend, "completed": True},
                recoverable=False,
                reason="Run completed",
            )
            scan_stats = merged_meta.get("scan_stats") or {}
            await self._event_bus.publish(
                "run.completed",
                {
                    "run_id": run_id,
                    "target": target,
                    "mode": mode,
                    "backend": backend,
                    "assets_count": int(scan_stats.get("assets", 0)),
                    "live_endpoints": int(scan_stats.get("live_endpoints", 0)),
                    "findings_count": int(scan_stats.get("findings", 0)),
                },
                run_id=run_id,
                engagement_id=engagement_id,
                source=kind,
            )
            if on_pipeline_state and target:
                on_pipeline_state(target, "completed", "DONE")
        except asyncio.CancelledError:
            await self._finalize_cancelled(run_id, root_task, target, on_pipeline_state)
            raise
        except Exception as exc:
            logger.exception("RuntimeOrchestrator run %s (%s) failed", run_id, backend)
            if root_task.state not in {LifecycleState.COMPLETED, LifecycleState.FAILED, LifecycleState.CANCELLED}:
                root_task.transition_to(LifecycleState.FAILED, error=str(exc)[:500])
            await run_without_cancel(
                asyncio.to_thread,
                store.upsert_task_node,
                task_id=root_task.task_id,
                run_id=run_id,
                title=root_task.title,
                role=root_task.role,
                status=LifecycleState.FAILED.value,
                error=str(exc)[:500],
                finished_at=time.time(),
            )
            await run_without_cancel(
                asyncio.to_thread,
                store.update_run,
                run_id,
                status="failed",
                error=str(exc),
                meta={"canonical_status": LifecycleState.FAILED.value, "recoverable": False},
                finished_at=time.time(),
            )
            await self._event_bus.publish(
                "run.failed",
                {"run_id": run_id, "backend": backend, "error": str(exc)},
                run_id=run_id,
                engagement_id=engagement_id,
                source=kind,
            )
            if on_pipeline_state and target:
                on_pipeline_state(target, "failed", str(exc))

    async def _finalize_cancelled(
        self,
        run_id: str,
        root_task: Any,
        target: str,
        on_pipeline_state: Optional[Callable[[str, str, Optional[str]], None]],
    ) -> None:
        store = self.store
        if root_task.state not in {LifecycleState.COMPLETED, LifecycleState.FAILED, LifecycleState.CANCELLED}:
            root_task.transition_to(LifecycleState.CANCELLED, error="Cancelled")
        await run_without_cancel(
            asyncio.to_thread,
            store.upsert_task_node,
            task_id=root_task.task_id,
            run_id=run_id,
            title=root_task.title,
            role=root_task.role,
            status=LifecycleState.CANCELLED.value,
            error="Cancelled",
            finished_at=time.time(),
        )
        await run_without_cancel(
            asyncio.to_thread,
            store.update_run,
            run_id,
            status="stopped",
            meta={"canonical_status": LifecycleState.CANCELLED.value, "recoverable": False},
            finished_at=time.time(),
        )
        if on_pipeline_state and target:
            on_pipeline_state(target, "stopped", None)

    # ── Concrete Backends ────────────────────────────────────────────────────

    async def _run_live_scanner_backend(
        self,
        *,
        run_id: str,
        root_task_id: str,
        target: str,
        mode: str,
        scope: List[str],
        out_of_scope: List[str],
        engagement_id: Optional[str],
        kind: str,
        proxy: Optional[str],
        resume_phase: Optional[str],
        on_pipeline_state: Optional[Callable[[str, str, Optional[str]], None]],
    ) -> Dict[str, Any]:
        store = self.store
        phase_delay = float(os.environ.get("HUNTER_PIPELINE_PHASE_DELAY_S", "0.35"))

        if resume_phase not in {"SCOPE_VERIFIED", "SCAN", "WEB", "REPORT"}:
            recon_sub = self.agent_manager.create_subtask(
                run_id=run_id,
                task_id=root_task_id,
                title="RECON_INIT",
            )
            await asyncio.to_thread(store.update_run, run_id, status="running", current_phase="RECON", progress=0.15)
            await asyncio.to_thread(
                store.save_checkpoint,
                run_id=run_id,
                phase="RECON",
                state={"progress": 0.15, "target": target, "mode": mode},
                recoverable=True,
            )
            await self._event_bus.publish(
                "pipeline.progress",
                {"phase": "RECON", "progress": 0.15, "target": target, "mode": mode},
                run_id=run_id,
                engagement_id=engagement_id,
                source=kind,
            )
            if on_pipeline_state and target:
                on_pipeline_state(target, "running", "RECON")
            if phase_delay > 0:
                await asyncio.sleep(phase_delay)
            if not await GLOBAL_RUN_CONTROLLER.checkpoint(run_id):
                return {"cancelled": True}
            recon_sub.transition_to(LifecycleState.RUNNING)
            recon_sub.transition_to(LifecycleState.COMPLETED)
            await asyncio.to_thread(
                store.upsert_subtask_node,
                subtask_id=recon_sub.subtask_id,
                task_id=root_task_id,
                run_id=run_id,
                title=recon_sub.title,
                status=recon_sub.state.value,
                attempt=recon_sub.attempt,
                started_at=recon_sub.started_at,
                finished_at=recon_sub.finished_at,
            )

        from core.scope_guard import ScopeGuard

        guard = ScopeGuard(in_scope=scope or ([target] if target else []), out_of_scope=out_of_scope)
        await asyncio.to_thread(store.update_run, run_id, status="running", current_phase="SCOPE_VERIFIED", progress=0.30)
        await asyncio.to_thread(
            store.save_checkpoint,
            run_id=run_id,
            phase="SCOPE_VERIFIED",
            state={"progress": 0.30, "in_scope": guard.in_scope, "out_of_scope": guard.out_of_scope},
            recoverable=True,
        )
        await self._event_bus.publish(
            "pipeline.scope_verified",
            {"in_scope": guard.in_scope, "out_of_scope": guard.out_of_scope},
            run_id=run_id,
            engagement_id=engagement_id,
            source="pipeline",
        )
        if phase_delay > 0:
            await asyncio.sleep(min(phase_delay, 0.25))
        if not await GLOBAL_RUN_CONTROLLER.checkpoint(run_id):
            return {"cancelled": True}

        discovered_assets: List[Dict[str, Any]] = []
        discovered_findings: List[Dict[str, Any]] = []
        scan_stats: Dict[str, Any] = {"assets": 0, "live_endpoints": 0, "findings": 0}

        if target:
            from core.global_state import GLOBAL_EVIDENCE_STORE
            from core.live_scanner import run_live_security_scan

            scan_sub = self.agent_manager.create_subtask(
                run_id=run_id,
                task_id=root_task_id,
                title="LIVE_SECURITY_SCAN",
            )

            async def _phase_cb(phase_name: str, pct: float, detail: Dict[str, Any]) -> bool:
                await asyncio.to_thread(store.update_run, run_id, status="running", current_phase=phase_name, progress=pct)
                await asyncio.to_thread(
                    store.save_checkpoint,
                    run_id=run_id,
                    phase=phase_name,
                    state={"progress": pct, "target": target, "detail": detail},
                    recoverable=True,
                )
                await self._event_bus.publish(
                    "pipeline.progress",
                    {"phase": phase_name, "progress": pct, "target": target, "mode": mode, **detail},
                    run_id=run_id,
                    engagement_id=engagement_id,
                    source=kind,
                )
                if on_pipeline_state and target:
                    on_pipeline_state(target, "running", phase_name)
                return await GLOBAL_RUN_CONTROLLER.checkpoint(run_id)

            async def _exec_scan(_sub: Any) -> Dict[str, Any]:
                return await run_live_security_scan(
                    target=target,
                    run_id=run_id,
                    mode=mode,
                    proxy=proxy,
                    phase_cb=_phase_cb,
                )

            scan_task = self.agent_manager.spawn_subtask(scan_sub, _exec_scan)
            scan_res = await scan_task
            if scan_res.get("cancelled"):
                return {"cancelled": True}

            discovered_assets = list(scan_res.get("assets") or [])
            discovered_findings = list(scan_res.get("findings") or [])
            observations = list(scan_res.get("observations") or [])
            scan_stats = {
                "assets": len(discovered_assets),
                "live_endpoints": int(scan_res.get("live_count") or 0),
                "endpoints": int(scan_res.get("endpoints_count") or 0),
                "findings": len(discovered_findings),
            }

            for obs in observations:
                GLOBAL_EVIDENCE_STORE.add_evidence(
                    run_id=run_id,
                    source_worker=kind,
                    source_tool=str(obs.get("source_tool") or "native_scanner"),
                    evidence_type=str(obs.get("evidence_type") or "observation"),
                    content=str(obs.get("content") or ""),
                    confidence=float(obs.get("confidence") or 0.9),
                    metadata={
                        "target": str(obs.get("target") or target),
                        "title": str(obs.get("title") or "Recon Observation"),
                    },
                )

            for fd in discovered_findings:
                ev_type = (
                    "proof"
                    if str(fd.get("severity") or "").upper() in {"CRITICAL", "HIGH", "MEDIUM"}
                    else "anomaly"
                )
                GLOBAL_EVIDENCE_STORE.add_evidence(
                    run_id=run_id,
                    source_worker=kind,
                    source_tool="native_security_audit",
                    evidence_type=ev_type,
                    content=str(fd.get("evidence") or ""),
                    confidence=float(fd.get("confidence") or 0.9),
                    metadata={
                        "target": str(fd.get("endpoint") or target),
                        "title": str(fd.get("title") or "Finding"),
                        "severity": str(fd.get("severity") or "INFO"),
                        "cvss_score": float(fd.get("cvss_score") or 0.0),
                        "vuln_class": str(fd.get("vuln_class") or "web"),
                    },
                )
                await self._event_bus.publish(
                    "finding.discovered",
                    {
                        "title": fd.get("title"),
                        "severity": fd.get("severity"),
                        "endpoint": fd.get("endpoint"),
                        "vuln_class": fd.get("vuln_class"),
                    },
                    run_id=run_id,
                    engagement_id=engagement_id,
                    source=kind,
                )

            if discovered_assets:
                await self._event_bus.publish(
                    "run.assets",
                    {
                        "target": target,
                        "assets_count": len(discovered_assets),
                        "live_endpoints": scan_stats["live_endpoints"],
                        "findings_count": len(discovered_findings),
                    },
                    run_id=run_id,
                    engagement_id=engagement_id,
                    source=kind,
                )

            if scan_stats["live_endpoints"] > 0 and not target.lower().endswith(
                (".example", ".invalid", ".test")
            ):
                await asyncio.to_thread(
                    self._export_scan_artifacts,
                    run_id,
                    target,
                    mode,
                    discovered_findings,
                )

        if not await GLOBAL_RUN_CONTROLLER.checkpoint(run_id):
            return {"cancelled": True}

        return {
            "discovered_assets": discovered_assets,
            "discovered_findings": discovered_findings,
            "scan_stats": scan_stats,
        }

    @staticmethod
    def _export_scan_artifacts(
        run_id: str,
        target: str,
        mode: str,
        discovered_findings: List[Dict[str, Any]],
    ) -> None:
        sessions_dir = _DATA_DIR / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(
            sessions_dir / f"{run_id}.json",
            {
                "id": run_id,
                "target": target,
                "mode": mode,
                "status": "completed",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "findings": [
                    {
                        "id": fd.get("id"),
                        "title": fd.get("title"),
                        "description": (fd.get("poc_details") or {}).get("description", ""),
                        "severity": str(fd.get("severity") or "info").lower(),
                        "cvss_score": float(fd.get("cvss_score") or 0.0),
                        "tool": "hunter_live_scanner",
                        "evidence": fd.get("evidence", ""),
                        "recommendation": "Review HTTP security configuration and verify finding reproduction.",
                    }
                    for fd in discovered_findings
                ],
            },
        )
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        for idx, fd in enumerate(discovered_findings[:8]):
            atomic_write_json(
                _REPORTS_DIR / f"{run_id}_f{idx + 1}.json",
                {
                    "report_id": fd.get("id") or f"{run_id}-{idx + 1}",
                    "title": fd.get("title", "Finding"),
                    "severity": str(fd.get("severity") or "INFO").capitalize(),
                    "vulnerability_type": fd.get("vuln_class", "web"),
                    "target": fd.get("endpoint") or target,
                    "platform": "HackerOne",
                    "report_ready": str(fd.get("status", "")).upper() == "CONFIRMED",
                    "confidence": float(fd.get("confidence") or 0.9),
                    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "summary": (fd.get("poc_details") or {}).get("description", ""),
                    "evidence": fd.get("evidence", ""),
                    "remediation": "Harden server headers, TLS, access controls, and input output encoding.",
                },
            )

    async def _run_vram_backend(
        self, run_id: str, target: str, engagement_id: Optional[str]
    ) -> Dict[str, Any]:
        from core.pipeline.vram_sequential_pipeline import vram_pipeline

        await asyncio.to_thread(self.store.update_run, run_id, current_phase="VRAM_PIPELINE", progress=0.25)
        res = await vram_pipeline.execute_pipeline(target)
        res_dict = (
            dataclasses.asdict(res)
            if dataclasses.is_dataclass(res)
            else (res if isinstance(res, dict) else {"raw": str(res)})
        )
        findings = list(res_dict.get("findings") or [])
        return {
            "discovered_findings": findings,
            "scan_stats": {"assets": int(res_dict.get("total_endpoints_crawled", 0)), "live_endpoints": 0, "findings": len(findings)},
            "vram_result": res_dict,
        }

    async def _run_omni_hunter_backend(
        self,
        run_id: str,
        target: str,
        engagement_id: Optional[str],
        scope: List[str],
        coverage: float,
        max_cycles: int,
    ) -> Dict[str, Any]:
        from core.engine.omni_hunter_engine import OmniHunterEngine

        await asyncio.to_thread(self.store.update_run, run_id, current_phase="OMNI_ENGINE", progress=0.20)
        engine = OmniHunterEngine(
            target=target,
            in_scope=scope or [target],
            target_coverage=coverage,
            max_cycles=max_cycles,
        )
        run_fn = getattr(engine, "run_full_assessment", None) or getattr(engine, "run", None)
        res = await run_fn() if callable(run_fn) else {}
        res_dict = (
            dataclasses.asdict(res)
            if dataclasses.is_dataclass(res)
            else (res if isinstance(res, dict) else {"raw": str(res)})
        )
        findings = list(res_dict.get("findings") or res_dict.get("confirmed_findings") or [])
        return {
            "discovered_findings": findings,
            "scan_stats": {"assets": int(res_dict.get("assets_count", 0)), "live_endpoints": 0, "findings": len(findings)},
            "omni_result": res_dict,
        }

    async def _run_hunter_pipeline_backend(
        self,
        run_id: str,
        target: str,
        engagement_id: Optional[str],
        mode: str,
        proxy: Optional[str],
    ) -> Dict[str, Any]:
        from hunter_ai.pipeline import HunterPipelineOrchestrator

        await asyncio.to_thread(self.store.update_run, run_id, current_phase="HUNTER_PIPELINE", progress=0.20)
        orch = HunterPipelineOrchestrator(target=target, mode=mode, proxy=proxy)
        res = await orch.run()
        res_dict = res if isinstance(res, dict) else {"raw": str(res)}
        return {
            "discovered_findings": list(res_dict.get("findings") or []),
            "scan_stats": {
                "assets": int(res_dict.get("live_assets_count", 0)),
                "live_endpoints": int(res_dict.get("endpoints_count", 0)),
                "findings": int(res_dict.get("findings_count", 0)),
            },
            "pipeline_result": res_dict,
        }

    async def _run_cli_engine_backend(
        self,
        run_id: str,
        target: str,
        engagement_id: Optional[str],
        engine_name: str,
        model: str,
        prompt: str,
        scope: List[str],
        out_of_scope: List[str],
    ) -> Dict[str, Any]:
        from agents.base_agent import AgentTask
        from core.scope_guard import ScopeGuard
        from engines.worker import EngineWorker, EngineWorkerConfig

        await asyncio.to_thread(self.store.update_run, run_id, current_phase="CLI_ENGINE", progress=0.25)
        cfg = EngineWorkerConfig(engine=engine_name, model=model)
        guard = ScopeGuard(in_scope=scope, out_of_scope=out_of_scope) if (scope or out_of_scope) else None
        worker = EngineWorker(cfg, scope_guard=guard)
        task = AgentTask(target=target, mode="engine", extra={"prompt": prompt})
        res = await worker.run(task)
        return {
            "discovered_findings": list(getattr(res, "findings", []) or []),
            "engine_output": str((getattr(res, "raw_output", {}) or {}).get("text", "")),
            "scan_stats": {"assets": 0, "live_endpoints": 0, "findings": len(getattr(res, "findings", []) or [])},
        }

    async def _run_go_artex_backend(
        self,
        run_id: str,
        target: str,
        engagement_id: Optional[str],
        *,
        go_client: Optional[httpx.AsyncClient] = None,
    ) -> Dict[str, Any]:
        from hunter_backend.auth import get_or_create_api_token

        await asyncio.to_thread(self.store.update_run, run_id, current_phase="GO_ARTEX_DISPATCH", progress=0.25)
        owned_client = go_client is None
        client = go_client or httpx.AsyncClient(
            base_url=self.artex_base_url,
            timeout=httpx.Timeout(connect=2.5, read=20.0, write=10.0, pool=5.0),
            headers={"Authorization": f"Bearer {get_or_create_api_token()}"},
        )
        try:
            resp = await client.post(
                "/api/v1/scan",
                json={"target": target},
                headers={"Idempotency-Key": run_id},
            )
            if resp.status_code >= 400:
                raise RuntimeError(f"Go ARTEX /api/v1/scan failed ({resp.status_code}): {resp.text[:300]}")
            dispatch_body = resp.json() if resp.content else {}
            sync_summary = await self.sync_artex_to_store(
                go_client=client,
                engagement_id=engagement_id,
                run_id=run_id,
            )
            return {
                "artex_dispatch": dispatch_body,
                "artex_sync": sync_summary,
                "discovered_assets": sync_summary.get("assets", []),
                "discovered_findings": sync_summary.get("findings", []),
                "scan_stats": {
                    "assets": len(sync_summary.get("assets", [])),
                    "live_endpoints": len(sync_summary.get("assets", [])),
                    "findings": len(sync_summary.get("findings", [])),
                },
            }
        finally:
            if owned_client:
                await client.aclose()

    async def sync_artex_to_store(
        self,
        *,
        go_client: Optional[httpx.AsyncClient] = None,
        engagement_id: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Synchronize Go ARTEX-Pro engagements, assets, tasks, and CANDIDATE findings into PlatformStore."""
        from hunter_backend.auth import get_or_create_api_token

        owned_client = go_client is None
        client = go_client or httpx.AsyncClient(
            base_url=self.artex_base_url,
            timeout=httpx.Timeout(connect=2.0, read=10.0, write=5.0, pool=5.0),
            headers={"Authorization": f"Bearer {get_or_create_api_token()}"},
        )
        synced_engagements: List[Dict[str, Any]] = []
        synced_assets: List[Dict[str, Any]] = []
        synced_findings: List[Dict[str, Any]] = []
        synced_tasks: List[Dict[str, Any]] = []
        try:
            r_eng = await client.get("/api/v1/engagements")
            if r_eng.status_code < 400:
                raw_engs = r_eng.json()
                if isinstance(raw_engs, list):
                    for item in raw_engs:
                        if not isinstance(item, dict):
                            continue
                        tgt = str(item.get("target_url") or item.get("authorized_scope") or "").strip()
                        if not tgt:
                            continue
                        eng = await asyncio.to_thread(
                            self.store.upsert_engagement,
                            target=tgt,
                            name=str(item.get("code") or tgt),
                            in_scope=[str(item.get("authorized_scope") or tgt)],
                            status=str(item.get("status") or "authorized").lower(),
                            source="go_artex",
                            metadata={"artex_engagement_id": item.get("id")},
                        )
                        synced_engagements.append(eng)

            r_assets = await client.get("/api/v1/assets")
            if r_assets.status_code < 400 and isinstance(r_assets.json(), list):
                synced_assets = list(r_assets.json())

            r_findings = await client.get("/api/v1/findings")
            if r_findings.status_code < 400 and isinstance(r_findings.json(), list):
                for fd in r_findings.json():
                    if not isinstance(fd, dict):
                        continue
                    # Enforce Evidence Court boundary: Go worker findings enter as CANDIDATE unless already adjudicated
                    norm_fd = dict(fd)
                    raw_status = str(norm_fd.get("status") or "CANDIDATE").upper()
                    if raw_status in {"", "TRIAGED", "NEW"}:
                        norm_fd["status"] = "CANDIDATE"
                    synced_findings.append(norm_fd)

            r_tasks = await client.get("/api/v1/tasks")
            if r_tasks.status_code < 400 and isinstance(r_tasks.json(), list):
                for t in r_tasks.json():
                    if not isinstance(t, dict):
                        continue
                    synced_tasks.append(t)
                    if run_id and t.get("id"):
                        canon, _ = to_canonical_status(str(t.get("status") or "QUEUED"))
                        await asyncio.to_thread(
                            self.store.upsert_task_node,
                            task_id=f"artex_{t['id']}",
                            run_id=run_id,
                            title=str(t.get("title") or "ARTEX Task"),
                            role=str(t.get("agent_role") or "artex"),
                            status=canon.value,
                            priority=int(t.get("priority") or 5),
                            input_data=dict(t.get("input_context") or {}),
                            output_data=dict(t.get("output_summary") or {}),
                        )

            await self._event_bus.publish(
                "artex.synced",
                {
                    "engagements": len(synced_engagements),
                    "assets": len(synced_assets),
                    "findings": len(synced_findings),
                    "tasks": len(synced_tasks),
                },
                run_id=run_id,
                engagement_id=engagement_id,
                source="go_artex",
            )
            return {
                "ok": True,
                "engagements": synced_engagements,
                "assets": synced_assets,
                "findings": synced_findings,
                "tasks": synced_tasks,
            }
        finally:
            if owned_client:
                await client.aclose()
