"""Resource Manager — Delegates Local GPU Lock Scheduling to Canonical GPUScheduler.

Preserves the legacy ``ResourceManager`` API (``exclusive_gpu``, ``run_local_model``,
``run_sequential``, ``status``, ``is_gpu_free``) while delegating all GPU lock
serialization, priority scheduling, and auto-unload lifecycle to the process-wide
``core.llm.gpu_scheduler.GPUScheduler`` singleton.

Supports zero-arg ``ResourceManager()`` construction (fixing previous crashes in
``core/exploit_factory.py`` and ``agents/refining_agent.py``).
"""
from __future__ import annotations

from contextlib import asynccontextmanager
import logging
from typing import Any, AsyncIterator, Callable, Dict, Optional

from core.llm.gpu_scheduler import (
    GPUScheduler,
    PRIORITY_BACKGROUND,
    get_gpu_scheduler,
)
from core.llm.manifest import get_model_manifest
from models.ollama_manager import OllamaManager

log = logging.getLogger("resource_manager")


class ResourceManager:
    """Process-wide GPU scheduler shim preserving legacy ``ResourceManager`` callers."""

    def __init__(
        self,
        ollama_manager: Optional[OllamaManager] = None,
        *,
        scheduler: Optional[GPUScheduler] = None,
    ) -> None:
        self.ollama: OllamaManager = ollama_manager or OllamaManager()
        self._scheduler: GPUScheduler = scheduler or get_gpu_scheduler()

    @asynccontextmanager
    async def exclusive_gpu(
        self,
        model_name: str,
        *,
        priority: int = PRIORITY_BACKGROUND,
        keep_alive: Optional[int] = None,
        unload_on_release: Optional[bool] = None,
    ) -> AsyncIterator[OllamaManager]:
        """Acquire exclusive GPU access via the process-wide ``GPUScheduler``."""
        log.info("[GPU] Requesting lock for: %s", model_name)
        async with self._scheduler.acquire(
            model_name,
            priority=priority,
            keep_alive=keep_alive,
            ollama_manager=self.ollama,
            unload_on_release=unload_on_release,
        ):
            log.info("[GPU] Lock acquired: %s", model_name)
            yield self.ollama
            log.info("[GPU] Releasing lease for: %s", model_name)

    async def run_local_model(
        self,
        model_name: str,
        messages: list,
        temperature: float = 0.3,
        num_ctx: Optional[int] = None,
        progress_cb: Optional[Callable[[Dict[str, Any]], Any]] = None,
        *,
        priority: int = PRIORITY_BACKGROUND,
        keep_alive: Optional[int] = None,
    ) -> str:
        """Run a local model exclusively on the GPU via ``GPUScheduler``."""
        if not self.ollama:
            log.warning("Ollama client instance not configured / offline")
            return ""

        manifest = get_model_manifest()
        eff_ctx = int(num_ctx) if (num_ctx and num_ctx > 0) else manifest.context_window_for(model_name, default=8192)
        eff_keep_alive = self._scheduler.default_keep_alive if keep_alive is None else max(0, int(keep_alive))

        if progress_cb:
            await progress_cb({
                "event": "gpu_queued",
                "model": model_name,
                "queue": self._scheduler.status().get("queue_length", 0) + 1,
            })

        async with self.exclusive_gpu(
            model_name,
            priority=priority,
            keep_alive=eff_keep_alive,
        ) as ollama:
            if progress_cb:
                await progress_cb({
                    "event": "gpu_active",
                    "model": model_name,
                })

            async def _on_token(token: str) -> None:
                if progress_cb:
                    try:
                        await progress_cb({
                            "event": "chat_token",
                            "token": token,
                            "model": model_name,
                        })
                    except Exception:  # noqa: BLE001
                        pass

            result = await ollama.chat_stream(
                model_name=model_name,
                messages=messages,
                keep_alive=eff_keep_alive,
                temperature=temperature,
                num_ctx=eff_ctx,
                token_cb=_on_token,
            )

            if progress_cb:
                await progress_cb({
                    "event": "gpu_done",
                    "model": model_name,
                    "chars": len(result),
                })

            return result

    async def run_sequential(
        self,
        tasks: list,
        progress_cb: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> Dict[str, str]:
        """Run local model tasks sequentially under the shared ``GPUScheduler``."""
        results: Dict[str, str] = {}
        for task in tasks:
            model = task["model"]
            name = task.get("name", model)
            messages = task["messages"]
            temperature = task.get("temperature", 0.3)
            num_ctx = task.get("num_ctx")

            if progress_cb:
                await progress_cb({
                    "event": "sequential_step",
                    "step": name,
                    "model": model,
                })

            result = await self.run_local_model(
                model_name=model,
                messages=messages,
                temperature=temperature,
                num_ctx=num_ctx,
                progress_cb=progress_cb,
                keep_alive=0,
            )
            results[name] = result

        return results

    @property
    def status(self) -> dict:
        return self._scheduler.status()

    def is_gpu_free(self) -> bool:
        return not self._scheduler.is_locked()


__all__ = ["ResourceManager"]
