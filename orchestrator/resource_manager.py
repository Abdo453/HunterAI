"""
Resource Manager — GPU Lock System
ضمان موديل محلي واحد فقط على الـ GPU في أي وقت
API Models تشتغل بدون قيود (no local GPU)
"""
import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from models.ollama_manager import OllamaManager

log = logging.getLogger("resource_manager")


@dataclass
class GPUStatus:
    locked: bool = False
    current_model: Optional[str] = None
    lock_time: float = 0.0
    queue_length: int = 0
    total_runs: int = 0
    total_unloads: int = 0


class ResourceManager:
    """
    قفل GPU حصري — Local Model Scheduler
    
    القاعدة الأساسية:
    - موديل محلي واحد فقط على GPU في أي وقت
    - بعد انتهاء المهمة → unload → تحرير القفل
    - API Models تشتغل بالتوازي بدون قيود
    """

    def __init__(self, ollama_manager: OllamaManager):
        self.ollama = ollama_manager
        self._gpu_lock = asyncio.Lock()
        self._status = GPUStatus()
        self._queue: asyncio.Queue = asyncio.Queue()

    @asynccontextmanager
    async def exclusive_gpu(self, model_name: str):
        """
        Context manager للاستخدام الحصري للـ GPU

        Usage:
            async with resource_manager.exclusive_gpu("qwen2.5-coder:14b") as gpu:
                result = await gpu.run(...)
        """
        queue_pos = self._status.queue_length
        log.info(f"[GPU] Requesting lock for: {model_name} (queue: {queue_pos})")

        async with self._gpu_lock:
            self._status.locked = True
            self._status.current_model = model_name
            self._status.lock_time = time.time()
            self._status.total_runs += 1
            self._status.queue_length = max(0, self._status.queue_length - 1)

            log.info(f"[GPU] Lock acquired: {model_name}")

            try:
                yield self.ollama
            finally:
                # تفريغ الموديل وتحرير القفل
                log.info(f"[GPU] Releasing + unloading: {model_name}")
                if self.ollama and hasattr(self.ollama, "unload_model"):
                    try:
                        await self.ollama.unload_model(model_name)
                    except Exception:
                        pass
                await asyncio.sleep(0.5)  # ضمان استقرار الذاكرة
                self._status.locked = False
                self._status.current_model = None
                self._status.total_unloads += 1
                log.info(f"[GPU] Lock released. Total runs: {self._status.total_runs}")

    async def run_local_model(
        self,
        model_name: str,
        messages: list,
        temperature: float = 0.3,
        num_ctx: int = 4096,
        progress_cb=None
    ) -> str:
        """
        تشغيل موديل محلي بشكل حصري على الـ GPU
        يحجز القفل → يشغّل → يفرّغ تلقائياً
        """
        if not self.ollama:
            log.warning("Ollama client instance not configured / offline")
            return ""

        self._status.queue_length += 1

        if progress_cb:
            await progress_cb({
                "event": "gpu_queued",
                "model": model_name,
                "queue": self._status.queue_length
            })

        async with self.exclusive_gpu(model_name) as ollama:
            if progress_cb:
                await progress_cb({
                    "event": "gpu_active",
                    "model": model_name
                })

            async def _on_token(token: str):
                if progress_cb:
                    try:
                        await progress_cb({
                            "event": "chat_token",
                            "token": token,
                            "model": model_name
                        })
                    except Exception:
                        pass

            result = await ollama.chat_stream(
                model_name=model_name,
                messages=messages,
                keep_alive=0,  # تفريغ فوري بعد الانتهاء
                temperature=temperature,
                num_ctx=num_ctx,
                token_cb=_on_token
            )

            if progress_cb:
                await progress_cb({
                    "event": "gpu_done",
                    "model": model_name,
                    "chars": len(result)
                })

            return result

    async def run_sequential(
        self,
        tasks: list,  # [{"model": str, "messages": list, "name": str}]
        progress_cb=None
    ) -> Dict[str, str]:
        """
        تشغيل موديلات محلية بالتتابع — كل موديل يُنهي ويُفرَّغ قبل التالي
        """
        results = {}
        for task in tasks:
            model = task["model"]
            name = task.get("name", model)
            messages = task["messages"]
            temperature = task.get("temperature", 0.3)

            if progress_cb:
                await progress_cb({
                    "event": "sequential_step",
                    "step": name,
                    "model": model
                })

            result = await self.run_local_model(
                model_name=model,
                messages=messages,
                temperature=temperature,
                progress_cb=progress_cb
            )
            results[name] = result

        return results

    @property
    def status(self) -> dict:
        elapsed = time.time() - self._status.lock_time if self._status.locked else 0
        return {
            "locked": self._status.locked,
            "current_model": self._status.current_model,
            "elapsed_seconds": round(elapsed, 1),
            "queue_length": self._status.queue_length,
            "total_runs": self._status.total_runs,
            "total_unloads": self._status.total_unloads,
        }

    def is_gpu_free(self) -> bool:
        return not self._gpu_lock.locked()
