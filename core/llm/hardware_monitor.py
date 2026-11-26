"""Live cross-platform hardware, GPU/VRAM, and Ollama runtime telemetry monitor.

Collects real host telemetry without ever fabricating hardware metrics:
- CPU% and RAM usage via ``psutil`` (graceful degradation if unavailable).
- GPU/VRAM via ``pynvml`` or ``nvidia-smi`` (``shell=False``, bounded timeout);
  explicitly reports ``status="unavailable"`` on CPU-only hosts.
- Ollama ``GET /api/ps`` loaded models (SSRF-gated via ``validate_probe_base_url``).
- Active ``VRAMManager.currently_loaded_model`` and ``GPUScheduler`` state.
- Resolved hardware profile from ``ModelManifest``.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import shutil
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
import weakref

import httpx

from core.llm.gpu_scheduler import get_gpu_scheduler
from core.llm.manifest import get_model_manifest
from core.llm.probe import validate_probe_base_url

logger = logging.getLogger("hunter_ai.llm.hardware_monitor")

_vram_manager_refs: List[weakref.ref[Any]] = []


def register_vram_manager(vram_mgr: Any) -> None:
    """Register a ``VRAMManager`` instance for live ``currently_loaded_model`` inspection."""
    global _vram_manager_refs
    _vram_manager_refs = [ref for ref in _vram_manager_refs if ref() is not None]
    if not any(ref() is vram_mgr for ref in _vram_manager_refs):
        _vram_manager_refs.append(weakref.ref(vram_mgr))


def get_vram_manager_loaded_model() -> Optional[str]:
    """Return ``VRAMManager.currently_loaded_model`` from any live registered instance."""
    for ref in list(_vram_manager_refs):
        mgr = ref()
        if mgr is not None:
            loaded = getattr(mgr, "currently_loaded_model", None)
            if loaded:
                return str(loaded)
    # Fallback: check module-level pipeline singleton if already imported
    try:
        import sys

        mod = sys.modules.get("core.pipeline.vram_sequential_pipeline")
        if mod is not None:
            pipe = getattr(mod, "vram_pipeline", None)
            vram_mgr = getattr(pipe, "vram_mgr", None) if pipe is not None else None
            if vram_mgr is not None and getattr(vram_mgr, "currently_loaded_model", None):
                return str(vram_mgr.currently_loaded_model)
    except Exception:  # noqa: BLE001
        pass
    return None


def _probe_cpu_ram() -> Tuple[Dict[str, Any], Dict[str, Any]]:
    try:
        import psutil  # type: ignore[import-untyped]

        cpu_pct = float(psutil.cpu_percent(interval=None))
        vm = psutil.virtual_memory()
        cpu = {
            "status": "ok",
            "percent": round(cpu_pct, 1),
            "logical_cores": int(psutil.cpu_count(logical=True) or os.cpu_count() or 1),
            "physical_cores": int(psutil.cpu_count(logical=False) or os.cpu_count() or 1),
        }
        ram = {
            "status": "ok",
            "total_mb": round(vm.total / (1024 * 1024), 1),
            "used_mb": round(vm.used / (1024 * 1024), 1),
            "available_mb": round(vm.available / (1024 * 1024), 1),
            "percent": round(float(vm.percent), 1),
        }
        return cpu, ram
    except Exception as exc:  # noqa: BLE001
        return (
            {
                "status": "unavailable",
                "percent": None,
                "logical_cores": int(os.cpu_count() or 1),
                "physical_cores": None,
                "detail": str(exc),
            },
            {
                "status": "unavailable",
                "total_mb": None,
                "used_mb": None,
                "available_mb": None,
                "percent": None,
                "detail": str(exc),
            },
        )


def _probe_gpu_pynvml() -> Optional[List[Dict[str, Any]]]:
    try:
        import pynvml  # type: ignore[import-untyped]

        pynvml.nvmlInit()
        try:
            count = int(pynvml.nvmlDeviceGetCount())
            gpus: List[Dict[str, Any]] = []
            for idx in range(count):
                handle = pynvml.nvmlDeviceGetHandleByIndex(idx)
                name = pynvml.nvmlDeviceGetName(handle)
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
                util = None
                try:
                    u = pynvml.nvmlDeviceGetUtilizationRates(handle)
                    util = float(u.gpu)
                except Exception:  # noqa: BLE001
                    util = None
                total_mb = round(mem.total / (1024 * 1024), 1)
                used_mb = round(mem.used / (1024 * 1024), 1)
                free_mb = round(mem.free / (1024 * 1024), 1)
                pct = round((used_mb / total_mb) * 100.0, 1) if total_mb > 0 else 0.0
                gpus.append({
                    "index": idx,
                    "name": str(name),
                    "vram_total_mb": total_mb,
                    "vram_used_mb": used_mb,
                    "vram_free_mb": free_mb,
                    "vram_used_pct": pct,
                    "utilization_pct": util,
                })
            return gpus
        finally:
            try:
                pynvml.nvmlShutdown()
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        return None


def _probe_gpu_nvidia_smi(timeout_s: float = 2.0) -> Optional[List[Dict[str, Any]]]:
    binary = shutil.which("nvidia-smi")
    if not binary:
        return None
    cmd = [
        binary,
        "--query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu",
        "--format=csv,noheader,nounits",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            shell=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        gpus: List[Dict[str, Any]] = []
        for raw_line in proc.stdout.strip().splitlines():
            parts = [p.strip() for p in raw_line.split(",")]
            if len(parts) < 5:
                continue
            try:
                idx = int(parts[0])
                name = parts[1]
                total_mb = float(parts[2])
                used_mb = float(parts[3])
                free_mb = float(parts[4])
                util = float(parts[5]) if len(parts) > 5 and parts[5] not in ("", "N/A", "[N/A]") else None
                pct = round((used_mb / total_mb) * 100.0, 1) if total_mb > 0 else 0.0
                gpus.append({
                    "index": idx,
                    "name": name,
                    "vram_total_mb": round(total_mb, 1),
                    "vram_used_mb": round(used_mb, 1),
                    "vram_free_mb": round(free_mb, 1),
                    "vram_used_pct": pct,
                    "utilization_pct": util,
                })
            except ValueError:
                continue
        return gpus if gpus else None
    except Exception:  # noqa: BLE001
        return None


class HardwareMonitor:
    """Cross-platform host CPU, RAM, GPU/VRAM, and Ollama loaded-model monitor."""

    def __init__(
        self,
        *,
        ollama_host: Optional[str] = None,
        gpu_probe_fn: Optional[Callable[[], Optional[List[Dict[str, Any]]]]] = None,
        ollama_ps_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
    ) -> None:
        self._ollama_host_override = ollama_host
        self._gpu_probe_fn = gpu_probe_fn
        self._ollama_ps_fn = ollama_ps_fn

    def _effective_ollama_host(self) -> str:
        from models.ollama_manager import normalize_ollama_host

        manifest = get_model_manifest()
        return normalize_ollama_host(
            self._ollama_host_override
            or os.getenv("OLLAMA_HOST")
            or manifest.default_host
        )

    def gpu_snapshot(self) -> Dict[str, Any]:
        """Probe GPU/VRAM via pynvml or nvidia-smi, returning explicit unavailable on CPU-only."""
        source = "unavailable"
        gpus: Optional[List[Dict[str, Any]]] = None

        if self._gpu_probe_fn is not None:
            gpus = self._gpu_probe_fn()
            source = "custom" if gpus else "unavailable"
        else:
            gpus = _probe_gpu_pynvml()
            if gpus:
                source = "pynvml"
            else:
                gpus = _probe_gpu_nvidia_smi()
                if gpus:
                    source = "nvidia-smi"

        if not gpus:
            return {
                "status": "unavailable",
                "available": False,
                "source": "unavailable",
                "count": 0,
                "gpus": [],
                "vram_total_mb": 0.0,
                "vram_used_mb": 0.0,
                "vram_free_mb": 0.0,
                "vram_used_pct": 0.0,
            }

        total_mb = round(sum(float(g.get("vram_total_mb", 0.0)) for g in gpus), 1)
        used_mb = round(sum(float(g.get("vram_used_mb", 0.0)) for g in gpus), 1)
        free_mb = round(sum(float(g.get("vram_free_mb", 0.0)) for g in gpus), 1)
        used_pct = round((used_mb / total_mb) * 100.0, 1) if total_mb > 0 else 0.0
        return {
            "status": "available",
            "available": True,
            "source": source,
            "count": len(gpus),
            "gpus": gpus,
            "vram_total_mb": total_mb,
            "vram_used_mb": used_mb,
            "vram_free_mb": free_mb,
            "vram_used_pct": used_pct,
        }

    def ollama_ps_snapshot(self, timeout_s: float = 1.5) -> Dict[str, Any]:
        """Query Ollama ``GET /api/ps`` (SSRF-gated) for currently loaded models."""
        host = self._effective_ollama_host()
        if self._ollama_ps_fn is not None:
            try:
                return self._ollama_ps_fn(host)
            except Exception as exc:  # noqa: BLE001
                return {"status": "offline", "host": host, "loaded_models": [], "detail": str(exc)}

        allowed, reason = validate_probe_base_url(host, check_dns=False)
        if not allowed:
            return {
                "status": "blocked",
                "host": host,
                "loaded_models": [],
                "detail": reason,
            }

        try:
            with httpx.Client(timeout=timeout_s, follow_redirects=False, trust_env=False) as client:
                resp = client.get(f"{host.rstrip('/')}/api/ps")
                if resp.status_code != 200:
                    return {
                        "status": "error",
                        "host": host,
                        "loaded_models": [],
                        "http_status": resp.status_code,
                    }
                data = resp.json() if resp.content else {}
                raw_models = data.get("models") if isinstance(data, dict) else []
                models: List[Dict[str, Any]] = []
                for item in raw_models or []:
                    if not isinstance(item, dict):
                        continue
                    size_bytes = int(item.get("size") or 0)
                    vram_bytes = int(item.get("size_vram") or 0)
                    models.append({
                        "name": str(item.get("name") or item.get("model") or ""),
                        "size_mb": round(size_bytes / (1024 * 1024), 1),
                        "size_vram_mb": round(vram_bytes / (1024 * 1024), 1),
                        "expires_at": item.get("expires_at"),
                    })
                return {
                    "status": "online",
                    "host": host,
                    "loaded_models": models,
                    "count": len(models),
                }
        except Exception as exc:  # noqa: BLE001
            return {
                "status": "offline",
                "host": host,
                "loaded_models": [],
                "detail": str(exc),
            }

    def snapshot(self, *, include_ollama: bool = True) -> Dict[str, Any]:
        """Collect a complete, truthful hardware + VRAM + Ollama telemetry snapshot."""
        cpu, ram = _probe_cpu_ram()
        gpu = self.gpu_snapshot()
        ollama = (
            self.ollama_ps_snapshot()
            if include_ollama
            else {"status": "skipped", "host": self._effective_ollama_host(), "loaded_models": []}
        )
        scheduler_status = get_gpu_scheduler().status()
        vram_loaded = get_vram_manager_loaded_model() or scheduler_status.get("currently_loaded_model")
        if not vram_loaded and ollama.get("loaded_models"):
            vram_loaded = ollama["loaded_models"][0].get("name")

        manifest = get_model_manifest()
        profile = manifest.resolve_hardware_profile(
            vram_total_mb=int(gpu["vram_total_mb"]) if gpu["available"] else 0,
            gpu_available=bool(gpu["available"]),
        )

        return {
            "timestamp": time.time(),
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
            },
            "cpu": cpu,
            "ram": ram,
            "gpu": gpu,
            "ollama": ollama,
            "vram_manager": {
                "currently_loaded_model": vram_loaded,
            },
            "gpu_scheduler": scheduler_status,
            "hardware_profile": {
                "configured": os.getenv("HUNTER_HARDWARE_PROFILE") or manifest.active_hardware_profile,
                "active": profile.name,
                "default_num_ctx": profile.default_num_ctx,
                "keep_alive_seconds": profile.keep_alive_seconds,
                "prefer_cloud_fallback": profile.prefer_cloud_fallback,
                "role_models": dict(profile.role_models),
            },
        }

    async def asnapshot(self, *, include_ollama: bool = True) -> Dict[str, Any]:
        """Async wrapper around ``snapshot()`` offloaded to a worker thread."""
        return await asyncio.to_thread(self.snapshot, include_ollama=include_ollama)


_monitor_singleton: Optional[HardwareMonitor] = None


def get_hardware_monitor() -> HardwareMonitor:
    """Return the process-wide ``HardwareMonitor`` singleton."""
    global _monitor_singleton
    if _monitor_singleton is None:
        _monitor_singleton = HardwareMonitor()
    return _monitor_singleton


__all__ = [
    "HardwareMonitor",
    "get_hardware_monitor",
    "get_vram_manager_loaded_model",
    "register_vram_manager",
]
