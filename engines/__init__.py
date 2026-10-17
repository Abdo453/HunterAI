"""نظام محركات الوكلاء (CLI Engine Workers) لـ HunterAI.

بنية:
- types.py     : أنواع مشتركة (LaunchContext, EngineResult, StreamStep)
- base.py      : EngineDriver المجرّد — عقد argv + تطبيع + صحة
- drivers/     : محركات محدّدة (claude, codex, opencode)
- registry.py  : سجل + أغلفة personal profiles/ endpoints
- runner.py    : تشغيل subprocess غير متزامن مع بثّ وإلغاء
- worker.py    : EngineWorker — ربط المحرك بحوكمة HunterAI
- selfcheck.py : فحص صحة شامل لكل المحركات المُهيّأة
"""
from engines.types import (
    EngineResult, HealthStatus, LaunchContext, StreamStep,
)
from engines.base import EngineDriver, SecurePromptUnsupported
from engines.registry import DRIVERS, available_engines, driver_for, get_driver
from engines.runner import build_worker_env, run_engine, stream_engine
from engines.worker import EngineWorker, EngineWorkerConfig

__all__ = [
    "EngineResult", "HealthStatus", "LaunchContext", "StreamStep",
    "EngineDriver", "SecurePromptUnsupported",
    "DRIVERS", "available_engines", "driver_for", "get_driver",
    "build_worker_env", "run_engine", "stream_engine",
    "EngineWorker", "EngineWorkerConfig",
]
