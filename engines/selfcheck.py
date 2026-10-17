"""فحص صحة المحركات (Self-check) — يُشغَّل من الواجهة أو CLI.

كل محرك يُفحص بجولة حقيقية صغيرة (hello probe) تكشف مشاكل auth/quota،
مع fallback لفحص الإصدار إن لم يدعم المحرك probe اقتصاديًا.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional

from engines.registry import DRIVERS, driver_for
from engines.types import HealthStatus

logger = logging.getLogger(__name__)


@dataclass
class SelfCheckReport:
    """تقرير فحص شامل لكل المحركات."""

    results: Dict[str, HealthStatus] = field(default_factory=dict)
    started_at: float = 0.0
    duration_s: float = 0.0

    @property
    def healthy_count(self) -> int:
        return sum(1 for r in self.results.values() if r.healthy)

    @property
    def total(self) -> int:
        return len(self.results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "results": {k: asdict(v) for k, v in self.results.items()},
            "healthy_count": self.healthy_count,
            "total": self.total,
            "duration_s": round(self.duration_s, 2),
        }


async def check_engine(
    engine_name: str,
    profile: Optional[Dict[str, Any]] = None,
    *,
    env: Optional[Dict[str, str]] = None,
) -> HealthStatus:
    """فحص محرك واحد: probe حقيقي بجولة واحدة."""
    try:
        driver = driver_for(profile or {"engine": engine_name})
    except ValueError as exc:
        return HealthStatus(healthy=False, detail=str(exc))

    # التشغيل في thread executor لعدم كتل event loop (subprocess blocking)
    loop = asyncio.get_running_loop()
    healthy, detail = await loop.run_in_executor(
        None, lambda: driver.health_detail(env=env))
    version = await loop.run_in_executor(None, driver.version_string)
    binary = await loop.run_in_executor(None, lambda: driver.bin)
    return HealthStatus(
        healthy=healthy, detail=detail, binary=binary, version=version)


async def run_selfcheck(
    engine_names: Optional[List[str]] = None,
    profiles: Optional[List[Dict[str, Any]]] = None,
    *,
    on_result: Optional[Callable[[str, HealthStatus], None]] = None,
    parallel: bool = True,
) -> SelfCheckReport:
    """فحص كل المحركات (أو قائمة محددة) بالتوازي.

    on_result تُستدعى فور اكتمال كل محرك لعرض تقدم حيّ.
    """
    import time
    started = time.time()
    report = SelfCheckReport(started_at=started)

    targets: List[tuple] = []
    if profiles:
        for p in profiles:
            name = str(p.get("engine") or p.get("name") or "unknown")
            targets.append((f"{name}:{p.get('model', 'default')}", p))
    else:
        names = engine_names or list(DRIVERS)
        for n in names:
            targets.append((n, {"engine": n}))

    async def _check_one(label: str, prof: Dict[str, Any]) -> tuple:
        status = await check_engine(str(prof.get("engine", "")), prof)
        return label, status

    if parallel:
        tasks = [asyncio.create_task(_check_one(lbl, prof)) for lbl, prof in targets]
        for coro in asyncio.as_completed(tasks):
            label, status = await coro
            report.results[label] = status
            if on_result:
                try:
                    on_result(label, status)
                except Exception:  # noqa: BLE001
                    pass
    else:
        for lbl, prof in targets:
            label, status = await _check_one(lbl, prof)
            report.results[label] = status
            if on_result:
                try:
                    on_result(label, status)
                except Exception:  # noqa: BLE001
                    pass

    report.duration_s = time.time() - started
    return report
