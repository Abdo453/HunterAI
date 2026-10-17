"""مراقبة التكلفة وسِقف الميزانية (Cost Budget) — Phase 3.

يحل النقص في عدم وجود سقف تكلفة فعلي:
- جدول أسعار لكل نموذج (USD لكل 1M tokens) — محلي وسحابي
- دفتر حسابات لكل run / solver / يوم
- circuit breaker: is_over_budget(scope) يوقف الجر عند التجاوز
- تقدير التكلفة من token counts حتى للنماذج المحلية (سعر مُهيّأ)

يتكامل مع system prompt: أي استدعاء LLM جديد يمرّ من charge_call() قبل الإرسال.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModelPrice:
    """USD لكل 1M tokens."""

    input_per_m: float
    output_per_m: float

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens / 1_000_000 * self.input_per_m
                + output_tokens / 1_000_000 * self.output_per_m)


# جدول أسعار افتراضي — قابل للتحديث عبر set_price / config
DEFAULT_PRICES: Dict[str, ModelPrice] = {
    # محلي (تقديري)
    "qwen2.5-coder:14b": ModelPrice(0.0, 0.0),
    "qwen3:8b": ModelPrice(0.0, 0.0),
    "xploiter/pentester:latest": ModelPrice(0.0, 0.0),
    # سحابي (قائمة عامة محدثة)
    "claude-sonnet-4-5": ModelPrice(3.0, 15.0),
    "claude-opus-4-1": ModelPrice(15.0, 75.0),
    "claude-haiku-4-5": ModelPrice(1.0, 5.0),
    "gpt-5": ModelPrice(1.25, 10.0),
    "gpt-5-mini": ModelPrice(0.25, 2.0),
    "gpt-4o": ModelPrice(2.5, 10.0),
    "deepseek-v4-flash": ModelPrice(0.07, 0.28),
    "deepseek-v4-pro": ModelPrice(0.55, 2.19),
    "gemini-2.5-pro": ModelPrice(1.25, 10.0),
    "gemini-2.5-flash": ModelPrice(0.30, 2.50),
}


@dataclass
class Ledger:
    """دفتر حسابات لنطاق واحد (run/solver/day)."""

    usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0
    unpriced_calls: int = 0

    def add(self, price: Optional[ModelPrice], inp: int, outp: int) -> Optional[float]:
        c = None
        if price is not None:
            c = price.cost(inp, outp)
            self.usd += c
        else:
            self.unpriced_calls += 1
        self.input_tokens += inp
        self.output_tokens += outp
        self.calls += 1
        return c


@dataclass
class Budget:
    """سقوف بالدولار؛ None = بلا حد."""

    per_run_usd: Optional[float] = None
    per_solver_usd: Optional[float] = None
    per_day_usd: Optional[float] = None


class CostController:
    """مدير التكلفة والميزانية — thread-safe."""

    def __init__(
        self,
        budget: Optional[Budget] = None,
        prices: Optional[Dict[str, ModelPrice]] = None,
        on_update: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.budget = budget or Budget()
        self.prices: Dict[str, ModelPrice] = dict(prices or DEFAULT_PRICES)
        self.on_update = on_update
        self._lock = threading.Lock()
        self._global = Ledger()
        self._by_run: Dict[str, Ledger] = {}
        self._by_solver: Dict[str, Ledger] = {}
        self._by_day: Dict[str, Ledger] = {}
        self._day_window = time.strftime("%Y-%m-%d")

    # ── التسعير ───────────────────────────────────────────────────────────
    def set_price(self, model: str, input_per_m: float, output_per_m: float) -> None:
        self.prices[model] = ModelPrice(input_per_m, output_per_m)

    def price_for(self, model: str) -> Optional[ModelPrice]:
        return self.prices.get(model)

    # ── تسجيل الاستهلاك ───────────────────────────────────────────────────
    def _day_key(self) -> str:
        today = time.strftime("%Y-%m-%d")
        if today != self._day_window:
            # نافذة يوم جديد: نبدأ دفتر اليوم جديدًا
            self._day_window = today
            self._by_day.pop(today, None)
        return today

    def charge_call(
        self,
        *,
        model: str,
        input_tokens: int,
        output_tokens: int,
        run_id: str = "",
        solver_id: str = "",
        reported_cost_usd: Optional[float] = None,
    ) -> Optional[float]:
        """تسجيل استدعاء واحد؛ يعود بالتكلفة أو None إن النموذج غير مُسعّر.

        reported_cost_usd: إذا أبلغ المحرك بتكلفته الفعلية تُستخدم بدل التقدير.
        """
        price = self.price_for(model)
        with self._lock:
            cost = reported_cost_usd
            if cost is None and price is not None:
                cost = price.cost(input_tokens, output_tokens)
            if cost is None:
                self._global.unpriced_calls += 1
                if run_id:
                    self._by_run.setdefault(run_id, Ledger()).unpriced_calls += 1
                return None
            self._global.usd += cost
            self._global.input_tokens += input_tokens
            self._global.output_tokens += output_tokens
            self._global.calls += 1
            if run_id:
                led = self._by_run.setdefault(run_id, Ledger())
                led.usd += cost
                led.input_tokens += input_tokens
                led.output_tokens += output_tokens
                led.calls += 1
            if solver_id:
                led = self._by_solver.setdefault(solver_id, Ledger())
                led.usd += cost
                led.input_tokens += input_tokens
                led.output_tokens += output_tokens
                led.calls += 1
            day = self._by_day.setdefault(self._day_key(), Ledger())
            day.usd += cost
            day.calls += 1

        snapshot = self.snapshot()
        if self.on_update is not None:
            try:
                self.on_update(snapshot)
            except Exception:  # noqa: BLE001
                pass
        return cost

    # ── circuit breaker ───────────────────────────────────────────────────
    def is_over_budget(self, scope: str = "global", *, run_id: str = "",
                       solver_id: str = "") -> bool:
        """scope: 'global' | 'run' | 'solver' | 'day'."""
        with self._lock:
            if scope == "global":
                return (self.budget.per_run_usd is not None
                        and self._global.usd >= self.budget.per_run_usd) or (
                    self.budget.per_day_usd is not None
                    and self._by_day.get(self._day_key(), Ledger()).usd
                    >= self.budget.per_day_usd)
            if scope == "run":
                led = self._by_run.get(run_id)
                return (self.budget.per_run_usd is not None and led is not None
                        and led.usd >= self.budget.per_run_usd)
            if scope == "solver":
                led = self._by_solver.get(solver_id)
                return (self.budget.per_solver_usd is not None and led is not None
                        and led.usd >= self.budget.per_solver_usd)
            if scope == "day":
                led = self._by_day.get(self._day_key())
                return (self.budget.per_day_usd is not None and led is not None
                        and led.usd >= self.budget.per_day_usd)
        return False

    def remaining_usd(self, scope: str = "global", *, run_id: str = "") -> Optional[float]:
        ceiling = self.budget.per_run_usd
        with self._lock:
            spent = self._by_run.get(run_id, Ledger()).usd if run_id else self._global.usd
        if ceiling is None:
            return None
        return max(0.0, ceiling - spent)

    # ── تقارير ────────────────────────────────────────────────────────────
    def global_usd(self) -> float:
        with self._lock:
            return self._global.usd

    def run_usd(self, run_id: str) -> float:
        with self._lock:
            led = self._by_run.get(run_id)
            return led.usd if led else 0.0

    def solver_usd(self, solver_id: str) -> float:
        with self._lock:
            led = self._by_solver.get(solver_id)
            return led.usd if led else 0.0

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "global_usd": round(self._global.usd, 6),
                "global_tokens": self._global.input_tokens + self._global.output_tokens,
                "calls": self._global.calls,
                "unpriced_calls": self._global.unpriced_calls,
                "by_run": {k: round(v.usd, 6) for k, v in self._by_run.items()},
                "by_solver": {k: round(v.usd, 6) for k, v in self._by_solver.items()},
                "today_usd": round(
                    self._by_day.get(self._day_key(), Ledger()).usd, 6),
                "budget": {
                    "per_run_usd": self.budget.per_run_usd,
                    "per_solver_usd": self.budget.per_solver_usd,
                    "per_day_usd": self.budget.per_day_usd,
                },
            }


# نسخة مشتركة تُحقن في نقاط الشحن
GLOBAL_COST_CONTROLLER = CostController()
