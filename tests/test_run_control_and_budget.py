"""
Unit Tests for Run Control & Cost Budget — Phase 3
Tests: register/stop/pause/resume lifecycle, cooperative checkpoints,
       cost charging, budget circuit-breaker, per-scope ledgers.
"""
import asyncio

import pytest

from core.cost_budget import (
    Budget, CostController, DEFAULT_PRICES, ModelPrice,
)
from core.run_control import RunController, RunState


# ── Run Control ───────────────────────────────────────────────────────────

class TestRunControl:
    def test_register_and_complete(self):
        async def _work():
            return 42

        async def _main():
            ctl = RunController()
            task = asyncio.create_task(_work())
            h = ctl.register("r1", task, kind="test")
            assert h.state == RunState.RUNNING
            await task
            await asyncio.sleep(0)  # done callback
            return ctl.get("r1").state

        assert asyncio.run(_main()) == RunState.COMPLETED

    def test_stop_cancels_task(self):
        async def _slow():
            await asyncio.sleep(30)

        async def _main():
            ctl = RunController()
            task = asyncio.create_task(_slow())
            ctl.register("r2", task, kind="test")
            await ctl.stop("r2")
            await asyncio.sleep(0.05)
            return ctl.get("r2").state

        assert asyncio.run(_main()) in (RunState.STOPPED, RunState.STOPPING)

    def test_pause_resume(self):
        async def _main():
            ctl = RunController()
            task = asyncio.create_task(asyncio.sleep(0.1))
            ctl.register("r3", task)
            assert ctl.pause("r3")
            assert ctl.get("r3").state == RunState.PAUSED
            assert ctl.resume("r3")
            assert ctl.get("r3").state == RunState.RUNNING
            await task

        asyncio.run(_main())

    def test_cooperative_checkpoint_stops(self):
        async def _main():
            ctl = RunController()
            ctl.register("r4")
            assert await ctl.checkpoint("r4") is True
            await ctl.stop("r4", force=False)
            return await ctl.checkpoint("r4")

        assert asyncio.run(_main()) is False

    def test_cooperative_checkpoint_pauses_then_resumes(self):
        async def _main():
            ctl = RunController()
            ctl.register("r5")
            ctl.pause("r5")
            asyncio.get_event_loop().call_later(
                0.1, lambda: ctl.resume("r5"))
            return await ctl.checkpoint("r5")

        assert asyncio.run(_main()) is True

    def test_list_runs_filters(self):
        async def _main():
            ctl = RunController()
            t1 = asyncio.create_task(asyncio.sleep(0.05))
            t2 = asyncio.create_task(asyncio.sleep(30))
            ctl.register("a", t1, kind="mission")
            ctl.register("b", t2, kind="engine")
            await t1
            await asyncio.sleep(0.02)
            all_runs = ctl.list_runs()
            missions = ctl.list_runs(kind="mission")
            active = ctl.list_runs(active_only=True)
            await ctl.stop("b")
            return len(all_runs), len(missions), len(active)

        a, m, act = asyncio.run(_main())
        assert a == 2
        assert m == 1
        assert act >= 1  # مهمة b لا تزال نشطة

    def test_stop_all(self):
        async def _main():
            ctl = RunController()
            t1 = asyncio.create_task(asyncio.sleep(30))
            t2 = asyncio.create_task(asyncio.sleep(30))
            ctl.register("x", t1)
            ctl.register("y", t2)
            n = ctl.stop_all()
            await asyncio.sleep(0.05)
            return n

        assert asyncio.run(_main()) == 2


# ── Cost Budget ───────────────────────────────────────────────────────────

class TestCostController:
    def test_charge_estimates_from_price_table(self):
        c = CostController()
        cost = c.charge_call(
            model="claude-sonnet-4-5", input_tokens=1_000_000,
            output_tokens=500_000, run_id="r1")
        # 3.0 + 0.5*15 = 10.5
        assert cost == pytest.approx(10.5)
        assert c.global_usd() == pytest.approx(10.5)
        assert c.run_usd("r1") == pytest.approx(10.5)

    def test_reported_cost_overrides_estimate(self):
        c = CostController()
        cost = c.charge_call(
            model="claude-sonnet-4-5", input_tokens=100, output_tokens=100,
            reported_cost_usd=2.5)
        assert cost == 2.5

    def test_unpriced_model_returns_none(self):
        c = CostController()
        cost = c.charge_call(
            model="unknown-model", input_tokens=100, output_tokens=100)
        assert cost is None
        snap = c.snapshot()
        assert snap["unpriced_calls"] == 1

    def test_local_models_zero_cost(self):
        c = CostController()
        cost = c.charge_call(
            model="qwen3:8b", input_tokens=10000, output_tokens=10000)
        assert cost == 0.0

    def test_budget_circuit_breaker_run(self):
        c = CostController(budget=Budget(per_run_usd=5.0))
        c.charge_call(model="gpt-5", input_tokens=1_000_000,
                      output_tokens=0, run_id="big")
        # 1M input * 1.25 = 1.25
        assert not c.is_over_budget("run", run_id="big")
        c.charge_call(model="gpt-5", input_tokens=4_000_000,
                      output_tokens=0, run_id="big")
        # now 1.25 + 5.0 = 6.25 >= 5.0
        assert c.is_over_budget("run", run_id="big")

    def test_per_solver_budget(self):
        c = CostController(budget=Budget(per_solver_usd=1.0))
        c.charge_call(model="gpt-5", input_tokens=1_000_000,
                      output_tokens=0, solver_id="w1")
        assert c.is_over_budget("solver", solver_id="w1")
        assert not c.is_over_budget("solver", solver_id="w2")

    def test_set_price_custom(self):
        c = CostController()
        c.set_price("my-model", input_per_m=10.0, output_per_m=20.0)
        cost = c.charge_call(model="my-model",
                             input_tokens=500_000, output_tokens=500_000)
        assert cost == pytest.approx(15.0)

    def test_remaining_usd(self):
        c = CostController(budget=Budget(per_run_usd=10.0))
        c.charge_call(model="gpt-5", input_tokens=2_000_000,
                      output_tokens=0, run_id="r")
        # spent 2.5 of 10 => 7.5 remaining
        assert c.remaining_usd("run", run_id="r") == pytest.approx(7.5)

    def test_snapshot_shape(self):
        c = CostController()
        c.charge_call(model="gpt-5", input_tokens=1000, output_tokens=1000,
                      run_id="r", solver_id="s")
        snap = c.snapshot()
        assert "global_usd" in snap
        assert "by_run" in snap and "r" in snap["by_run"]
        assert "by_solver" in snap and "s" in snap["by_solver"]
        assert "budget" in snap

    def test_on_update_callback(self):
        seen = []
        c = CostController(on_update=lambda snap: seen.append(snap))
        c.charge_call(model="gpt-5", input_tokens=1000, output_tokens=1000)
        assert len(seen) == 1
