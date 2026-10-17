"""EngineWorker — وكيل ينفّذ مهمة عبر محرك CLI خارجي ضمن حوكمة HunterAI.

الفرق الجوهري عن تشغيل المحرك مباشرة: كل مهمة تمرّ عبر ScopeGuard
(الهدف في النطاق؟) و PolicyGate (الفئة مصرّح بها؟) قبل إرسال الـ prompt،
وناتج المحرك يُسجَّل في سجل الأدوات القابل للتدقيق.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from agents.base_agent import AgentResult, AgentTask, BaseAgent
from engines.registry import driver_for
from engines.runner import run_engine
from engines.types import EngineResult, LaunchContext, StreamStep

logger = logging.getLogger(__name__)


@dataclass
class EngineWorkerConfig:
    """إعدادات وكيل محرك واحد."""

    engine: str = "claude"                 # مُعرّف المحرك في السجل
    model: str = ""
    permission_mode: str = ""
    sandbox_mode: str = ""
    web_access: bool = True
    timeout_s: float = 1800.0
    # حساب قابل للحقن (أسرار تمر عبر env وليس argv)
    credential_env: Dict[str, str] = field(default_factory=dict)
    profile: Dict[str, Any] = field(default_factory=dict)
    # CTF flag pipeline (اختياري): يُفعَّل عند تحديد flag_format
    flag_format: str = ""
    expected_flags: int = 1

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "EngineWorkerConfig":
        return cls(
            engine=str(d.get("engine") or "claude"),
            model=str(d.get("model") or ""),
            permission_mode=str(d.get("permission_mode") or ""),
            sandbox_mode=str(d.get("sandbox_mode") or ""),
            web_access=bool(d.get("web_access", True)),
            timeout_s=float(d.get("timeout_s", 1800.0)),
            credential_env=dict(d.get("credential_env") or {}),
            profile=dict(d.get("profile") or {}),
            flag_format=str(d.get("flag_format") or ""),
            expected_flags=int(d.get("expected_flags", 1)),
        )


class EngineWorker(BaseAgent):
    """وكيل يدير مهمة واحدة أو أكثر عبر محرك CLI، مع سجل إثبات."""

    def __init__(
        self,
        config: EngineWorkerConfig,
        *,
        workspace_root: str = "data/engine_workers",
        policy_gate: Optional[Any] = None,
        scope_guard: Optional[Any] = None,
        progress_callback: Optional[Callable] = None,
        tool_manager: Optional[Any] = None,
        evidence_graph: Optional[Any] = None,
        evidence_store: Optional[Any] = None,
    ):
        super().__init__(
            name=f"engine-{config.engine}",
            description=f"وكيل محرك CLI: {config.engine}",
            tool_manager=tool_manager,
            progress_callback=progress_callback,
        )
        self.cfg = config
        self.workspace = Path(workspace_root) / f"{config.engine}-{uuid.uuid4().hex[:8]}"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.policy_gate = policy_gate
        self.scope_guard = scope_guard
        self._sessions: Dict[str, str] = {}  # target -> session_id للاستئناف

        # الرسم البياني المشترك (اختياري) — لتوحيد المعرفة بين الوكلاء
        self.evidence_graph = evidence_graph
        # متجر الأدلة الدائم (اختياري) — لتخزين الحقائق بشكل دائم
        self.evidence_store = evidence_store

        # CTF flag pipeline — يُنشأ فقط عند تحديد flag_format
        self.flag_service = None
        if config.flag_format:
            from flags.service import FlagService
            self.flag_service = FlagService(
                flag_format=config.flag_format,
                expected_count=config.expected_flags,
                store_path=str(self.workspace / "flags.json"),
            )

    # ── الحوكمة ───────────────────────────────────────────────────────────
    def _authorize(self, task: AgentTask) -> Optional[str]:
        """إرجاع سبب الرفض أو None إذا مُصرّح."""
        target = task.target
        if self.scope_guard is not None:
            try:
                in_scope, reason = self.scope_guard.is_in_scope(target)
                if not in_scope:
                    return f"خارج النطاق: {reason}"
            except Exception as exc:  # noqa: BLE001
                return f"ScopeGuard فشل: {exc}"
        if self.policy_gate is not None:
            try:
                from core.control_plane.policy_gate import (
                    ActionCategory, ActionRequest)
                req = ActionRequest(
                    category=ActionCategory.RECON,
                    command="engine-worker",
                    destinations=[target] if target else [],
                    raw={"engine": self.cfg.engine},
                )
                decision = self.policy_gate.evaluate(req)
                if not getattr(decision, "allowed", True):
                    return f"PolicyGate رفض: {getattr(decision, 'reason', 'غير معروف')}"
            except Exception as exc:  # noqa: BLE001
                # فشل الفحص = رفض (fail-closed) لكن نسجل تحذيرًا
                logger.warning("policy probe failed (fail-closed): %s", exc)
                return f"PolicyGate غير متاح: {exc}"
        return None

    # ── التنفيذ ───────────────────────────────────────────────────────────
    async def run(self, task: AgentTask) -> AgentResult:
        result = AgentResult(agent_name=self.name, target=task.target)

        deny_reason = self._authorize(task)
        if deny_reason is not None:
            result.errors.append(deny_reason)
            result.success = False
            return result

        prompt = str(task.extra.get("prompt") or "").strip()
        if not prompt:
            result.errors.append("لا يوجد prompt في المهمة")
            result.success = False
            return result

        # دمج context الهدف في الـ prompt
        full_prompt = (
            f"Target: {task.target}\n"
            f"Mode: {task.mode}\n\n{prompt}"
        )

        profile = dict(self.cfg.profile)
        profile.setdefault("engine", self.cfg.engine)
        if self.cfg.model:
            profile["model"] = self.cfg.model
        if self.cfg.permission_mode:
            profile["permission_mode"] = self.cfg.permission_mode
        if self.cfg.sandbox_mode:
            profile["sandbox_mode"] = self.cfg.sandbox_mode
        driver = driver_for(profile)

        launch = LaunchContext(
            model=self.cfg.model,
            permission_mode=self.cfg.permission_mode,
            sandbox_mode=self.cfg.sandbox_mode,
            cwd=str(self.workspace),
        )

        prev_session = self._sessions.get(task.target)
        steps_log: List[Dict[str, Any]] = []

        def _on_step(step: StreamStep) -> None:
            steps_log.append({
                "kind": step.kind,
                "text": step.text[:500],
                "tool": step.tool_name,
            })
            try:
                loop = asyncio.get_running_loop()
                loop.call_soon_threadsafe(
                    lambda: asyncio.ensure_future(
                        self.emit("step", {"kind": step.kind, "tool": step.tool_name})))
            except RuntimeError:
                pass

        eng_result: EngineResult = await run_engine(
            driver,
            full_prompt,
            session=prev_session,
            resume=prev_session is not None,
            web_access=self.cfg.web_access,
            stream=True,
            launch=launch,
            env_extra=self.cfg.credential_env,
            timeout_s=self.cfg.timeout_s,
            cwd=str(self.workspace),
            on_step=_on_step,
        )

        # حفظ الجلسة للاستئناف المستقبلي
        if eng_result.session_id:
            self._sessions[task.target] = eng_result.session_id

        # تسجيل إثبات قابل للتدقيق
        evidence_path = self.workspace / f"run_{int(time.time())}.json"
        try:
            evidence_path.write_text(json.dumps({
                "engine": self.cfg.engine,
                "model": self.cfg.model,
                "target": task.target,
                "ok": eng_result.ok,
                "exit_code": eng_result.exit_code,
                "session_id": eng_result.session_id,
                "duration_s": eng_result.duration_s,
                "steps_count": len(steps_log),
                "output_tail": eng_result.output_text[-2000:],
                "error": eng_result.error,
            }, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass

        result.raw_output = {
            "text": eng_result.output_text,
            "session_id": eng_result.session_id,
            "duration_s": str(eng_result.duration_s),
            "evidence_file": str(evidence_path),
        }
        result.success = eng_result.ok
        if eng_result.error:
            result.errors.append(eng_result.error)

        # محاولة استخراج نتائج بنية من مخرجات النموذج
        findings = task.extra.get("parse_findings")
        if callable(findings):
            try:
                result.findings = list(findings(eng_result.output_text) or [])
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"استخراج النتائج فشل: {exc}")

        # CTF flag pipeline: استخراج مرشّحات فلوغات من المخرجات
        if self.flag_service is not None and eng_result.output_text:
            try:
                fresh = self.flag_service.ingest(
                    eng_result.output_text,
                    source=f"engine:{self.cfg.engine}",
                    worker=self.name,
                )
                for c in fresh:
                    result.findings.append({
                        "type": "flag_candidate",
                        "value": c.value,
                        "confidence": round(c.confidence, 3),
                        "format_ok": c.format_ok,
                    })
                await self.emit("flags", {
                    "fresh": len(fresh),
                    "progress": self.flag_service.progress().to_dict(),
                })
            except Exception as exc:  # noqa: BLE001
                logger.warning("flag ingest failed: %s", exc)

        # الرسم البياني المشترك: تسجيل نتيجة التشغيل لتوحيد المعرفة
        if self.evidence_graph is not None:
            try:
                from core.shared_evidence import Fact
                self.evidence_graph.add_fact(Fact(
                    key=f"engine_run:{self.cfg.engine}:{task.target}",
                    value="ok" if eng_result.ok else "failed",
                    source=self.name,
                    confidence=1.0 if eng_result.ok else 0.3,
                    metadata={
                        "engine": self.cfg.engine,
                        "duration_s": eng_result.duration_s,
                        "findings": len(result.findings),
                        "session_id": eng_result.session_id,
                    },
                ))
                if self.evidence_store is not None:
                    self.evidence_store.add_evidence(
                        run_id=getattr(task, "session_id", "") or "",
                        source_worker=self.name,
                        source_tool=self.cfg.engine,
                        evidence_type="observation",
                        content=(f"تشغيل {self.cfg.engine} على {task.target}: "
                                 f"{'نجح' if eng_result.ok else 'فشل'}"),
                        provenance=f"engine:{self.cfg.engine}",
                        confidence=1.0 if eng_result.ok else 0.3,
                        metadata={
                            "engine": self.cfg.engine,
                            "duration_s": eng_result.duration_s,
                            "findings": len(result.findings),
                            "session_id": eng_result.session_id,
                            "fact_key": f"engine_run:{self.cfg.engine}:{task.target}",
                        },
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning("evidence fact record failed: %s", exc)
        return result
