"""
WebSocket Learning Stream — /ws/learn
يُشغّل دورة التعلم الذاتي ويبث التقدم للـ UI في الوقت الحقيقي
"""
import asyncio
import json
import time
from pathlib import Path

# ─── Feedback Loop: Confirmed Finding → Knowledge Base ───────────────────────

async def _handle_feedback(data: dict):
    """
    Feedback loop: عندما يُأكّد الـ Brain ثغرة حقيقية،
    تُحفظ تلقائياً في قاعدة المعرفة كـ 'confirmed exploit'
    """
    from core.learning.knowledge_base import KnowledgeBase
    from core.learning.analyzer import DeepAnalyzer

    kb = KnowledgeBase()
    analyzer = DeepAnalyzer()

    target = data.get("target", "")
    finding = data.get("finding", {})
    payload_used = finding.get("payload_used", "")
    vuln_type = finding.get("type", "")
    severity = finding.get("severity", "Medium")
    evidence = finding.get("evidence", "")
    param_name = finding.get("param_name", "")
    confidence = finding.get("confidence", 0.0)

    if not vuln_type or confidence < 0.7:
        return  # لا نحفظ إلا ما تم تأكيده بثقة عالية

    # 1. Save confirmed payload
    if payload_used and len(payload_used) > 3:
        kb.save_payload(
            payload_text=payload_used,
            payload_type=vuln_type,
            technologies=analyzer.detect_affected_tech(evidence),
            source_url=target,
            severity=severity,
        )

    # 2. Save as confirmed article/exploit
    analysis = {
        "source_url": target,
        "title": f"[Confirmed] {vuln_type.upper()} on {param_name!r} — {target[:50]}",
        "source_type": "confirmed_exploit",
        "summary": f"Confirmed {vuln_type} vulnerability on parameter '{param_name}' with payload: {payload_used}",
        "severity": severity,
        "techniques": [vuln_type],
        "related_cves": analyzer.extract_cves(evidence),
        "related_tools": ["SmartPoC", "AutonomousBrain"],
        "bypass_techniques": analyzer.extract_bypass_techniques(evidence),
        "payloads": [payload_used] if payload_used else [],
        "key_learnings": [
            f"Parameter '{param_name}' is vulnerable to {vuln_type}",
            f"Payload used: {payload_used}",
            f"Target: {target}",
            f"Evidence: {evidence[:200]}",
        ],
        "exploit_chain_hints": [],
        "affected_technologies": analyzer.detect_affected_tech(evidence),
        "embedding_text": f"{vuln_type} {param_name} {payload_used} {target} {evidence[:200]}",
    }
    doc_id = kb.save_article(analysis)
    kb.log_learning(
        source_url=target,
        source_type="confirmed_exploit",
        analysis=analysis,
        status="confirmed"
    )
    kb.flush_vectors()
    return doc_id


# ─── Auto Scheduler ────────────────────────────────────────────────────────────

class LearningScheduler:
    """
    يُشغّل دورات التعلم تلقائياً بحسب الـ frequency.
    يُشغَّل كـ background task مع بدء الـ app.
    """

    SCHEDULE = {
        "cisa_kev":   {"hours": 24,  "enabled": True},
        "nvd":        {"hours": 24,  "enabled": True},
        "medium":     {"hours": 12,  "enabled": True},
        "payloads":   {"hours": 72,  "enabled": True},
        "portswigger":{"hours": 168, "enabled": True},
        "exploit_db": {"hours": 48,  "enabled": True},
    }

    STATE_FILE = Path("data/knowledge_base/scheduler_state.json")

    def __init__(self):
        self._running = False
        self._state = self._load_state()

    def _load_state(self) -> dict:
        if self.STATE_FILE.exists():
            try:
                return json.loads(self.STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_state(self):
        self.STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        self.STATE_FILE.write_text(json.dumps(self._state, indent=2), encoding="utf-8")

    def _is_due(self, source: str) -> bool:
        sched = self.SCHEDULE.get(source, {})
        if not sched.get("enabled"):
            return False
        last_run = self._state.get(source, {}).get("last_run", 0)
        hours = sched.get("hours", 24)
        return (time.time() - last_run) >= (hours * 3600)

    async def run_forever(self, check_interval_minutes: int = 30):
        """حلقة لا نهائية تفحص الـ schedule كل 30 دقيقة"""
        self._running = True
        import logging
        log = logging.getLogger("learning.scheduler")
        log.info("[SCHEDULER] Started — checking every %dm", check_interval_minutes)

        while self._running:
            due_sources = [s for s in self.SCHEDULE if self._is_due(s)]
            if due_sources:
                log.info(f"[SCHEDULER] Due: {due_sources}")
                try:
                    from core.learning.self_learning_loop import SelfLearningLoop
                    loop = SelfLearningLoop()
                    await loop.run_full_cycle(sources=due_sources, use_ai=False)
                    for source in due_sources:
                        self._state[source] = {"last_run": time.time()}
                    self._save_state()
                    log.info(f"[SCHEDULER] Done: {due_sources}")
                except Exception as e:
                    log.exception(f"[SCHEDULER] Error: {e}")
            await asyncio.sleep(check_interval_minutes * 60)

    def stop(self):
        self._running = False


# ─── Singleton instances ─────────────────────────────────────────────────────
_scheduler: LearningScheduler = None

def get_scheduler() -> LearningScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = LearningScheduler()
    return _scheduler
