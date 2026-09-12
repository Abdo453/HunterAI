"""
Level 3 AI Reasoning Pipeline: Asynchronous priority queue for deep LLM threat evaluation on high-value traffic.
"""
import asyncio
import logging
from typing import Dict, Any, Optional
from agents.burp_agent.storage.models import HTTPRequestModel, HTTPResponseModel
from agents.burp_agent.pipeline.event_bus import BurpEvent, EventBus
from agents.burp_agent.storage.database import TrafficDatabase

log = logging.getLogger("burp_agent.ai_pipeline")


class AIPipeline:
    """طابور التحليل الذكي المتقدم للطلبات المشبوهة فقط (Level 3)"""

    def __init__(self, db: TrafficDatabase, bus: EventBus, ai_reasoner: Any, max_queue: int = 500):
        self.db = db
        self.bus = bus
        self.ai_reasoner = ai_reasoner
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue)
        self._running = False

    async def enqueue_interesting_traffic(self, data: Dict[str, Any]):
        """إضافة الطلب المشبوه إلى طابور التحليل الذكي بدون إبطاء الـ Ingestion"""
        try:
            self._queue.put_nowait(data)
        except asyncio.QueueFull:
            log.warning("[AIPipeline] AI analysis queue full; dropping oldest low-priority items")

    async def start_worker(self):
        """معالج الخلفية لتحليل الطلبات بواسطة Ollama"""
        self._running = True
        while self._running:
            try:
                data = await self._queue.get()
                req: HTTPRequestModel = data["request"]
                resp: Optional[HTTPResponseModel] = data.get("response")

                # Perform Contextual AI Threat Reasoning
                if self.ai_reasoner:
                    analysis = await self.ai_reasoner.analyze_request_context(req, resp)
                    if analysis:
                        self.db.insert_ai_analysis(analysis)
                        await self.bus.publish(BurpEvent.AI_ANALYSIS_DONE, analysis)

                self._queue.task_done()
                await asyncio.sleep(0.1)  # rate pacing
            except Exception as e:
                log.error(f"[AIPipeline] Worker error: {e}", exc_info=True)
                await asyncio.sleep(1.0)
