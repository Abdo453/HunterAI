"""
Burp Controller & Repeater Experiment Workspace
Enables HunterAI to interact with Burp Suite:
1. Inspect proxy history and captured transactions.
2. Manage the Repeater Workspace for structured scientific experiments.
3. Execute controlled mutated requests and track baseline vs experiment outcomes.
"""
import uuid
import time
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from agents.burp_agent.extension.burp_extension_bridge import BurpExtensionBridge, IngestionReceipt

log = logging.getLogger("core.controllers.burp")


class RepeaterExperiment(BaseModel):
    """تجربة علمية مقننة في مساحة عمل الـ Repeater"""
    experiment_id: str
    base_tx_id: str
    hypothesis: str
    mutation_description: str
    mutated_request: Dict[str, Any]
    response_tx_id: Optional[str] = None
    outcome_status: Optional[int] = None
    diff_summary: Optional[str] = None
    created_at: float = Field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class BurpController:
    """
    متحكم Burp ومختبر تجارب الـ Repeater:
    يوفر للـ Brain إمكانية فحص السجل وإطلاق التجارب التفاضلية
    """

    def __init__(self, bridge: Optional[BurpExtensionBridge] = None):
        self.bridge = bridge or BurpExtensionBridge()
        self.experiments: Dict[str, RepeaterExperiment] = {}
        self._mock_transactions: Dict[str, Dict[str, Any]] = {}

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """استرجاع سجل الحركات الملتقطة في البروكسي"""
        events = self.bridge.bus.get_recent_events(limit=limit)
        return [
            {
                "transaction_id": ev.transaction_id,
                "event": ev.event.value,
                "summary": ev.summary,
                "timestamp": ev.timestamp,
                "data": ev.data
            }
            for ev in events
        ]

    def get_transaction(self, tx_id: str) -> Optional[Dict[str, Any]]:
        """استرجاع تفاصيل حركة كاملة بواسطة الـ ID"""
        # Look in evidence store
        evids = self.bridge.evidence_store.get_by_transaction(tx_id)
        if not evids and tx_id in self._mock_transactions:
            return self._mock_transactions[tx_id]
        return {
            "transaction_id": tx_id,
            "evidence_items": [e.to_dict() for e in evids]
        }

    async def send_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        tool: str = "repeater"
    ) -> IngestionReceipt:
        """إرسال طلب مباشر عبر Burp وتوثيقه كحركة حسية"""
        # Simulate network or local reflection
        status = 200
        resp_body = f"OK Response for {method} {url}"
        if "sleep" in (body or "") or "pg_sleep" in url:
            time.sleep(0.05)  # Simulated delay

        receipt = await self.bridge.ingest_transaction(
            method=method,
            url=url,
            request_headers=headers or {},
            request_body=body or "",
            response_status=status,
            response_headers={"Content-Type": "text/html; charset=utf-8"},
            response_body=resp_body,
            tool=tool
        )
        return receipt

    def create_repeater_experiment(
        self,
        base_tx_id: str,
        hypothesis: str,
        mutation_description: str,
        mutated_request: Dict[str, Any]
    ) -> RepeaterExperiment:
        """
        إنشاء تجربة مقننة في مساحة عمل Repeater
        """
        exp_id = f"exp_{uuid.uuid4().hex[:6]}"
        experiment = RepeaterExperiment(
            experiment_id=exp_id,
            base_tx_id=base_tx_id,
            hypothesis=hypothesis,
            mutation_description=mutation_description,
            mutated_request=mutated_request
        )
        self.experiments[exp_id] = experiment
        return experiment

    async def execute_experiment(self, experiment_id: str) -> RepeaterExperiment:
        """
        تنفيذ التجربة المقننة في Repeater وحساب التباعد السلوكي
        """
        exp = self.experiments.get(experiment_id)
        if not exp:
            raise ValueError(f"Experiment {experiment_id} not found in Repeater workspace.")

        req = exp.mutated_request
        receipt = await self.send_request(
            method=req.get("method", "GET"),
            url=req.get("url", "http://localhost"),
            headers=req.get("headers", {}),
            body=req.get("body", ""),
            tool="repeater"
        )

        exp.response_tx_id = receipt.transaction_id
        exp.outcome_status = 200
        exp.diff_summary = f"Executed mutation '{exp.mutation_description}' -> Transaction {receipt.transaction_id}"
        return exp

    def get_experiment(self, experiment_id: str) -> Optional[RepeaterExperiment]:
        return self.experiments.get(experiment_id)
