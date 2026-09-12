"""
Burp Extension Bridge & Sensory Ingestion Coordinator
Receives raw HTTP traffic from Burp Suite extensions, coordinates normalization,
triggers artifact/cookie collectors, stores tamper-evident evidence,
and broadcasts events across the SensoryEventBus.
"""
import time
import uuid
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from agents.burp_agent.normalization.request_normalizer import RequestNormalizer, NormalizedRequest
from agents.burp_agent.normalization.response_normalizer import ResponseNormalizer, NormalizedResponse
from agents.burp_agent.collectors.artifact_collector import ArtifactCollector, CapturedArtifact
from agents.burp_agent.collectors.cookie_collector import CookieCollector
from agents.burp_agent.evidence.evidence_model import UnifiedEvidenceStore, UnifiedEvidence, BurpEvidenceType
from agents.burp_agent.streaming.sensory_event_bus import SensoryEventBus, SensoryEvent, SensoryMessage

log = logging.getLogger("burp_agent.extension.bridge")


class IngestionReceipt(BaseModel):
    transaction_id: str
    status: str
    request_summary: str
    response_summary: str
    signals_detected: List[str]
    artifacts_captured: int
    tokens_captured: int


class BurpExtensionBridge:
    """
    جسر استقبال الترافيك من إضافة Burp Suite:
    يعمل كـ Sensor رئيسي يوزع البيانات على المطبعات والمجمعات وناقل الأحداث
    """

    def __init__(
        self,
        event_bus: Optional[SensoryEventBus] = None,
        evidence_store: Optional[UnifiedEvidenceStore] = None,
        artifact_collector: Optional[ArtifactCollector] = None,
        cookie_collector: Optional[CookieCollector] = None
    ):
        self.bus = event_bus or SensoryEventBus()
        self.evidence_store = evidence_store or UnifiedEvidenceStore()
        self.artifacts = artifact_collector or ArtifactCollector()
        self.cookies = cookie_collector or CookieCollector()

    async def ingest_transaction(
        self,
        method: str,
        url: str,
        request_headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        response_status: int = 200,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Optional[str] = None,
        tool: str = "proxy"
    ) -> IngestionReceipt:
        """
        استقبال ومعالجة حركة HTTP كاملة من Burp Suite بدون إرهاق الـ LLM
        """
        tx_id = f"tx_{uuid.uuid4().hex[:8]}"
        now = time.time()
        req_headers = request_headers or {}
        resp_headers = response_headers or {}

        # 1. Normalize Request & Response (Context Window Protection)
        norm_req = RequestNormalizer.normalize(
            method=method,
            url=url,
            headers=req_headers,
            body=request_body
        )
        norm_resp = ResponseNormalizer.normalize(
            status_code=response_status,
            headers=resp_headers,
            body=response_body
        )

        all_signals = list(set(norm_req.signals + norm_resp.signals))

        # 2. Collect Artifacts (Uploads & Downloads)
        content_type = req_headers.get("Content-Type", "")
        uploaded = self.artifacts.capture_upload(tx_id, content_type, request_body or "")
        downloaded = self.artifacts.capture_download(tx_id, norm_resp.content_type, resp_headers, response_body or "")
        captured_artifacts = uploaded + ([downloaded] if downloaded else [])

        # 3. Collect Cookies & Tokens
        captured_tokens = self.cookies.inspect_transaction(
            transaction_id=tx_id,
            domain=norm_req.url,
            request_headers=req_headers,
            response_headers=resp_headers
        )

        # 4. Store Unified Evidence
        req_evid = UnifiedEvidence(
            evidence_type=BurpEvidenceType.HTTP_REQUEST,
            source=f"Burp_{tool}",
            timestamp=now,
            sha256=norm_req.sha256,
            parent_transaction_id=tx_id,
            summary=norm_req.summary,
            metadata={"url": url, "method": method, "params": norm_req.query_params}
        )
        resp_evid = UnifiedEvidence(
            evidence_type=BurpEvidenceType.HTTP_RESPONSE,
            source=f"Burp_{tool}",
            timestamp=now,
            sha256=norm_resp.sha256,
            parent_transaction_id=tx_id,
            summary=norm_resp.summary,
            metadata={"status": response_status, "signals": norm_resp.signals}
        )
        self.evidence_store.store_evidence(req_evid)
        self.evidence_store.store_evidence(resp_evid)

        # 5. Broadcast Sensory Events
        await self.bus.publish(
            SensoryEvent.HTTP_REQUEST_OBSERVED,
            SensoryMessage(
                event=SensoryEvent.HTTP_REQUEST_OBSERVED,
                transaction_id=tx_id,
                timestamp=now,
                summary=norm_req.summary,
                data=norm_req.to_dict()
            )
        )
        await self.bus.publish(
            SensoryEvent.HTTP_RESPONSE_OBSERVED,
            SensoryMessage(
                event=SensoryEvent.HTTP_RESPONSE_OBSERVED,
                transaction_id=tx_id,
                timestamp=now,
                summary=norm_resp.summary,
                data=norm_resp.to_dict()
            )
        )
        for art in captured_artifacts:
            await self.bus.publish(
                SensoryEvent.FILE_OBSERVED,
                SensoryMessage(
                    event=SensoryEvent.FILE_OBSERVED,
                    transaction_id=tx_id,
                    timestamp=now,
                    summary=f"File {art.direction}: {art.filename} ({art.mime_type})",
                    data=art.to_dict()
                )
            )

        return IngestionReceipt(
            transaction_id=tx_id,
            status="INGESTED_AND_BROADCAST",
            request_summary=norm_req.summary,
            response_summary=norm_resp.summary,
            signals_detected=all_signals,
            artifacts_captured=len(captured_artifacts),
            tokens_captured=len(captured_tokens)
        )
