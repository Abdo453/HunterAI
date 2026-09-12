"""
UI ↔ Traffic Correlation Engine
Bridges Playwright UI/DOM interactions with contemporaneous HTTP network traffic (Playwright + Burp).
Maps user actions (clicks, form submits) directly to triggered API endpoints and exposed parameters.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.database.knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedEvent:
    action_id: str
    element_type: str
    element_label: str
    locator: str
    req_id: str
    method: str
    endpoint_url: str
    status_code: Optional[int]
    payload_snippet: Optional[str]
    time_delta_ms: float
    confidence: float
    correlation_reason: str


class UITrafficCorrelator:
    """
    محرك ربط واجهة المستخدم بحركة مرور الشبكة (Playwright ↔ Burp Correlation Engine):
    - يربط نقرات الأزرار واستمارات الواجهة بالطلبات المباشرة التي أُرسلت للخادم.
    - يستنتج الـ Parameters المرتبطة بكل حقل إدخال في الصفحة.
    - يغذي قاعدة المعرفة وخريطة التطبيق بالعلاقات السببية الدقيقة.
    """

    def __init__(self, db: KnowledgeDB, max_time_delta_seconds: float = 3.0):
        self.db = db
        self.max_time_delta_seconds = max_time_delta_seconds

    def correlate_events(
        self,
        ui_actions: List[Dict[str, Any]],
        traffic_records: List[Dict[str, Any]]
    ) -> List[CorrelatedEvent]:
        """
        مقارنة أحداث الواجهة بطلبات الشبكة وتوليد الارتباطات السببية
        """
        correlations: List[CorrelatedEvent] = []

        # Sort by timestamp
        sorted_actions = sorted(ui_actions, key=lambda a: a.get("timestamp", 0))
        sorted_traffic = sorted(traffic_records, key=lambda t: t.get("timestamp", 0))

        for action in sorted_actions:
            act_time = action.get("timestamp", 0)
            act_id = action.get("action_id", "")
            elem_type = action.get("element_type", "button")
            label = action.get("text_label", "")
            locator = action.get("locator", "")

            # Look for traffic immediately following the UI action
            matching_requests = [
                t for t in sorted_traffic
                if 0 <= (t.get("timestamp", 0) - act_time) <= self.max_time_delta_seconds
            ]

            for req in matching_requests:
                req_time = req.get("timestamp", 0)
                delta_ms = round((req_time - act_time) * 1000, 1)
                req_url = req.get("url", "")
                method = req.get("method", "GET")
                status = req.get("status_code")
                post_data = req.get("post_data")

                # Score correlation confidence
                confidence = 0.70
                reasons = [f"Temporal proximity ({delta_ms}ms)"]

                label_tokens = [w.lower() for w in label.split() if len(w) > 2]
                label_match = False
                if label:
                    if label.lower() in req_url.lower() or (post_data and label.lower() in post_data.lower()):
                        label_match = True
                    elif label_tokens and any(t in req_url.lower() or (post_data and t in post_data.lower()) for t in label_tokens):
                        label_match = True

                if label_match:
                    confidence += 0.20
                    reasons.append(f"Label '{label}' matched in request payload/URL")

                if elem_type in ("form_submit", "button") and method in ("POST", "PUT", "PATCH", "DELETE"):
                    confidence += 0.10
                    reasons.append(f"{elem_type.title()} triggered state-changing HTTP {method}")

                confidence = min(confidence, 1.0)
                reason_str = " | ".join(reasons)

                corr = CorrelatedEvent(
                    action_id=act_id,
                    element_type=elem_type,
                    element_label=label,
                    locator=locator,
                    req_id=req.get("req_id", ""),
                    method=method,
                    endpoint_url=req_url,
                    status_code=status,
                    payload_snippet=post_data[:200] if post_data else None,
                    time_delta_ms=delta_ms,
                    confidence=confidence,
                    correlation_reason=reason_str
                )
                correlations.append(corr)

                # Persist to SQLite DB
                self.db.insert_correlation(
                    action_id=act_id,
                    req_id=req.get("req_id", ""),
                    endpoint=f"{method} {req_url}",
                    match_reason=reason_str
                )

        return correlations

    def export_correlation_graph(self, destination: Path) -> Path:
        """تصدير تقرير ارتباطات الواجهة والشبكة إلى ملف JSON منظم"""
        destination.parent.mkdir(parents=True, exist_ok=True)
        records = self.db.get_correlated_traffic()

        data = {
            "total_correlations": len(records),
            "generated_at": time.time(),
            "correlations": records
        }
        destination.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return destination
