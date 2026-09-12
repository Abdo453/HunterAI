"""
Live Traffic Interception & Stream Correlator
Intercepts HTTP and WebSocket requests, captures response headers and payloads,
and measures request/response baselines for vulnerability differential testing.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CapturedHTTPFlow:
    flow_id: str
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[str]
    status_code: int
    response_headers: Dict[str, str]
    response_body: str
    response_length: int
    response_time_ms: float
    timestamp: float = field(default_factory=time.time)
    content_type: str = "text/html"


class TrafficStreamInterceptor:
    """
    معترض ومحلل حركة مرور الشبكة اللحظي (Traffic Stream Interceptor):
    - يوثق الطلبات والردود مع أزمنة الاستجابة وأحجام الـ Payloads.
    - يقيس الـ Baseline الطبيعي للاستجابات لمقارنتها بالفحوصات الأمنية اللاحقة.
    """

    def __init__(self):
        self.flows: List[CapturedHTTPFlow] = []
        self._baselines: Dict[str, Dict[str, Any]] = {}

    def record_flow(
        self,
        method: str,
        url: str,
        request_headers: Dict[str, str],
        request_body: Optional[str],
        status_code: int,
        response_headers: Dict[str, str],
        response_body: str,
        response_time_ms: float
    ) -> CapturedHTTPFlow:
        flow_id = f"flow_{len(self.flows) + 1:05d}"
        c_type = response_headers.get("content-type", response_headers.get("Content-Type", "text/html"))

        flow = CapturedHTTPFlow(
            flow_id=flow_id,
            method=method.upper(),
            url=url,
            request_headers=request_headers,
            request_body=request_body,
            status_code=status_code,
            response_headers=response_headers,
            response_body=response_body,
            response_length=len(response_body),
            response_time_ms=response_time_ms,
            content_type=c_type
        )
        self.flows.append(flow)

        # Update baseline for this endpoint if status is standard
        if status_code == 200:
            key = f"{method}:{url.split('?')[0]}"
            if key not in self._baselines:
                self._baselines[key] = {
                    "avg_length": len(response_body),
                    "status_code": status_code,
                    "avg_time_ms": response_time_ms,
                    "sample_count": 1
                }
            else:
                b = self._baselines[key]
                b["sample_count"] += 1
                b["avg_length"] = (b["avg_length"] + len(response_body)) / 2.0
                b["avg_time_ms"] = (b["avg_time_ms"] + response_time_ms) / 2.0

        return flow

    def get_baseline_for_endpoint(self, method: str, url: str) -> Optional[Dict[str, Any]]:
        key = f"{method.upper()}:{url.split('?')[0]}"
        return self._baselines.get(key)

    def calculate_differential(
        self,
        baseline_flow: CapturedHTTPFlow,
        probe_flow: CapturedHTTPFlow
    ) -> Dict[str, Any]:
        """مقارنة دقيقة بين طلب الـ Baseline وطلب الفحص لاكتشاف الفروقات الأمنية"""
        len_diff = probe_flow.response_length - baseline_flow.response_length
        time_diff = probe_flow.response_time_ms - baseline_flow.response_time_ms
        status_changed = probe_flow.status_code != baseline_flow.status_code

        return {
            "status_changed": status_changed,
            "baseline_status": baseline_flow.status_code,
            "probe_status": probe_flow.status_code,
            "length_difference": len_diff,
            "time_difference_ms": round(time_diff, 1),
            "is_significant_delta": abs(len_diff) > 20 or status_changed or time_diff > 3000
        }
