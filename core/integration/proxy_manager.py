"""
Proxy Integration & Traffic Monitoring Engine
"Passive Traffic Pattern Analysis & Differential Inspection"

يراقب ويحلل حركة المرور والطلبات عبر البروكسي (Burp / OWASP ZAP / HTTP logs):
1. رسم خريطة الـ Endpoints والـ APIs والباراميترات من الترافيك
2. تحليل الأمان السلبي للهيدرز وسياسات CORS و CSP
3. فحص التفاضل بين الطلبات (Differential Request/Response Analysis)
4. كشف مؤشرات التسريب والانعكاس في الوقت الفعلي دون تعديل الطلبات
"""
import difflib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

log = logging.getLogger("integration.proxy_manager")


class ProxyMonitoringEngine:
    """محرك مراقبة وتحليل حركة المرور والتفاضل"""

    def __init__(self, upstream_proxy: Optional[str] = "http://127.0.0.1:8080"):
        self.upstream_proxy = upstream_proxy
        self.captured_endpoints: set = set()
        self.parameter_map: Dict[str, set] = {}

    # ── 1. Traffic Pattern Analysis ──────────────────────────────────────────

    def analyze_traffic_stream(self, traffic_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        تحليل قائمة بطلبات واستجابات HTTP المسجلة:
        - استخراج مسارات الـ API والـ Endpoints
        - فهرسة الباراميترات (GET / POST / JSON)
        - كشف غياب الهيدرز الأمنية وتسريبات الـ CORS
        """
        findings = []
        api_routes = set()
        discovered_params = set()

        for entry in traffic_entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})

            url = req.get("url", "")
            method = req.get("method", "GET").upper()
            status_code = resp.get("status_code", 200)
            headers = resp.get("headers", {})
            body = resp.get("body", "")

            if not url:
                continue

            parsed = urlparse(url)
            base_path = parsed.path
            self.captured_endpoints.add(base_path)

            if "/api/" in base_path or "/v1/" in base_path or "/v2/" in base_path or "/graphql" in base_path:
                api_routes.add(f"{method} {base_path}")

            # Parse GET parameters
            qs = parse_qs(parsed.query)
            for k in qs.keys():
                discovered_params.add(k)
                self.parameter_map.setdefault(base_path, set()).add(k)

            # Parse POST JSON / form data
            req_body = req.get("body", "")
            if req_body and isinstance(req_body, str):
                try:
                    json_data = json.loads(req_body)
                    if isinstance(json_data, dict):
                        for k in json_data.keys():
                            discovered_params.add(k)
                            self.parameter_map.setdefault(base_path, set()).add(k)
                except Exception:
                    pass

            # Audit CORS policies in response
            acao = headers.get("Access-Control-Allow-Origin") or headers.get("access-control-allow-origin")
            acac = headers.get("Access-Control-Allow-Credentials") or headers.get("access-control-allow-credentials")
            if acao == "*" and str(acac).lower() == "true":
                findings.append({
                    "type": "insecure_cors",
                    "severity": "High",
                    "title": f"Insecure CORS (Wildcard with Credentials) on {base_path}",
                    "evidence": f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true"
                })

            # Check for sensitive data leakage in response
            if re.search(r"\b(password|secret_key|api_key|private_key|aws_secret)\b", body, re.I):
                findings.append({
                    "type": "sensitive_data_exposure",
                    "severity": "Medium",
                    "title": f"Potential Sensitive Key Mention in Response from {base_path}",
                    "evidence": f"Sensitive keyword identified in {len(body)} bytes response body."
                })

        return {
            "total_requests_analyzed": len(traffic_entries),
            "endpoints_count": len(self.captured_endpoints),
            "api_routes": sorted(list(api_routes)),
            "parameters_discovered": sorted(list(discovered_params)),
            "parameter_map": {k: sorted(list(v)) for k, v in self.parameter_map.items()},
            "passive_findings": findings
        }

    # ── 2. Differential Response Analysis ────────────────────────────────────

    @staticmethod
    def calculate_differential(
        baseline_resp: Dict[str, Any],
        test_resp: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        مقارنة تفاضلية رياضية بين استجابتين (Baseline vs Modified Probe):
        - حساب فارق الحجم (Length Delta)
        - نسبة التشابه في المحتوى (Divergence Ratio via SequenceMatcher)
        - تغير كود الاستجابة (Status Change)
        """
        base_status = baseline_resp.get("status_code", 200)
        test_status = test_resp.get("status_code", 200)

        base_body = str(baseline_resp.get("body", ""))
        test_body = str(test_resp.get("body", ""))

        base_len = len(base_body)
        test_len = len(test_body)
        len_delta = abs(test_len - base_len)

        # Quick similarity ratio
        matcher = difflib.SequenceMatcher(None, base_body[:2000], test_body[:2000])
        similarity = round(matcher.ratio(), 3)
        divergence = round(1.0 - similarity, 3)

        status_changed = base_status != test_status
        significant_behavior_change = status_changed or (divergence > 0.25 and len_delta > 50)

        return {
            "base_status": base_status,
            "test_status": test_status,
            "status_changed": status_changed,
            "base_length": base_len,
            "test_length": test_len,
            "length_delta": len_delta,
            "similarity_ratio": similarity,
            "divergence_ratio": divergence,
            "significant_behavior_change": significant_behavior_change
        }
