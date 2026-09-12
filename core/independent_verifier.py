"""
Independent Vulnerability Verifier & False Positive Killer (Inspired by Xalgorix & Strix)
محرك التحقق المستقل وإعدام الـ False Positives بواسطة الاختبار التفاضلي (Differential Probing)
"""
import time
import difflib
from typing import Dict, Any, Optional, Tuple
import httpx


class IndependentVerifier:
    """
    المدقق المستقل لإثبات الثغرات ونفي الـ False Positives:
    - يرسل 3 طلبات تفاضلية: (Baseline, Exploit Probe, Control Negative)
    - يقارن التغير الفعلي في استجابة السيرفر قبل اعتماد أي نتيجة!
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    async def verify_endpoint_vulnerability(self, target_url: str, param_name: str,
                                           vuln_type: str) -> Dict[str, Any]:
        """فحص تفاضلي مستقل للتحقق من وجود الثغرة أو نفيها كـ False Positive"""
        t0 = time.time()
        vuln_t = vuln_type.lower()

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            try:
                # 1. الطلب الأساسي (Baseline Request)
                base_resp = await client.get(target_url)
                base_len = len(base_resp.text)
                base_status = base_resp.status_code

                # 2. طلب الاختبار (Exploit Probe)
                if "sql" in vuln_t:
                    probe_payload = "1' OR '1'='1"
                    control_payload = "1' AND '1'='2"
                elif "xss" in vuln_t:
                    probe_payload = "test<tagxyz>123"
                    control_payload = "test123clean"
                else:
                    probe_payload = "test_probe_value"
                    control_payload = "test_control_value"

                sep = "&" if "?" in target_url else "?"
                probe_url = f"{target_url}{sep}{param_name}={probe_payload}"
                control_url = f"{target_url}{sep}{param_name}={control_payload}"

                probe_resp = await client.get(probe_url)
                control_resp = await client.get(control_url)

                # 3. المقارنة التفاضلية
                diff_probe_base = abs(len(probe_resp.text) - base_len)
                diff_probe_control = abs(len(probe_resp.text) - len(control_resp.text))

                is_proven = False
                reason = "No meaningful differential response detected."

                if "sql" in vuln_t:
                    # لو رد السيرفر اختلف بوضوح بين OR 1=1 و AND 1=2 أو ظهر خطأ SQL
                    sql_errors = ["syntax error", "sql", "mysql", "sqlite", "psycopg", "ora-", "syntax error in string"]
                    if any(err in probe_resp.text.lower() for err in sql_errors):
                        is_proven = True
                        reason = "Database error signature confirmed in response."
                    elif diff_probe_control > 50 and probe_resp.status_code == 200:
                        is_proven = True
                        reason = "Differential boolean evaluation confirmed (True vs False query response mismatch)."

                elif "xss" in vuln_t:
                    if "<tagxyz>123" in probe_resp.text:
                        is_proven = True
                        reason = "Unsanitized payload reflection confirmed in response body."

                status = "PROVEN" if is_proven else "FALSE_POSITIVE_REJECTED"
                confidence = 0.98 if is_proven else 0.15

                return {
                    "status": status,
                    "is_proven": is_proven,
                    "confidence": confidence,
                    "reason": reason,
                    "target_url": target_url,
                    "tested_parameter": param_name,
                    "duration": round(time.time() - t0, 2),
                    "baseline_status": base_status,
                    "probe_status": probe_resp.status_code,
                    "control_status": control_resp.status_code
                }

            except Exception as e:
                return {
                    "status": "UNCONFIRMED_ERROR",
                    "is_proven": False,
                    "confidence": 0.5,
                    "reason": f"Connection or verification error: {str(e)}",
                    "duration": round(time.time() - t0, 2)
                }
