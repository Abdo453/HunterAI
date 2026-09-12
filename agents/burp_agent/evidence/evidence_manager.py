"""
Evidence Manager for BurpAgent
Links findings to exact request/response IDs, highlighted snippets, and persistence.
"""
import time
import logging
from typing import Dict, Any, List, Optional
from agents.burp_agent.storage.models import EvidenceModel, FindingModel

log = logging.getLogger("burp_agent.evidence")


class EvidenceManager:
    """مدير الأدلة الجنائية لربط كل ثغرة مستنتجة بالطلب والرد الحقيقي"""

    def __init__(self, db_manager):
        self.db = db_manager

    def link_finding_to_traffic(
        self,
        finding: FindingModel,
        request_id: str,
        response_id: Optional[str] = None,
        endpoint_id: Optional[str] = None,
        parameter_name: Optional[str] = None,
        evidence_snippet: str = "",
        highlight_offset: Optional[int] = None
    ) -> int:
        """حفظ الثغرة وربطها بسجل الدليل في قاعدة البيانات"""
        finding_id = self.db.insert_finding(finding)
        
        evidence = EvidenceModel(
            finding_id=finding_id,
            request_id=request_id,
            response_id=response_id,
            endpoint_id=endpoint_id,
            parameter_name=parameter_name,
            highlight_offset=highlight_offset,
            evidence_snippet=evidence_snippet or finding.evidence,
            timestamp=time.time()
        )
        self.db.insert_evidence(evidence)
        log.info(f"[Evidence] Linked finding #{finding_id} ({finding.title}) -> Req #{request_id}")
        return finding_id
