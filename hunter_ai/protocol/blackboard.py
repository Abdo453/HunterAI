"""
Hunter Agent Protocol v1: 3-Tier Blackboard Shared Memory
=========================================================
Implements strict 3-tier memory separation:
- Level 1: Summary (Broadly shared metadata, e.g. target, status, high-level flags)
- Level 2: Evidence (On-demand telemetry, HTTP request/response diffs, canaries)
- Level 3: Raw Data (Disk-backed file/DB storage: storage/jobs/<target>/recon.json, burp.db)
"""
from __future__ import annotations

import os
import json
import time
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set


@dataclass
class Level1Summary:
    """المستوى 1: ملخص خفيف الوزن يشارك مع جميع الوكلاء دون إرهاق الـ Context Window"""
    job_id: str
    target: str
    status: str = "in_progress"
    important_tags: List[str] = field(default_factory=list)  # e.g. ["API found", "Login found", "Laravel"]
    endpoints_count: int = 0
    subdomains_count: int = 0
    potential_vuln_count: int = 0
    active_agent: Optional[str] = None
    last_updated: float = field(default_factory=time.time)


@dataclass
class Level2EvidenceItem:
    """المستوى 2: أدلة وتفاصيل تيليميتري تُستدعى عند الحاجة فقط"""
    evidence_id: str
    url: str
    method: str
    parameter: str
    vulnerability_type: str
    request_snippet: str
    response_snippet: str
    canary_token: Optional[str] = None
    differential_notes: str = ""
    timestamp: float = field(default_factory=time.time)


class ThreeTierBlackboardMemory:
    """
    الذاكرة المشتركة ثلاثية المستويات (Blackboard Memory Pattern):
    تتيح للوكلاء قراءة الملخص العام، واسترجاع الأدلة التفصيلية عند الطلب،
    وتخزين البيانات الخام الكبيرة على القرص مع حفظ روابط المراجع فقط.
    """

    def __init__(self, base_storage_dir: str = "storage/jobs"):
        self.base_storage_dir = Path(base_storage_dir)
        self.base_storage_dir.mkdir(parents=True, exist_ok=True)
        self._level1_summaries: Dict[str, Level1Summary] = {}
        self._level2_evidence: Dict[str, Dict[str, Level2EvidenceItem]] = {}  # job_id -> {ev_id: item}

    # ── Level 1: Summary Methods ─────────────────────────────────────────────
    def get_or_create_summary(self, job_id: str, target: str) -> Level1Summary:
        if job_id not in self._level1_summaries:
            self._level1_summaries[job_id] = Level1Summary(job_id=job_id, target=target)
        return self._level1_summaries[job_id]

    def update_summary(
        self,
        job_id: str,
        tags_to_add: Optional[List[str]] = None,
        endpoints_delta: int = 0,
        subdomains_delta: int = 0,
        vulns_delta: int = 0,
        status: Optional[str] = None,
        active_agent: Optional[str] = None
    ) -> Level1Summary:
        summary = self._level1_summaries.get(job_id)
        if not summary:
            raise KeyError(f"Job summary not found for job_id: {job_id}")

        if tags_to_add:
            for t in tags_to_add:
                if t not in summary.important_tags:
                    summary.important_tags.append(t)
        if endpoints_delta:
            summary.endpoints_count += endpoints_delta
        if subdomains_delta:
            summary.subdomains_count += subdomains_delta
        if vulns_delta:
            summary.potential_vuln_count += vulns_delta
        if status:
            summary.status = status
        if active_agent:
            summary.active_agent = active_agent
        summary.last_updated = time.time()
        return summary

    def get_summary_dict(self, job_id: str) -> Dict[str, Any]:
        s = self._level1_summaries.get(job_id)
        return asdict(s) if s else {}

    # ── Level 2: Evidence Methods ────────────────────────────────────────────
    def add_evidence(self, job_id: str, evidence: Level2EvidenceItem) -> str:
        if job_id not in self._level2_evidence:
            self._level2_evidence[job_id] = {}
        self._level2_evidence[job_id][evidence.evidence_id] = evidence
        return evidence.evidence_id

    def get_evidence(self, job_id: str, evidence_id: str) -> Optional[Level2EvidenceItem]:
        return self._level2_evidence.get(job_id, {}).get(evidence_id)

    def list_evidence_for_job(self, job_id: str) -> List[Level2EvidenceItem]:
        return list(self._level2_evidence.get(job_id, {}).values())

    # ── Level 3: Raw Storage Methods (Disk Storage) ──────────────────────────
    def get_job_storage_dir(self, target_domain: str) -> Path:
        clean_name = target_domain.replace("https://", "").replace("http://", "").split("/")[0].replace(":", "_")
        p = self.base_storage_dir / clean_name
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save_raw_data(self, target_domain: str, filename: str, data: Any) -> str:
        """Saves raw data to disk and returns the absolute file path"""
        job_dir = self.get_job_storage_dir(target_domain)
        file_path = job_dir / filename
        if isinstance(data, (dict, list)):
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        elif isinstance(data, str):
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(data)
        elif isinstance(data, bytes):
            with open(file_path, "wb") as f:
                f.write(data)
        return str(file_path)

    def read_raw_data(self, file_path: str) -> Any:
        p = Path(file_path)
        if not p.exists():
            return None
        if p.suffix == ".json":
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        return p.read_text(encoding="utf-8", errors="ignore")
