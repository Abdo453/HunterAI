"""Cloud-Enum Cloud Storage — Canonical Data Schemas (L2-L5 shared data model)"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import time
import uuid
import hashlib


class CloudEnumEvidenceLevel(str):
    E0 = "E0"      # Raw cloud-enum result — needs review
    E1 = "E1"      # Corroborated / evidence sufficient


@dataclass
class CloudBucketRecord:
    """سجل سحابة واحدة من cloud-enum موحد."""
    record_id: str
    bucket_name: str
    provider: str  # aws_s3, azure_blob, google_cloud_storage
    access_level: str  # public, private, unknown
    region: Optional[str]
    url: str
    evidence_level: str = CloudEnumEvidenceLevel.E0
    captured_at: float = field(default_factory=time.time)
    source_tool: str = "cloud-enum"
    raw_json: Dict[str, Any] = field(default_factory=dict)
    validation_note: str = ""

    def __post_init__(self):
        if not self.record_id:
            self.record_id = f"cb_{str(uuid.uuid4())[:10]}"

    @property
    def canonical_key(self) -> str:
        """مفتاح للتكرارات: bucket_name"""
        return self.bucket_name.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CloudBucketProfile:
    """ملف سحابة موحد بعد تحليل cloud-enum + سياق إضافي."""
    bucket_name: str
    provider: str
    access_level: str
    region: Optional[str]
    url: str
    confidence_score: float       # 0.0 → 1.0
    confidence_label: str         # weak | possible | probable | strong
    evidence_level: str           # E0 | E1
    is_public: bool = False
    context_notes: List[str] = field(default_factory=list)
    adaptive_suggestions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
