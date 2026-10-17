"""Cloud-Enum Cloud Storage — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional, Set
from core.cloud_enum.schemas import CloudBucketRecord

log = logging.getLogger("cloud_enum.context")


class ContextEnricher:
    """
    L3: يضيف سياقًا لكل دلو S3:
      - تصنيف الدلو حسب النوع (عام، خاص، Mixed)
      - تحديد إن كانت الدلو عالية القيمة (بيانات حساسة، نسخ احتياطية، إلخ)
      - الربط بنتائج nmap أو HTTPx (إن توفرت)
    """

    def __init__(
        self,
        httpx_results: Optional[Dict[str, List[str]]] = None,   # bucket_name -> [urls]
    ):
        self.httpx_results = httpx_results or {}

    def enrich(self, record: CloudBucketRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "is_public": record.access_level.lower() == "public",
            "is_private": record.access_level.lower() == "private",
            "is_high_value": False,
            "provider_category": "unknown",
            "notes": [],
        }

        bucket_lower = record.bucket_name.lower()
        provider_lower = (record.provider or "").lower()

        # تحديد إن كانت الدلو عالية القيمة
        high_value_keywords = ["backup", "backup", "archive", "logs", "config", "secret", "key", "password", "database", "db"]
        if any(k in bucket_lower for k in high_value_keywords):
            context["is_high_value"] = True
            context["notes"].append("دلو عالي القيمة — قد يحتوي على بيانات حساسة")

        # تصنيف الموفر
        if "aws" in provider_lower or "s3" in provider_lower:
            context["provider_category"] = "aws_s3"
        elif "azure" in provider_lower or "blob" in provider_lower:
            context["provider_category"] = "azure_blob"
        elif "google" in provider_lower or "gcs" in provider_lower or "storage" in provider_lower:
            context["provider_category"] = "google_cloud_storage"

        # الروابط المرتبطة من HTTPx
        if record.bucket_name in self.httpx_results:
            context["related_urls"] = self.httpx_results[record.bucket_name]
            context["notes"].append(f"روابط مرتبطة من HTTPx: {len(self.httpx_results[record.bucket_name])} رابط")

        return context


class AdaptiveTestAdvisor:
    """
    L4: يقترح فحوصات إضافية بناءً على النتائج الفعلية (بدلًا من تكرار فحوصات عامة).
    """

    def advise(
        self,
        record: CloudBucketRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        يُترح قائمة بأدوات/قوالب مقترحة للفحص التكيفي.
        """
        context = context or {}
        suggestions: List[str] = []

        # بناءً على الحساسية
        if context.get("is_public"):
            suggestions.append("nuclei -t http/exposed-panels")
            suggestions.append("ffuf -u http://<bucket>.s3.amazonaws.com/FUZZ")

        # بناءً على provider
        provider_lower = (record.provider or "").lower()
        if "aws" in provider_lower or "s3" in provider_lower:
            suggestions.append("aws s3 ls s3://<bucket_name> --no-sign-request")
            suggestions.append("testssl.sh --s3")
        elif "azure" in provider_lower or "blob" in provider_lower:
            suggestions.append("az storage blob list --account-name <account> --no-sign-request")
        elif "google" in provider_lower or "gcs" in provider_lower:
            suggestions.append("gsutil ls gs://<bucket_name>")

        # إزالة التكرار مع الحفاظ على الترتيب
        seen = set()
        unique = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)

        return unique[:8]
