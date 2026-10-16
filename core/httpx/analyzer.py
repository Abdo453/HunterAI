"""HTTPx Technology Profiler — L2 AI Analyzer + L5 Evidence Reviewer
Finding Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.httpx.schemas import (
    HTTPxAssetRecord, TechnologyProfile,
    HTTPxEvidenceLevel, AssetStatus,
)

log = logging.getLogger("httpx.analyzer")

# بصمات WAF/CDN معروفة تُساعد في L5 Reviewer
WAF_CDN_SIGNATURES: Dict[str, List[str]] = {
    "cloudflare": ["cloudflare", "__cfduid", "cf-ray", "cloudflare-nginx"],
    "akamai": ["akamai", "akamaigreenthigh"],
    "imperva": ["incap_ses", "visid_incap", "imperva"],
    "f5": ["bigip", "f5"],
    "aws_waf": ["aws-waf", "awswaf"],
    "google_cloud": ["google", "gws"],
    "fastly": ["fastly"],
    "sucuri": ["sucuri", "sucuri-cloudproxy"],
    "fortinet": ["fortiweb", "fortigate"],
}


class HTTPxNormalizer:
    """
    L2: يحول مخرجات HTTPx JSON (NDJSON) إلى HTTPxAssetRecord موحد،
    مع استخراج الحقول الهامة وتطبيعها.
    """

    @staticmethod
    def normalize_httpx_json_line(line: str) -> Optional[HTTPxAssetRecord]:
        """
        يُحط سطر JSON واحد من مخرجات httpx (-json) إلى سجل موحد.
        """
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        url = data.get("url", "") or ""
        host = data.get("host", "") or ""
        port = data.get("port", 443 if url.startswith("https") else 80)
        scheme = data.get("scheme", "https" if url.startswith("https") else "http")
        status_code = data.get("status_code")
        content_length = data.get("content_length")
        content_type = data.get("content_type")
        title = data.get("title")
        web_server = data.get("web_server") or data.get("server")
        technologies = data.get("technology", []) or []
        if isinstance(technologies, str):
            technologies = [technologies]
        cdn = data.get("cdn")
        ip = data.get("ip")
        cname = data.get("cname")

        digest_src = f"{host}:{port}:{scheme}"
        record_id = f"hx_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        return HTTPxAssetRecord(
            record_id=record_id,
            url=url,
            host=host,
            port=port,
            scheme=scheme,
            status_code=status_code,
            content_length=content_length,
            content_type=content_type,
            title=title,
            web_server=web_server,
            technologies=technologies,
            cdn=cdn,
            ip=ip,
            cname=cname,
            status=AssetStatus.ALIVE if status_code else AssetStatus.UNKNOWN,
            evidence_level=HTTPxEvidenceLevel.E0,
            source_tool="httpx",
            raw_json=data,
            validation_note=f"HTTP {status_code} | {web_server or 'unknown server'} | {', '.join(technologies[:3]) or 'no tech detected'}",
        )

    def normalize_batch(self, httpx_stdout: str) -> List[HTTPxAssetRecord]:
        """يحول مخرجات httpx NDJSON إلى قائمة سجلات."""
        records: List[HTTPxAssetRecord] = []
        for line in httpx_stdout.splitlines():
            rec = self.normalize_httpx_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    """
    L2: يكتشف الأصول المكررة (نفس host:port) ويجمعها في مجموعة واحدة.
    """

    def __init__(self):
        self._groups: Dict[str, List[HTTPxAssetRecord]] = defaultdict(list)

    def add(self, record: HTTPxAssetRecord) -> Optional[List[HTTPxAssetRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            # تكرار — إرجاع المجموعة للدلالة على التكرار
            return self._groups[key]
        return None  # أصل جديد، لا تكرار بعد

    def flush(self) -> Dict[str, List[HTTPxAssetRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل أصل ويحدد:
      - هل الأدلة كافية لدعم الملف التقني؟ (evidence_status)
      - هل الأصل يحتاج تحقق إضافي؟ (needs_verification)
      - هل يبدو WAF/CDN؟
      - درجة الثقة المبدئية (بدون LLM)
    """

    def __init__(self):
        pass

    def review(self, record: HTTPxAssetRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للأصل.
        """
        issues: List[str] = []
        evidence_status = "insufficient"
        confidence = 0.2  # قاعدة: نتيجة HTTPx واحدة غير كافية لملف تقني قوي

        # وجود استجابة HTTP كاملة = دليل أقوى
        if record.status_code is not None:
            evidence_status = "partial"
            confidence += 0.3
        else:
            issues.append("لا توجد حالة استجابة HTTP (قد يكون الأصل معطلاً)")

        # وجود Web Server = دليل أقوى
        if record.web_server:
            confidence += 0.15
        else:
            issues.append("لا يوجد خادم ويب مكتشف (web_server)")

        # وجود تقنيات = دليل أقوى
        if record.technologies:
            confidence += 0.2 * min(len(record.technologies), 3)
        else:
            issues.append("لا توجد تقنيات مكتشفة")

        # وجود عنوان = سياق إضافي
        if record.title:
            confidence += 0.1

        # كشف WAF/CDN
        is_waf = self._detect_waf(record)
        is_cdn = self._detect_cdn(record)

        if is_waf:
            confidence += 0.1  # WAF يزيد من الثقة في أن الأصل محمي، لكنه يخفي التقنيات الحقيقية
            issues.append("يُحتمل وجود WAF — قد تكون التقنيات الظاهرة ناقصة أو مضللة")
        if is_cdn:
            confidence += 0.05
            issues.append("يُحتمل وجود CDN — 실제 البنية التحتية قد تكون خلف وسيط")

        # إذا كانت الأدلة مكتملة → E1
        if record.status_code is not None and (record.web_server or record.technologies):
            evidence_status = "sufficient"
            record.evidence_level = HTTPxEvidenceLevel.E1

        confidence = min(confidence, 1.0)
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "host": record.host,
            "url": record.url,
            "evidence_status": evidence_status,
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "evidence_level": record.evidence_level,
            "is_likely_waf": is_waf,
            "is_likely_cdn": is_cdn,
            "needs_verification": evidence_status != "sufficient",
            "issues": issues,
            "recommendation": (
                "الأداة أولية كافية لملف تقني مبدئي (E1). يُنصح بالتحقق عبر أداة ثانية أو تحليل يدوي للتقنيات المخفية خلف WAF/CDN."
                if evidence_status == "sufficient" else
                "الأدلة ناقصة — يُنصح بإعادة الفحص أو التحقق手动 من الاستجابة الأصلية."
            ),
        }

    def _detect_waf(self, record: HTTPxAssetRecord) -> bool:
        text = " ".join([
            record.web_server or "",
            record.title or "",
            ",".join(record.technologies),
            str(record.raw_json.get("header", "")),
        ]).lower()
        for waf, sigs in WAF_CDN_SIGNATURES.items():
            if any(s in text for s in sigs):
                return True
        return False

    def _detect_cdn(self, record: HTTPxAssetRecord) -> bool:
        cdn_indicators = ["cloudflare", "akamai", "fastly", "cloudfront", "azure", "aws"]
        text = f"{record.cdn or ''} {record.web_server or ''}".lower()
        return any(c in text for c in cdn_indicators)

    @staticmethod
    def _label(score: float) -> str:
        if score >= 0.75:
            return "strong"
        elif score >= 0.50:
            return "probable"
        elif score >= 0.25:
            return "possible"
        return "weak"
