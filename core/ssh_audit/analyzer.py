"""SSH-Audit Security Profiler — L2 AI Analyzer + L5 Evidence Reviewer
Finding Normalizer + Duplicate Detector + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.ssh_audit.schemas import (
    SSHAssetRecord, SSHSecurityProfile,
    SSHAuditEvidenceLevel,
)

log = logging.getLogger("ssh_audit.analyzer")


class SSHAuditNormalizer:
    """
    L2: يحول مخرجات ssh-audit JSON إلى SSHAssetRecord موحد،
    مع استخراج الحقول الهامة وتطبيعها.
    """

    @staticmethod
    def normalize_ssh_audit_json_line(line: str) -> Optional[SSHAssetRecord]:
        """
        يُحط سطر JSON واحد من مخرجات ssh-audit (-j) إلى سجل موحد.
        ssh-audit قد يُخرج كائن JSON واحد لكل هدف.
        """
        line = line.strip()
        if not line:
            return None
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        host = data.get("host", "") or data.get("ip", "") or data.get("hostname", "") or ""
        port = data.get("port", 22) or 22
        banner = data.get("web_server", "") or data.get("banner", "")
        status_code = data.get("status_code")
        technologies = data.get("technology", []) or []
        url = data.get("url")
        scheme = data.get("scheme")
        content_length = data.get("content_length")
        content_type = data.get("content_type")
        cdn = data.get("cdn")
        ip = data.get("ip")
        cname = data.get("cname")

        # استخراج الخوارزميات
        kex = data.get("kex_algorithms", []) or []
        server_host_key = data.get("server_host_key_algorithms", []) or []
        encryption = data.get("encryption_algorithms", []) or []
        mac = data.get("mac_algorithms", []) or []
        compression = data.get("compression_algorithms", []) or []

        # استخراج issues
        issues = data.get("issues", []) or []

        digest_src = f"{host}:{port}"
        record_id = f"ssh_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

        # Determine evidence level & status
        evidence_level = SSHAuditEvidenceLevel.E0
        evidence_status = "raw"
        confidence_score = 0.2
        if status_code is not None and banner and technologies:
            evidence_level = SSHAuditEvidenceLevel.E1
            evidence_status = "sufficient"
            confidence_score = 0.75

        return SSHAssetRecord(
            record_id=record_id,
            host=host,
            port=port,
            banner=banner,
            url=url,
            scheme=scheme,
            status_code=status_code,
            content_length=content_length,
            content_type=content_type,
            web_server=banner,
            technologies=technologies,
            cdn=cdn,
            ip=ip,
            cname=cname,
            kex_algorithms=kex,
            server_host_key_algorithms=server_host_key,
            encryption_algorithms=encryption,
            mac_algorithms=mac,
            compression_algorithms=compression,
            issues=issues,
            evidence_level=evidence_level,
            evidence_status=evidence_status,
            confidence_score=confidence_score,
            source_tool="ssh-audit",
            raw_json=data,
            validation_note=f"SSH {host}:{port} | {len(issues)} issues | Banner: {banner or 'unknown'}",
        )

    def normalize_batch(self, ssh_audit_stdout: str) -> List[SSHAssetRecord]:
        """يحول مخرجات ssh-audit JSON إلى قائمة سجلات."""
        records: List[SSHAssetRecord] = []
        for line in ssh_audit_stdout.splitlines():
            rec = self.normalize_ssh_audit_json_line(line)
            if rec:
                records.append(rec)
        return records


class DuplicateDetector:
    """
    L2: يكتشف الأصول المكررة (نفس host:port) ويجمعها في مجموعة واحدة.
    """

    def __init__(self):
        self._groups: Dict[str, List[SSHAssetRecord]] = defaultdict(list)

    def add(self, record: SSHAssetRecord) -> Optional[List[SSHAssetRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[SSHAssetRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل أصل SSH ويحدد:
      - هل الأدلة كافية لدعم الملف الأمني؟ (evidence_status)
      - هل الأصل يحتاج تحقق إضافي؟ (needs_verification)
      - درجة الثقة المبدئية (بدون LLM)
    """

    def __init__(self):
        pass

    def review(self, record: SSHAssetRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للسجل.
        """
        issues: List[str] = []
        confidence = 0.2  # قاعدة: نتيجة ssh-audit واحدة غير كافية للإثبات الكامل

        # وجود Banner = دليل أقوى
        if record.banner:
            confidence += 0.2
        else:
            issues.append("لا يوجد Banner لـ SSH server")

        # وجود خوارزميات Kex = دليل أقوى
        if record.server_host_key_algorithms:
            confidence += 0.15
        else:
            issues.append("لا يوجد خوارزميات مفتاح مضيف (host key algorithms)")

        # وجود تشفير = دليل أقوى
        if record.encryption_algorithms:
            confidence += 0.15
        else:
            issues.append("لا يوجد خوارزميات تشفير (encryption algorithms)")

        # حساب عدد الإشادات حسب الخطورة
        critical = sum(1 for i in record.issues if i.get("severity", "").lower() == "critical")
        high = sum(1 for i in record.issues if i.get("severity", "").lower() == "high")
        medium = sum(1 for i in record.issues if i.get("severity", "").lower() == "medium")
        low = sum(1 for i in record.issues if i.get("severity", "").lower() == "low")
        info = sum(1 for i in record.issues if i.get("severity", "").lower() == "info")

        # خصم ثقة إذا كانت هناك قضايا خطيرة
        if critical > 0:
            confidence -= 0.30
            issues.append(f"يوجد {critical} قضية خطيرة (Critical) في إعدادات SSH")
        if high > 0:
            confidence -= 0.15
            issues.append(f"يوجد {high} قضية عالية (High) في إعدادات SSH")

        # إذا كانت الأدلة مكتملة → E1
        if record.banner and record.server_host_key_algorithms and record.encryption_algorithms:
            evidence_status = "sufficient"
            record.evidence_level = SSHAuditEvidenceLevel.E1
        else:
            evidence_status = "insufficient"

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "host": record.host,
            "port": record.port,
            "banner": record.banner,
            "evidence_status": evidence_status,
            "confidence": round(confidence, 2),
            "confidence_label": label,
            "evidence_level": record.evidence_level,
            "critical_issues": critical,
            "high_issues": high,
            "medium_issues": medium,
            "low_issues": low,
            "info_issues": info,
            "total_issues": len(record.issues),
            "needs_verification": record.evidence_level != SSHAuditEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "إعدادات SSH موثقة (E1) — يُنصح بتحديث الخوارزميات الضعيفة وتعطيل الإصدارات القديمة."
                if record.evidence_level == SSHAuditEvidenceLevel.E1 else
                "الأدلة ناقصة — يُنصح بإعادة الفحص أو التحقق手动 من إعدادات SSH."
            ),
        }

    @staticmethod
    def _label(score: float) -> str:
        if score >= 0.75:
            return "strong"
        elif score >= 0.50:
            return "probable"
        elif score >= 0.25:
            return "possible"
        return "weak"
