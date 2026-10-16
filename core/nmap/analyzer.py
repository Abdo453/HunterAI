"""Nmap Service Fingerprint — L2 AI Analyzer + L5 Evidence Reviewer
Port Normalizer + Duplicate Detector + Service Confidence + Evidence Reviewer (rule-based، لا LLM لكل خطوة)
"""
from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from collections import defaultdict

from core.nmap.schemas import (
    NmapPortRecord, ServiceProfile,
    NmapEvidenceLevel, ServiceConfidence,
)

log = logging.getLogger("nmap.analyzer")


class NmapNormalizer:
    """
    L2: يحول مخرجات Nmap XML إلى NmapPortRecord موحد،
    مع تصنيف الخدمة وتقييم الثقة المبدئي.
    """

    @staticmethod
    def normalize_nmap_xml(xml_output: str) -> List[NmapPortRecord]:
        """
        يُحط مخرجات Nmap XML إلى قائمة سجلات موحدة.
        """
        records: List[NmapPortRecord] = []
        if not xml_output.strip():
            return records

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            log.warning("Nmap XML parse failed — falling back to text parsing")
            return NmapNormalizer._parse_text_fallback(xml_output)

        # استضافة المضيفين
        for host_elem in root.findall("host"):
            host = host_elem.findtext("address/addr", default="unknown") if host_elem.find("address") is not None else "unknown"
            # قد يكون هناك عناوين متعددة، نأخذ أول IPv4
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    host = addr.get("addr")
                    break

            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall("port"):
                port = int(port_elem.get("portid", 0))
                protocol = port_elem.get("protocol", "tcp")

                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

                service_elem = port_elem.find("service")
                service_name = service_elem.get("name") if service_elem is not None else None
                service_product = service_elem.get("product") if service_elem is not None else None
                service_version = service_elem.get("version") if service_elem is not None else None

                # استخراج الـ banner
                banner = None
                if service_elem is not None:
                    banner_parts = []
                    if service_product:
                        banner_parts.append(service_product)
                    if service_version:
                        banner_parts.append(service_version)
                    if service_name:
                        banner_parts.append(service_name)
                    banner = " ".join(banner_parts) if banner_parts else None

                # تقييم الثقة المبدئي (L2)
                confidence = NmapNormalizer._evaluate_confidence(
                    state, service_name, service_product, service_version, banner
                )

                digest_src = f"{host}:{port}:{protocol}"
                record_id = f"nm_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

                records.append(NmapPortRecord(
                    record_id=record_id,
                    host=host,
                    port=port,
                    protocol=protocol,
                    state=state,
                    service_name=service_name,
                    service_version=service_version,
                    service_product=service_product,
                    banner=banner,
                    confidence=confidence,
                    evidence_level=NmapEvidenceLevel.E0,
                    source_tool="nmap",
                    raw_json={},  # XML not easily dictified; stored in validation_note
                    validation_note=f"Nmap scan: {host}:{port}/{protocol} state={state} service={service_name or 'unknown'}",
                ))

        return records

    @staticmethod
    def _evaluate_confidence(
        state: str,
        service_name: Optional[str],
        service_product: Optional[str],
        service_version: Optional[str],
        banner: Optional[str],
    ) -> str:
        """يحدد مستوى الثقة المبدئي في اكتشاف الخدمة."""
        if state != "open":
            return ServiceConfidence.UNKNOWN

        if service_product and service_version:
            return ServiceConfidence.CONFIRMED
        if service_product:
            return ServiceConfidence.PROBABLE
        if service_name:
            return ServiceConfidence.POSSIBLE
        return ServiceConfidence.UNKNOWN

    @staticmethod
    def _parse_text_fallback(text: str) -> List[NmapPortRecord]:
        """محاكاة بسيطة للمخرجات النصية إذا فشل XML."""
        records: List[NmapPortRecord] = []
        # نمط بسيط: PORT   STATE SERVICE VERSION
        pattern = re.compile(
            r"(\d+)/(\w+)\s+(\w+)\s+(\S+)(?:\s+(.+))?",
            re.IGNORECASE,
        )
        for line in text.splitlines():
            m = pattern.search(line)
            if not m:
                continue
            port = int(m.group(1))
            protocol = m.group(2)
            state = m.group(3)
            service_name = m.group(4)
            version_info = m.group(5) or ""

            product = None
            service_version = None
            if version_info:
                parts = version_info.split(" ", 1)
                product = parts[0]
                if len(parts) > 1:
                    service_version = parts[1]

            confidence = NmapNormalizer._evaluate_confidence(
                state, service_name, product, service_version, version_info
            )

            digest_src = f"unknown:{port}:{protocol}"
            record_id = f"nm_{__import__('hashlib').md5(digest_src.encode()).hexdigest()[:10]}"

            records.append(NmapPortRecord(
                record_id=record_id,
                host="unknown",
                port=port,
                protocol=protocol,
                state=state,
                service_name=service_name,
                service_version=service_version,
                service_product=product,
                banner=version_info,
                confidence=confidence,
                evidence_level=NmapEvidenceLevel.E0,
                source_tool="nmap",
                raw_json={},
                validation_note=f"Nmap text fallback: port={port}/{protocol} state={state}",
            ))
        return records

    def normalize_batch(self, nmap_stdout: str) -> List[NmapPortRecord]:
        """يحول مخرجات nmap XML إلى قائمة سجلات."""
        return self.normalize_nmap_xml(nmap_stdout)


class DuplicateDetector:
    """
    L2: يكتشف المنافذ المكررة (نفس host:port:protocol) ويجمعها.
    """

    def __init__(self):
        self._groups: Dict[str, List[NmapPortRecord]] = defaultdict(list)

    def add(self, record: NmapPortRecord) -> Optional[List[NmapPortRecord]]:
        key = record.canonical_key
        self._groups[key].append(record)
        if len(self._groups[key]) > 1:
            return self._groups[key]
        return None

    def flush(self) -> Dict[str, List[NmapPortRecord]]:
        groups = dict(self._groups)
        self._groups.clear()
        return groups


class EvidenceReviewer:
    """
    L5 Verification: يراجع الأدلة المرتبطة بكل منفذ ويحدد:
      - هل الأدلة كافية لدعم الملف الخدمي؟ (evidence_status)
      - هل المنفذ يحتاج تحقق إضافي؟ (needs_verification)
      - هل الخدمة عالية القيمة (SSH, HTTP, DB, إلخ)؟
      - درجة الثقة المبدئية (بدون LLM)
    """

    HIGH_VALUE_PORTS = {
        22: "SSH",
        21: "FTP",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
        5900: "VNC",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
    }

    WAF_SERVICE_PATTERNS = [
        "cloudflare", "akamai", "imperva", "incapsula", "f5", "bigip",
        "aws-waf", "sucuri", "fortinet", "fortigate",
    ]

    def __init__(self):
        pass

    def review(self, record: NmapPortRecord) -> Dict[str, Any]:
        """
        يُرجع تقرير مراجعة للمنفذ.
        """
        issues: List[str] = []
        confidence = 0.15  # قاعدة: نتيجة Nmap واحدة غير كافية للإثبات الكامل

        # حالة المنفذ
        if record.state == "open":
            confidence += 0.25
        elif record.state in ("filtered", "closed"):
            confidence += 0.05
            issues.append(f"منفذ {record.state} — قد يكون محمياً أو مغلقاً")
        else:
            issues.append(f"حالة منفذ غير معروفة ({record.state})")

        # اسم الخدمة
        if record.service_name:
            confidence += 0.15
        else:
            issues.append("لا يوجد اسم خدمة مكتشف")

        # الإصدار + المنتج = دليل أقوى
        if record.service_product and record.service_version:
            confidence += 0.2
        elif record.service_product:
            confidence += 0.1
        elif record.service_version:
            confidence += 0.1
        else:
            issues.append("لا يوجد منتج أو إصدار خدمة مكتشف")

        # الـ banner
        if record.banner:
            confidence += 0.1

        # منفذ عالي القيمة
        is_high_value = record.port in self.HIGH_VALUE_PORTS
        if is_high_value:
            confidence += 0.1
            issues.append(f"منفذ عالي القيمة ({self.HIGH_VALUE_PORTS[record.port]})")

        # كشف WAF
        is_waf = False
        banner_text = (record.banner or "").lower()
        for waf_pattern in self.WAF_SERVICE_PATTERNS:
            if waf_pattern in banner_text:
                is_waf = True
                issues.append(f"يُحتمل وجود WAF ({waf_pattern})")
                break
        if is_waf:
            confidence += 0.05  # WAF يزيد الثقة في الحماية لكنه قد يخفي الخدمات الحقيقية

        # إذا كانت الأدلة مكتملة → E1
        if record.state == "open" and record.service_name and (record.service_product or record.service_version):
            record.evidence_level = NmapEvidenceLevel.E1

        confidence = max(0.0, min(confidence, 1.0))
        label = self._label(confidence)

        return {
            "record_id": record.record_id,
            "host": record.host,
            "port": record.port,
            "protocol": record.protocol,
            "state": record.state,
            "service_name": record.service_name,
            "service_version": record.service_version,
            "service_product": record.service_product,
            "banner": record.banner,
            "confidence_score": round(confidence, 2),
            "confidence_label": label,
            "evidence_level": record.evidence_level,
            "evidence_status": "sufficient" if record.evidence_level == NmapEvidenceLevel.E1 else "insufficient",
            "is_high_value": is_high_value,
            "is_likely_waf": is_waf,
            "needs_verification": record.evidence_level != NmapEvidenceLevel.E1,
            "issues": issues,
            "recommendation": (
                "خدمة موثقة (E1) — يُنصح بالفحص العميق عبر Nuclei أو أدوات متخصصة حسب نوع الخدمة."
                if record.evidence_level == NmapEvidenceLevel.E1 else
                "الخدمة تحتاج أدلة إضافية قبل اعتمادها في التحقيق الأمني."
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
