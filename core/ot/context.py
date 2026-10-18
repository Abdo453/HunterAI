"""OT / ICS intelligence — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.ot.schemas import OTAssetRecord, OTProtocol

log = logging.getLogger("ot.context")


class ContextEnricher:
    """L3: يضيف سياقًا لكل أصل OT (البروتوكول، صلاحية الكتابة، التأثير على السلامة)."""

    def enrich(self, record: OTAssetRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "safety_impact": "low",
            "process_control": False,
            "protocol_risk": [],
            "notes": [],
        }

        if record.protocol == OTProtocol.MODBUS:
            context["protocol_risk"].append("modbus_cleartext")
            context["notes"].append("Modbus TCP — نص واضح، عادة بلا مصادقة")
            context["safety_impact"] = "medium"
        if record.protocol == OTProtocol.S7:
            context["protocol_risk"].append("s7comm")
            context["notes"].append("S7comm — بروتوكول سيمنز للتحكم المنطقي")
            context["safety_impact"] = "medium"
        if record.protocol == OTProtocol.ETHERNET_IP:
            context["protocol_risk"].append("cip_exposure")
            context["notes"].append("EtherNet/IP — سطح للتحكم الصناعي")
            context["safety_impact"] = "medium"

        if record.unauthenticated:
            context["process_control"] = True
            context["notes"].append("غير مصادق — إرسال أوامر تحكم ممكن")
            context["safety_impact"] = "high"
        if record.write_access:
            context["process_control"] = True
            context["notes"].append("صلاحية كتابة — تعديل قيم المعالجة ممكن")
            context["safety_impact"] = "critical"

        high_risk_ports = [p for p in (record.port,) if p in (502, 102, 44818)]
        if high_risk_ports:
            context["notes"].append(f"منفذ OT قياسي: {high_risk_ports[0]}")

        return context


class AdaptiveTestAdvisor:
    """L4: يقترح خطوات الفحص التالية بناءً على أصل OT."""

    def advise(
        self,
        record: OTAssetRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        ip = record.ip
        port = record.port
        protocol = record.protocol
        suggestions: List[str] = []

        suggestions.append(f"nmap -p {port} --script {protocol}-* {ip}")
        if protocol == OTProtocol.MODBUS:
            suggestions.append(
                f"nmap -p {port} --script modbus-discover {ip}  # اكتشاف وحدات Modbus"
            )
            if record.unit_id:
                suggestions.append(
                    f"modbus-cli read-holding-registers -a {ip} -u {record.unit_id}  # قراءة مسجلات"
                )
        if protocol == OTProtocol.S7:
            suggestions.append(
                f"nmap -p {port} --script s7-info {ip}  # معلومات وحدة سيمنز"
            )
        if record.unauthenticated:
            suggestions.append(
                f"⚠️  تجنب الكتابة إلى {ip}:{port} — اختبار reading فقط"
            )

        seen: set = set()
        unique: List[str] = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
