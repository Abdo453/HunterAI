"""IoT device intelligence — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.iot.schemas import IoTDeviceRecord, IoTProtocol

log = logging.getLogger("iot.context")


class ContextEnricher:
    """L3: يضيف سياقًا لكل جهاز IoT (البروتوكول، المنافذ المفتوحة، خطر البيانات الافتراضية)."""

    def enrich(self, record: IoTDeviceRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "risk_tier": "low",
            "network_exposed": False,
            "protocol_risk": [],
            "notes": [],
        }

        if record.ip:
            context["network_exposed"] = True
            context["attack_surface"] = ["network_accessible"]
        else:
            context["attack_surface"] = ["local_only"]

        if record.protocol == IoTProtocol.MQTT:
            context["protocol_risk"].append("mqtt_broker_access")
            context["notes"].append("MQTT — قد يُنشر بيانات حساسة بدون مصادقة")
            context["risk_tier"] = "high"
        if record.protocol == IoTProtocol.UPNP:
            context["protocol_risk"].append("upnp_exposure")
            context["notes"].append("UPNP — surface للاختراق عبر LAN")
            context["risk_tier"] = "high"
        if record.protocol == IoTProtocol.BLE:
            context["protocol_risk"].append("ble_proximity")
            context["notes"].append("BLE — surface للهجوم من مدى قريب")
        if record.protocol == IoTProtocol.ZIGBEE:
            context["protocol_risk"].append("zigbee_network")
            context["notes"].append("Zigbee — شبكة محلية منخفضة الطاقة")

        if record.default_creds:
            context["risk_tier"] = "critical"
            context["notes"].append("بيانات اعتماد افتراضية — استيلاء محتمل")
        if record.unauthenticated:
            context["risk_tier"] = "critical"
            context["notes"].append("غير مصادق عليه — وصول مفتوح")
        if record.ports:
            high_risk_ports = [p for p in record.ports if p in (1883, 8883, 5683, 1900)]
            if high_risk_ports:
                context["notes"].append(
                    f"منافذ عالية الخطر: {high_risk_ports}"
                )

        return context


class AdaptiveTestAdvisor:
    """L4: يقترح خطوات الفحص التالية بناءً على جهاز IoT."""

    def advise(
        self,
        record: IoTDeviceRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        ip = record.ip or record.mac
        protocol = record.protocol
        suggestions: List[str] = []

        suggestions.append(f"nmap -sV {ip}")
        if protocol == IoTProtocol.MQTT:
            suggestions.append(f"mosquitto_sub -h {ip} -t '#' -C 1  # اختبار публикация/استقبال")
        if protocol == IoTProtocol.UPNP:
            suggestions.append(f"nmap -p 1900 --script upnp-info {ip}")
        if protocol == IoTProtocol.BLE:
            suggestions.append(f"gatttool -b {ip} --primary  # فحص خدمات BLE")
        if protocol == IoTProtocol.ZIGBEE:
            suggestions.append(f"zigbee2mqtt --map  # خريطة شبكةzigbee")
        if record.default_creds:
            suggestions.append(f"hydra -L default_users.txt -P default_pwds.txt {ip}")
        suggestions.append(f"nmap --script iot-* {ip}")

        seen: set = set()
        unique: List[str] = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
