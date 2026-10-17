"""Wireless / WiFi intelligence — L3 Context Intelligence + L4 Adaptive Advisor"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.wireless.schemas import EncryptionStrength, WiFiNetworkRecord

log = logging.getLogger("wireless.context")

# قنوات 2.4GHz المتداخلة (كل قناة تتداخل مع القنوات ±4)
CHANNEL_OVERLAP_2GHZ: Dict[int, List[int]] = {
    1: [2, 3, 4, 5],
    2: [1, 3, 4, 5, 6],
    3: [1, 2, 4, 5, 6, 7],
    4: [1, 2, 3, 5, 6, 7, 8],
    5: [1, 2, 3, 4, 6, 7, 8, 9],
    6: [2, 3, 4, 5, 7, 8, 9, 10],
    7: [3, 4, 5, 6, 8, 9, 10, 11],
    8: [4, 5, 6, 7, 9, 10, 11],
    9: [5, 6, 7, 8, 10, 11, 12, 13],
    10: [6, 7, 8, 9, 11, 12, 13],
    11: [7, 8, 9, 10, 12, 13],
    12: [8, 9, 10, 11, 13],
    13: [9, 10, 11, 12],
}


class ContextEnricher:
    """L3: يضيف سياقًا لكل شبكة WiFi (القنوات المتداخلة، SSID مخفي، WPS)."""

    def __init__(self, other_networks: Optional[List[WiFiNetworkRecord]] = None):
        self.other_networks = other_networks or []

    def enrich(self, record: WiFiNetworkRecord) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "risk_tier": "low",
            "channel_overlap": False,
            "overlapping_count": 0,
            "notes": [],
        }

        overlaps: List[str] = []
        if record.channel is not None:
            expected = CHANNEL_OVERLAP_2GHZ.get(record.channel, [])
            for other in self.other_networks:
                if other.bssid == record.bssid:
                    continue
                if other.channel in expected:
                    overlaps.append(other.bssid)
        if overlaps:
            context["channel_overlap"] = True
            context["overlapping_count"] = len(overlaps)
            context["notes"].append(
                f"قناة متداخلة مع {len(overlaps)} شبكة/interference محتملة"
            )

        if record.hidden:
            context["notes"].append("SSID مخفي — security by obscurity فقط")
        if record.wps:
            context["notes"].append("WPS مفعّل — surface لهجوم PixieDust / brute-force PIN")
            context["risk_tier"] = "high"
        if record.is_open:
            context["risk_tier"] = "critical"
            context["notes"].append("شبكة مفتوحة — कोई مصادقة")
        elif record.encryption == EncryptionStrength.WEP:
            context["risk_tier"] = "critical"
            context["notes"].append("WEP — قابل للكسر خلال دقائق")
        elif record.encryption == EncryptionStrength.WPA:
            context["risk_tier"] = "medium"
            context["notes"].append("WPA/WPA2 — surface للقاموس")

        if record.signal_dbm is not None and record.signal_dbm > -50:
            context["notes"].append("إشارة قوية — المدى الفعلي قريب")

        return context


class AdaptiveTestAdvisor:
    """L4: يقترح خطوات اللاسلكية التالية بناءً على النتيجة."""

    def advise(
        self,
        record: WiFiNetworkRecord,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        context = context or {}
        bssid = record.bssid
        ssid = record.ssid
        channel = record.channel or ""
        suggestions: List[str] = []

        suggestions.append(f"airodump-ng -c {channel} --bssid {bssid} -w capture wlan0mon")
        suggestions.append(f"aireplay-ng --deauth 10 -a {bssid} wlan0mon")

        if record.is_open:
            suggestions.append(f"no encryption — connect & enumerate {ssid}")
        elif record.encryption == EncryptionStrength.WEP:
            suggestions.append(f"aircrack-ng -b {bssid} capture*.cap")
        elif record.encryption == EncryptionStrength.WPA:
            suggestions.append(
                f"aircrack-ng -w wordlist.txt -b {bssid} capture*.cap"
            )
        if record.wps:
            suggestions.append(f"reaver -i wlan0mon -b {bssid} -vv")
            suggestions.append(f"wifite --wps --bssid {bssid}")

        seen: set = set()
        unique: List[str] = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique[:8]
