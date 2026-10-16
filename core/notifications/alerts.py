"""
HunterAI Notifications — إشعارات Discord و Telegram للنتائج الحرجة
مقتبس من تكامل Xalgorix مع Discord و Telegram
"""
from __future__ import annotations

import logging
import asyncio
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

log = logging.getLogger("hunter_ai.notifications")


class AlertSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """تنبيه أمني للإرسال"""
    title: str
    message: str
    severity: str
    target: str
    finding_id: str
    confidence: float
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            import time
            self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "message": self.message,
            "severity": self.severity,
            "target": self.target,
            "finding_id": self.finding_id,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }


class NotificationManager:
    """
    مدير الإشعارات — يرسل التنبيهات إلى Discord و Telegram webhooks
    """

    def __init__(
        self,
        discord_webhook: Optional[str] = None,
        telegram_bot_token: Optional[str] = None,
        telegram_chat_id: Optional[str] = None,
        min_severity: str = "medium",
    ):
        self.discord_webhook = discord_webhook
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_chat_id
        self.min_severity = min_severity
        self._severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def _should_send(self, severity: str) -> bool:
        return self._severity_order.get(severity, 0) >= self._severity_order.get(self.min_severity, 2)

    async def send(self, alert: Alert) -> dict:
        """
        يرسل التنبيه إلى جميع القنوات المفعلة
        """
        if not self._should_send(alert.severity):
            return {"sent": False, "reason": "below min severity"}

        results = {}
        if HAS_AIOHTTP:
            if self.discord_webhook:
                results["discord"] = await self._send_discord(alert)
            if self.telegram_bot_token and self.telegram_chat_id:
                results["telegram"] = await self._send_telegram(alert)
        else:
            log.warning("aiohttp not installed. Install with: pip install aiohttp")

        return {"sent": bool(results), "details": results}

    async def send_batch(self, alerts: List[Alert]) -> dict:
        """
        يرسل دفعة من التنبيهات
        """
        results = []
        for alert in alerts:
            res = await self.send(alert)
            results.append(res)
        return {"total": len(alerts), "sent": sum(1 for r in results if r["sent"]), "details": results}

    # ── Discord Webhook ──────────────────────────────────────────────

    async def _send_discord(self, alert: Alert) -> dict:
        if not self.discord_webhook:
            return {"sent": False, "reason": "no webhook"}

        color_map = {
            "critical": 0xFF0000,
            "high": 0xFF4500,
            "medium": 0xFFA500,
            "low": 0xFFFF00,
            "info": 0x0099FF,
        }

        embed = {
            "title": f"🚨 HunterAI — {alert.title}",
            "description": alert.message,
            "color": color_map.get(alert.severity, 0x0099FF),
            "fields": [
                {"name": "الهدف", "value": alert.target, "inline": True},
                {"name": "الشدة", "value": alert.severity.upper(), "inline": True},
                {"name": "الثقة", "value": f"{alert.confidence:.0%}", "inline": True},
                {"name": "المعرف", "value": alert.finding_id, "inline": False},
            ],
            "footer": {"text": "HunterAI Autonomous Security Agent"},
        }

        payload = {
            "username": "HunterAI",
            "embeds": [embed],
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.discord_webhook, json=payload) as resp:
                    return {"sent": resp.status == 204, "status": resp.status}
        except Exception as e:
            log.exception("Discord webhook error")
            return {"sent": False, "reason": str(e)}

    # ── Telegram ─────────────────────────────────────────────────────

    async def _send_telegram(self, alert: Alert) -> dict:
        if not self.telegram_bot_token or not self.telegram_chat_id:
            return {"sent": False, "reason": "no bot token or chat id"}

        emoji_map = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "⚠️",
            "low": "ℹ️",
            "info": "ℹ️",
        }

        text = (
            f"{emoji_map.get(alert.severity, 'ℹ️')} *HunterAI Security Alert*\n\n"
            f"*العنوان:* {alert.title}\n"
            f>*الرسالة:* {alert.message}\n\n"
            f"*الهدف:* `{alert.target}`\n"
            f"*الشدة:* {alert.severity.upper()}\n"
            f"*الثقة:* {alert.confidence:.0%}\n"
            f"*المعرف:* `{alert.finding_id}`\n"
        )

        url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    return {"sent": resp.status == 200, "status": resp.status}
        except Exception as e:
            log.exception("Telegram webhook error")
            return {"sent": False, "reason": str(e)}
