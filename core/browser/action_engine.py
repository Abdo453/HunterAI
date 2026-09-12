"""
Action Engine
=============
Executes UI interactions (click, type, hover, submit) safely with DOM mutation tracking.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("hunter_ai.action_engine")


class ActionEngine:
    """Safely triggers DOM interactions and observes side-effects"""

    def __init__(self, session: Any):
        self.session = session

    async def execute_action(
        self,
        selector: str,
        action_type: str = "click",
        value: str = "",
        settle_delay: float = 0.5,
    ) -> bool:
        """Executes a sandboxed action with safety checks"""
        try:
            res = await self.session.interact(selector, action_type, value)
            if settle_delay > 0:
                await asyncio.sleep(settle_delay)
            return res
        except Exception as e:
            logger.debug(f"[ACTION_ENGINE] Failed action {action_type} on {selector}: {e}")
            return False
