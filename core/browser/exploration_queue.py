"""
Exploration Queue
=================
Priority queue for exploration frontiers (URLs, actions, states) sorted by Information Gain.
"""
from __future__ import annotations

import heapq
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.exploration_queue")


@dataclass(order=True)
class FrontierItem:
    priority: float  # Inverted for min-heap: -priority
    url: str = field(compare=False)
    depth: int = field(compare=False, default=0)
    referrer: str = field(compare=False, default="")
    action_hint: Optional[str] = field(compare=False, default=None)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "depth": self.depth,
            "priority": -self.priority,
            "referrer": self.referrer,
            "action_hint": self.action_hint,
        }


class ExplorationQueue:
    """Manages priority-ordered exploration tasks and deduplicates candidates"""

    def __init__(self):
        self._heap: List[FrontierItem] = []
        self._enqueued_urls: Set[str] = set()

    def enqueue(self, url: str, priority: float = 1.0, depth: int = 0, referrer: str = "", action_hint: Optional[str] = None) -> bool:
        norm_url = url.strip()
        if norm_url in self._enqueued_urls:
            return False

        self._enqueued_urls.add(norm_url)
        # heapq is a min-heap, so store -priority to pop highest first
        item = FrontierItem(priority=-priority, url=norm_url, depth=depth, referrer=referrer, action_hint=action_hint)
        heapq.heappush(self._heap, item)
        return True

    def pop(self) -> Optional[FrontierItem]:
        if not self._heap:
            return None
        return heapq.heappop(self._heap)

    def __len__(self) -> int:
        return len(self._heap)

    def is_empty(self) -> bool:
        return len(self._heap) == 0

    def peek(self) -> Optional[FrontierItem]:
        return self._heap[0] if self._heap else None
