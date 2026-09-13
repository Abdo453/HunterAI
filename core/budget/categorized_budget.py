"""
HunterAI Categorized Test Budget Allocator
==========================================
Partitions scan quotas into specialized category buckets:
- AUTHENTICATION: 800
- AUTHORIZATION_BOLA: 1200
- INJECTION_TESTS: 1500
- CLIENT_SIDE_JS: 700
- VERIFICATION_REPLAY: 500
- RESERVE: 300

Supports dynamic reallocation of unspent budget from exhausted/passive buckets
to active high-yield targets.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict


class BudgetCategory(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION_BOLA = "AUTHORIZATION_BOLA"
    INJECTION_TESTS = "INJECTION_TESTS"
    CLIENT_SIDE_JS = "CLIENT_SIDE_JS"
    VERIFICATION_REPLAY = "VERIFICATION_REPLAY"
    RESERVE = "RESERVE"


@dataclass
class BudgetQuota:
    category: BudgetCategory
    allocated: int
    consumed: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.allocated - self.consumed)


class CategorizedBudgetManager:
    """Manages categorized request budgeting and dynamic reallocation"""

    DEFAULT_BUDGET = {
        BudgetCategory.AUTHENTICATION: 800,
        BudgetCategory.AUTHORIZATION_BOLA: 1200,
        BudgetCategory.INJECTION_TESTS: 1500,
        BudgetCategory.CLIENT_SIDE_JS: 700,
        BudgetCategory.VERIFICATION_REPLAY: 500,
        BudgetCategory.RESERVE: 300,
    }

    def __init__(self, custom_allocation: Dict[BudgetCategory, int] = None):
        alloc = custom_allocation or self.DEFAULT_BUDGET
        self.quotas: Dict[BudgetCategory, BudgetQuota] = {
            cat: BudgetQuota(category=cat, allocated=amount)
            for cat, amount in alloc.items()
        }

    def can_consume(self, category: BudgetCategory, count: int = 1) -> bool:
        quota = self.quotas.get(category)
        if not quota:
            return False
        return quota.remaining >= count

    def consume(self, category: BudgetCategory, count: int = 1) -> bool:
        quota = self.quotas.get(category)
        if not quota or quota.remaining < count:
            # Try to draw from RESERVE if available
            reserve = self.quotas[BudgetCategory.RESERVE]
            if category != BudgetCategory.RESERVE and reserve.remaining >= count:
                reserve.consumed += count
                quota.consumed += count
                return True
            return False

        quota.consumed += count
        return True

    def reallocate(self, from_cat: BudgetCategory, to_cat: BudgetCategory, amount: int) -> bool:
        src = self.quotas.get(from_cat)
        dst = self.quotas.get(to_cat)
        if not src or not dst or src.remaining < amount:
            return False

        src.allocated -= amount
        dst.allocated += amount
        return True

    def get_summary(self) -> Dict[str, Any]:
        total_allocated = sum(q.allocated for q in self.quotas.values())
        total_consumed = sum(q.consumed for q in self.quotas.values())
        return {
            "total_allocated": total_allocated,
            "total_consumed": total_consumed,
            "total_remaining": total_allocated - total_consumed,
            "categories": {
                cat.value: {
                    "allocated": q.allocated,
                    "consumed": q.consumed,
                    "remaining": q.remaining
                }
                for cat, q in self.quotas.items()
            }
        }
