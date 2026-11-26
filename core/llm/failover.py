"""Non-deterministic failover orchestration across primary and backup LLM calls.

Adapted from:
- vxcontrol/pentagi ``backend/pkg/providers/retry.go``
  (commit ``cffed9485aa1cca70762cd08a57ac62a80406258``, licensed under MIT;
  see ``THIRD_PARTY_LICENSES/PENTAGI_MIT.txt`` and ``NOTICE``).
- PentesterFlow/agent ``src/llm/errors.ts`` & ``src/llm/retry.ts``
  (commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
  see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from typing import Awaitable, Callable, Generic, Optional, TypeVar

from core.llm.errors import is_deterministic_error, is_refusal_error

logger = logging.getLogger("hunter_ai.llm.failover")

T = TypeVar("T")


@dataclass
class FailoverResult(Generic[T]):
    """Outcome of a primary -> backup failover call."""

    value: T
    used_backup: bool = False
    primary_error: Optional[BaseException] = None


def should_failover(err: BaseException) -> bool:
    """Return True only when *err* is non-deterministic and NOT a refusal or 4xx client error.

    Failover triggers on transport outages, timeouts, rate limits (429/408),
    or upstream 5xx errors. Refusals and deterministic 4xx errors (400, 401,
    403, 404, 422) are NOT blindly failed over to a different provider.
    """
    if isinstance(err, asyncio.CancelledError):
        return False
    if is_refusal_error(err):
        return False
    if is_deterministic_error(err):
        return False
    return True


async def with_failover(
    primary: Callable[[], Awaitable[T]],
    backup: Optional[Callable[[], Awaitable[T]]],
    *,
    on_failover: Optional[Callable[[BaseException], None]] = None,
    return_metadata: bool = False,
) -> T | FailoverResult[T]:
    """Run ``primary`` and fall back to ``backup`` ONLY on non-deterministic failures.

    Refusals, deterministic 4xx client errors (except 408/429), and task
    cancellations propagate directly without invoking ``backup``.
    """
    try:
        val = await primary()
        return FailoverResult(value=val, used_backup=False) if return_metadata else val
    except asyncio.CancelledError:
        raise
    except Exception as primary_err:
        if backup is None or not should_failover(primary_err):
            raise
        logger.warning(
            "[LLMFailover] Primary failed with non-deterministic error (%s); invoking backup",
            primary_err,
        )
        if on_failover is not None:
            on_failover(primary_err)
        backup_val = await backup()
        if return_metadata:
            return FailoverResult(
                value=backup_val,
                used_backup=True,
                primary_error=primary_err,
            )
        return backup_val


__all__ = [
    "FailoverResult",
    "should_failover",
    "with_failover",
]
