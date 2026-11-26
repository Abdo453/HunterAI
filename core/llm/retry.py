"""Exponential-backoff retry with jitter and capped Retry-After support.

Adapted from PentesterFlow/agent ``src/llm/retry.ts``
(commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import random
from typing import Awaitable, Callable, Optional, TypeVar

from core.llm.errors import BackendError, is_deterministic_error, is_transient

T = TypeVar("T")

#: Hard ceiling for server-advised Retry-After waits (30 seconds).
MAX_RETRY_AFTER_S: float = 30.0


@dataclass(frozen=True)
class RetryInfo:
    """Metadata passed to ``on_retry`` hooks before sleeping."""

    attempt: int
    delay_s: float
    error: BaseException


@dataclass
class RetryOptions:
    """Configuration for ``with_retry``."""

    retries: int = 2
    base_delay_s: float = 0.5
    max_delay_s: float = 8.0
    max_retry_after_s: float = MAX_RETRY_AFTER_S
    sleep: Optional[Callable[[float], Awaitable[None]]] = None
    rand: Optional[Callable[[], float]] = None
    cancel_event: Optional[asyncio.Event] = None
    on_retry: Optional[Callable[[RetryInfo], None]] = None


async def _default_sleep(delay_s: float, cancel_event: Optional[asyncio.Event]) -> None:
    if cancel_event is None:
        await asyncio.sleep(delay_s)
        return
    if cancel_event.is_set():
        raise asyncio.CancelledError("retry aborted")
    sleep_task = asyncio.create_task(asyncio.sleep(delay_s))
    cancel_task = asyncio.create_task(cancel_event.wait())
    try:
        done, pending = await asyncio.wait(
            {sleep_task, cancel_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for p in pending:
            p.cancel()
        if cancel_task in done and cancel_event.is_set():
            raise asyncio.CancelledError("retry aborted")
    finally:
        for t in (sleep_task, cancel_task):
            if not t.done():
                t.cancel()


def compute_retry_delay(
    attempt: int,
    err: BaseException,
    *,
    base_delay_s: float = 0.5,
    max_delay_s: float = 8.0,
    max_retry_after_s: float = MAX_RETRY_AFTER_S,
    rand_value: Optional[float] = None,
) -> float:
    """Compute bounded exponential backoff + jitter, respecting capped Retry-After."""
    backoff = min(max_delay_s, base_delay_s * (2 ** max(0, attempt)))
    r = random.random() if rand_value is None else max(0.0, min(1.0, float(rand_value)))
    jittered = backoff + r * base_delay_s
    advised = 0.0
    if isinstance(err, BackendError) and err.retry_after_s is not None:
        advised = max(0.0, min(float(err.retry_after_s), max_retry_after_s))
    return max(jittered, advised)


async def with_retry(
    fn: Callable[[], Awaitable[T]],
    options: Optional[RetryOptions] = None,
    *,
    retries: Optional[int] = None,
    base_delay_s: Optional[float] = None,
    max_delay_s: Optional[float] = None,
    sleep: Optional[Callable[[float], Awaitable[None]]] = None,
    on_retry: Optional[Callable[[RetryInfo], None]] = None,
) -> T:
    """Execute ``fn`` with exponential backoff + jitter on transient backend errors.

    Deterministic errors (refusals, 4xx other than 408/429, auth/model errors)
    and cancellations propagate immediately without retrying.
    """
    opts = options or RetryOptions()
    max_retries = opts.retries if retries is None else retries
    b_delay = opts.base_delay_s if base_delay_s is None else base_delay_s
    m_delay = opts.max_delay_s if max_delay_s is None else max_delay_s
    sleep_fn = sleep or opts.sleep or (lambda d: _default_sleep(d, opts.cancel_event))
    retry_cb = on_retry or opts.on_retry
    rand_fn = opts.rand or random.random

    attempt = 0
    while True:
        try:
            return await fn()
        except asyncio.CancelledError:
            raise
        except Exception as err:
            if opts.cancel_event is not None and opts.cancel_event.is_set():
                raise
            if attempt >= max_retries or is_deterministic_error(err) or not is_transient(err):
                raise
            delay_s = compute_retry_delay(
                attempt,
                err,
                base_delay_s=b_delay,
                max_delay_s=m_delay,
                max_retry_after_s=opts.max_retry_after_s,
                rand_value=rand_fn(),
            )
            if retry_cb is not None:
                retry_cb(RetryInfo(attempt=attempt + 1, delay_s=delay_s, error=err))
            await sleep_fn(delay_s)
            attempt += 1


__all__ = [
    "MAX_RETRY_AFTER_S",
    "RetryInfo",
    "RetryOptions",
    "compute_retry_delay",
    "with_retry",
]
