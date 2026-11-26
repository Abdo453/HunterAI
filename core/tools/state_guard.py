"""
Flow State Guard Sentinel
=========================
Adapted from PentAGI ``backend/pkg/tools/flow_manager.go`` (commit ``cffed94``, MIT License).

Marks tool/orchestration errors that stem from the flow/task/subtask being in a
state that makes the requested operation currently impossible (e.g., task
already running, no plan yet, unknown task ID, missing subtask after a DB
change) rather than malformed tool arguments.

Callers check ``is_state_guard(err)`` to skip LLM argument-fixing retries: no
amount of "corrected" arguments changes the underlying flow state, so retrying
only wastes model round-trips before the same guard fires again.
"""
from __future__ import annotations

from typing import Optional


class _ErrFlowStateGuardSentinel(Exception):
    """Sentinel type/instance identifying a flow-state guard refusal."""


# Sentinel instance (analogous to Go's ``var ErrFlowStateGuard = errors.New("flow state guard")``)
ErrFlowStateGuard: Exception = _ErrFlowStateGuardSentinel("flow state guard")


class FlowStateGuardError(Exception):
    """Wraps an underlying error so ``is_state_guard(err)`` reports True
    without altering ``str(err)`` — callers and the LLM only ever see the
    original message."""

    def __init__(self, inner: Exception | str) -> None:
        self._inner: Exception = inner if isinstance(inner, Exception) else RuntimeError(str(inner))
        super().__init__(str(self._inner))
        self.__cause__ = self._inner

    @property
    def inner(self) -> Exception:
        return self._inner

    def unwrap(self) -> Exception:
        return self._inner

    def __str__(self) -> str:
        return str(self._inner)


def state_guard(err: Exception | str) -> FlowStateGuardError:
    """Wrap ``err`` as a flow-state guard error without mutating its message."""
    if isinstance(err, FlowStateGuardError):
        return err
    return FlowStateGuardError(err)


def is_state_guard(err: Optional[BaseException]) -> bool:
    """Return True if ``err`` or any error in its cause/context chain is a
    ``FlowStateGuardError`` or ``ErrFlowStateGuard``."""
    seen: set[int] = set()
    cur: Optional[BaseException] = err
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if cur is ErrFlowStateGuard or isinstance(cur, (FlowStateGuardError, _ErrFlowStateGuardSentinel)):
            return True
        cur = cur.__cause__ if cur.__cause__ is not None else cur.__context__
    return False


def unwrap_state_guard(err: BaseException) -> BaseException:
    """Return the unwrapped original exception if ``err`` is a ``FlowStateGuardError``."""
    if isinstance(err, FlowStateGuardError):
        return err.unwrap()
    return err
