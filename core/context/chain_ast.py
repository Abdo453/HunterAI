"""AST-aware conversation chain representation and window byte budget calculations.

Adapted from vxcontrol/pentagi ``backend/pkg/cast/chain_ast.go`` and
``backend/pkg/providers/provider/limits.go``
(commit ``cffed9485aa1cca70762cd08a57ac62a80406258``, licensed under MIT;
see ``THIRD_PARTY_LICENSES/PENTAGI_MIT.txt`` and ``NOTICE``).

Guarantees:
- Exact ``chain_byte_budget(window, tools)`` reserving ``MINIMUM_OUTPUT_ROOM``
  and accounting for attached tool schemas BEFORE sizing history bytes.
- Structural ``ChainAST`` grouping messages into ``ChainSection`` (``Header`` +
  ``BodyPair``s) so paired assistant ``tool_calls`` and ``role='tool'`` results
  are NEVER orphaned or split apart during compaction.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any, Dict, List, Optional, Sequence

from core.context.reconcile import SYNTHETIC_INTERRUPTED_ERROR

BYTES_PER_TOKEN: int = 4
MINIMUM_OUTPUT_ROOM: int = 1024
SUMMARIZATION_TOOL_NAME: str = "execute_task_and_return_summary"


class BodyPairType(str, Enum):
    REQUEST_RESPONSE = "request-response"
    COMPLETION = "completion"
    SUMMARIZATION = "summarization"


def calculate_message_size(msg: Dict[str, Any]) -> int:
    """Measure message size in UTF-8 bytes (content + tool_calls + tool metadata)."""
    if not isinstance(msg, dict):
        return len(str(msg).encode("utf-8"))
    size = len(str(msg.get("content") or "").encode("utf-8"))
    if msg.get("tool_call_id"):
        size += len(str(msg["tool_call_id"]).encode("utf-8"))
    if msg.get("name"):
        size += len(str(msg["name"]).encode("utf-8"))
    tool_calls = msg.get("tool_calls") or msg.get("toolCalls") or []
    for tc in tool_calls:
        if not isinstance(tc, dict):
            continue
        size += len(str(tc.get("id") or "").encode("utf-8"))
        size += len(str(tc.get("type") or "").encode("utf-8"))
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
        size += len(str(fn.get("name") or "").encode("utf-8"))
        args = fn.get("arguments") or fn.get("args") or ""
        if not isinstance(args, str):
            args = json.dumps(args, default=str)
        size += len(args.encode("utf-8"))
    return size


def estimate_input_tokens(messages: Sequence[Dict[str, Any]]) -> int:
    """Estimate total input tokens across ``messages`` (~4 bytes/token)."""
    total_bytes = sum(calculate_message_size(m) for m in messages)
    return total_bytes // BYTES_PER_TOKEN


def estimate_tool_tokens(tools: Optional[Sequence[Any]]) -> int:
    """Estimate input tokens consumed by attached JSON tool schemas."""
    if not tools:
        return 0
    try:
        raw = json.dumps(list(tools), default=str).encode("utf-8")
    except (TypeError, ValueError):
        return 0
    return len(raw) // BYTES_PER_TOKEN


def chain_byte_budget(window: int, tools: Optional[Sequence[Any]] = None) -> int:
    """Compute available UTF-8 byte budget for a message chain inside ``window``.

    Reserves ``MINIMUM_OUTPUT_ROOM`` tokens for the answer and subtracts the
    token cost of attached ``tools`` schemas first. Returns ``0`` if the window
    cannot fit output room + tools.
    """
    if not window or window <= 0:
        return 0
    room = int(window) - MINIMUM_OUTPUT_ROOM - estimate_tool_tokens(tools)
    if room <= 0:
        return 0
    return room * BYTES_PER_TOKEN


def chain_fits_window(
    messages: Sequence[Dict[str, Any]],
    tools: Optional[Sequence[Any]],
    window: int,
) -> bool:
    """Return True if ``messages`` + ``tools`` fit within ``window`` leaving output room."""
    if not window or window <= 0:
        return True
    return (
        estimate_input_tokens(messages) + estimate_tool_tokens(tools)
        <= int(window) - MINIMUM_OUTPUT_ROOM
    )


@dataclass
class Header:
    """Opening system and/or human message for a ``ChainSection``."""

    system_message: Optional[Dict[str, Any]] = None
    human_message: Optional[Dict[str, Any]] = None

    @property
    def size_bytes(self) -> int:
        total = 0
        if self.system_message is not None:
            total += calculate_message_size(self.system_message)
        if self.human_message is not None:
            total += calculate_message_size(self.human_message)
        return total

    def to_messages(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if self.system_message is not None:
            out.append(copy.deepcopy(self.system_message))
        if self.human_message is not None:
            out.append(copy.deepcopy(self.human_message))
        return out


@dataclass
class BodyPair:
    """One assistant message paired with all of its corresponding ``role='tool'`` results."""

    pair_type: BodyPairType
    ai_message: Dict[str, Any]
    tool_messages: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def size_bytes(self) -> int:
        total = calculate_message_size(self.ai_message)
        for tm in self.tool_messages:
            total += calculate_message_size(tm)
        return total

    def tool_call_ids(self) -> List[str]:
        tcs = self.ai_message.get("tool_calls") or self.ai_message.get("toolCalls") or []
        return [str(tc.get("id") or "") for tc in tcs if isinstance(tc, dict)]

    def pending_tool_call_ids(self) -> List[str]:
        answered = {
            str(tm.get("tool_call_id") or tm.get("toolCallID") or "")
            for tm in self.tool_messages
        }
        return [tid for tid in self.tool_call_ids() if tid not in answered]

    def is_valid(self) -> bool:
        if self.pair_type == BodyPairType.COMPLETION:
            return len(self.tool_messages) == 0
        if self.pair_type in (BodyPairType.REQUEST_RESPONSE, BodyPairType.SUMMARIZATION):
            return len(self.tool_messages) > 0 and len(self.pending_tool_call_ids()) == 0
        return False

    def to_messages(self) -> List[Dict[str, Any]]:
        out = [copy.deepcopy(self.ai_message)]
        for tm in self.tool_messages:
            out.append(copy.deepcopy(tm))
        return out


@dataclass
class ChainSection:
    """One user/system header followed by zero or more assistant+tool ``BodyPair``s."""

    header: Header
    body: List[BodyPair] = field(default_factory=list)

    @property
    def size_bytes(self) -> int:
        return self.header.size_bytes + sum(p.size_bytes for p in self.body)

    def to_messages(self) -> List[Dict[str, Any]]:
        out = self.header.to_messages()
        for pair in self.body:
            out.extend(pair.to_messages())
        return out


def _classify_ai_message(ai_msg: Dict[str, Any]) -> BodyPairType:
    tcs = ai_msg.get("tool_calls") or ai_msg.get("toolCalls") or []
    for tc in tcs:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
        if fn.get("name") == SUMMARIZATION_TOOL_NAME:
            return BodyPairType.SUMMARIZATION
        return BodyPairType.REQUEST_RESPONSE
    return BodyPairType.COMPLETION


@dataclass
class ChainAST:
    """AST over a conversation message chain preserving tool-call/result pairs."""

    sections: List[ChainSection] = field(default_factory=list)

    @property
    def size_bytes(self) -> int:
        return sum(sec.size_bytes for sec in self.sections)

    def to_messages(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for sec in self.sections:
            out.extend(sec.to_messages())
        return out

    @classmethod
    def from_messages(
        cls,
        messages: Sequence[Dict[str, Any]],
        *,
        force: bool = True,
    ) -> "ChainAST":
        """Parse a flat message list into a validated ``ChainAST``.

        When ``force=True``, repairs dangling tool calls with synthetic error
        tool results and merges consecutive user headers rather than raising.
        """
        ast = cls()
        if not messages:
            return ast

        current_section: Optional[ChainSection] = None
        current_pair: Optional[BodyPair] = None

        def _finalize_pending_tools() -> None:
            if current_pair is None or current_pair.pair_type == BodyPairType.COMPLETION:
                return
            pending = current_pair.pending_tool_call_ids()
            if not pending:
                return
            if not force:
                raise ValueError(f"tool calls with IDs {pending} have no response")
            tcs = current_pair.ai_message.get("tool_calls") or current_pair.ai_message.get("toolCalls") or []
            name_by_id = {}
            for tc in tcs:
                if isinstance(tc, dict):
                    fn = tc.get("function") if isinstance(tc.get("function"), dict) else tc
                    name_by_id[str(tc.get("id") or "")] = str(fn.get("name") or "")
            for tid in pending:
                synth: Dict[str, Any] = {
                    "role": "tool",
                    "tool_call_id": tid,
                    "content": SYNTHETIC_INTERRUPTED_ERROR,
                }
                if name_by_id.get(tid):
                    synth["name"] = name_by_id[tid]
                current_pair.tool_messages.append(synth)

        for raw in messages:
            if not isinstance(raw, dict):
                continue
            msg = copy.deepcopy(raw)
            role = str(msg.get("role") or "user").lower()

            if role == "system":
                if current_section is not None:
                    if not force:
                        raise ValueError("unexpected system message in the middle of a chain")
                    # Never promote mid-chain messages into system authority;
                    # append as user passive note instead.
                    _finalize_pending_tools()
                    current_pair = None
                    current_section = ChainSection(
                        header=Header(human_message={"role": "user", "content": str(msg.get("content") or "")})
                    )
                    ast.sections.append(current_section)
                    continue
                current_section = ChainSection(header=Header(system_message=msg))
                ast.sections.append(current_section)
                current_pair = None

            elif role in ("user", "human"):
                msg["role"] = "user"
                if current_section is None:
                    current_section = ChainSection(header=Header(human_message=msg))
                    ast.sections.append(current_section)
                    current_pair = None
                elif current_section.header.human_message is None and len(current_section.body) == 0:
                    current_section.header.human_message = msg
                elif len(current_section.body) == 0:
                    if not force:
                        raise ValueError("consecutive user messages without assistant turn")
                    prev_text = str(current_section.header.human_message.get("content") or "")
                    next_text = str(msg.get("content") or "")
                    current_section.header.human_message["content"] = (
                        f"{prev_text}\n\n{next_text}".strip()
                    )
                else:
                    _finalize_pending_tools()
                    current_section = ChainSection(header=Header(human_message=msg))
                    ast.sections.append(current_section)
                    current_pair = None

            elif role in ("assistant", "ai", "model"):
                msg["role"] = "assistant"
                if current_section is None:
                    if not force:
                        raise ValueError("unexpected assistant message without preceding header")
                    current_section = ChainSection(header=Header())
                    ast.sections.append(current_section)
                _finalize_pending_tools()
                pair = BodyPair(pair_type=_classify_ai_message(msg), ai_message=msg)
                current_section.body.append(pair)
                current_pair = pair

            elif role == "tool":
                if current_pair is None or current_pair.pair_type == BodyPairType.COMPLETION:
                    if not force:
                        raise ValueError("unexpected tool message without preceding assistant tool call")
                    continue
                current_pair.tool_messages.append(msg)

            else:
                if not force:
                    raise ValueError(f"unexpected message role: {role}")
                _finalize_pending_tools()
                current_section = ChainSection(
                    header=Header(human_message={"role": "user", "content": str(msg.get("content") or "")})
                )
                ast.sections.append(current_section)
                current_pair = None

        _finalize_pending_tools()
        return ast


__all__ = [
    "BYTES_PER_TOKEN",
    "BodyPair",
    "BodyPairType",
    "ChainAST",
    "ChainSection",
    "Header",
    "MINIMUM_OUTPUT_ROOM",
    "SUMMARIZATION_TOOL_NAME",
    "calculate_message_size",
    "chain_byte_budget",
    "chain_fits_window",
    "estimate_input_tokens",
    "estimate_tool_tokens",
]
