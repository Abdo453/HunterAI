"""Shared, persistent, tamper-evident memory shared by the whole agent tree.

Every agent in the hierarchy reads and writes the same store, so a lead found
by the recon worker is immediately visible to the validator and the reporter.
Records are append-only and hash-chained: editing or removing an entry breaks
:func:`SharedMemory.verify_chain`.

Secrets are redacted before they reach the store -- the memory is a hunting
log, not a vault.  Operator-supplied test credentials are referenced by label
only; the value itself never lands on disk here.

Python 3.11, standard library only.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = ["Namespace", "SharedMemory", "redact_secrets"]


class Namespace(str, Enum):
    """Memory partitions; each key maps to the newest value in its namespace."""

    LEAD = "lead"
    SESSION = "session"
    EVIDENCE = "evidence"
    ATTACK_PATH = "attack_path"
    CREDENTIAL_FINDING = "credential_finding"
    ACCESS_PATH = "access_path"
    NOTE = "note"
    EVENT = "event"


_SECRET_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.S,
        ),
        "<redacted:private-key>",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<redacted:aws-key-id>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,255}\b"), "<redacted:github-token>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<redacted:slack-token>"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "<redacted:jwt>",
    ),
    (
        re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-]{20,}"),
        "<redacted:bearer-token>",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|token|client_secret)\s*[=:]\s*\S{6,}"
        ),
        r"\1=<redacted>",
    ),
)


def redact_secrets(value: Any) -> Any:
    """Recursively redact credential-shaped substrings from a value."""
    if isinstance(value, str):
        redacted = value
        for pattern, replacement in _SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted
    if isinstance(value, dict):
        return {key: redact_secrets(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_secrets(item) for item in value]
    return value


class SharedMemory:
    """Append-only, hash-chained key/value store shared across agents."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path else None
        self._records: List[Dict[str, Any]] = []
        self._latest: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._last_hash = "0" * 64
        self._seq = 0
        if self.path and self.path.exists():
            self._load()

    # -- internals ---------------------------------------------------------
    def _load(self) -> None:
        assert self.path is not None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            self._records.append(record)
            self._seq = max(self._seq, int(record.get("seq", 0)))
            self._last_hash = str(record.get("hash", self._last_hash))
            namespace = str(record.get("namespace", ""))
            key = str(record.get("key", ""))
            if namespace and key:
                self._latest[(namespace, key)] = record

    def _persist(self, record: Dict[str, Any]) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")

    def _append(
        self,
        namespace: str,
        key: str,
        value: Any,
        agent_id: str,
        tags: Iterable[str],
    ) -> Dict[str, Any]:
        self._seq += 1
        body: Dict[str, Any] = {
            "seq": self._seq,
            "ts": time.time(),
            "namespace": namespace,
            "key": key,
            "value": redact_secrets(value),
            "agent_id": agent_id,
            "tags": sorted(set(tags)),
            "prev_hash": self._last_hash,
        }
        blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        record = dict(body)
        record["hash"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        self._records.append(record)
        self._last_hash = record["hash"]
        self._latest[(namespace, key)] = record
        self._persist(record)
        return record

    # -- writes ------------------------------------------------------------
    def write(
        self,
        namespace: Namespace | str,
        key: str,
        value: Any,
        *,
        agent_id: str = "root",
        tags: Iterable[str] = (),
    ) -> Dict[str, Any]:
        """Upsert ``key`` inside ``namespace``; the newest write wins."""
        ns = namespace.value if isinstance(namespace, Namespace) else str(namespace)
        return self._append(ns, str(key), value, agent_id, tags)

    def record_event(
        self, kind: str, payload: Any, *, agent_id: str = "root"
    ) -> Dict[str, Any]:
        """Append an immutable event (decisions, tool calls, state changes)."""
        return self._append(
            Namespace.EVENT.value,
            str(kind),
            payload,
            agent_id,
            tags=("event", str(kind)),
        )

    # -- reads -------------------------------------------------------------
    def read(self, namespace: Namespace | str, key: str) -> Any:
        ns = namespace.value if isinstance(namespace, Namespace) else str(namespace)
        record = self._latest.get((ns, str(key)))
        return None if record is None else record.get("value")

    def latest(self, namespace: Namespace | str) -> Dict[str, Any]:
        ns = namespace.value if isinstance(namespace, Namespace) else str(namespace)
        return {
            key: record.get("value")
            for (record_ns, key), record in self._latest.items()
            if record_ns == ns
        }

    def history(self, namespace: Namespace | str | None = None) -> List[Dict[str, Any]]:
        if namespace is None:
            return list(self._records)
        ns = namespace.value if isinstance(namespace, Namespace) else str(namespace)
        return [r for r in self._records if r.get("namespace") == ns]

    def search(
        self,
        query: str,
        namespaces: Optional[Iterable[Namespace | str]] = None,
        *,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Substring search across keys, values, and tags."""
        needle = str(query).lower()
        allowed = None
        if namespaces is not None:
            allowed = {
                ns.value if isinstance(ns, Namespace) else str(ns) for ns in namespaces
            }
        hits: List[Dict[str, Any]] = []
        for (ns, key), record in self._latest.items():
            if allowed is not None and ns not in allowed:
                continue
            haystack = json.dumps(
                {"key": key, "value": record.get("value"), "tags": record.get("tags")},
                ensure_ascii=False,
            ).lower()
            if needle in haystack:
                hits.append(
                    {
                        "namespace": ns,
                        "key": key,
                        "value": record.get("value"),
                        "agent_id": record.get("agent_id"),
                        "ts": record.get("ts"),
                    }
                )
        hits.sort(key=lambda item: float(item.get("ts") or 0.0), reverse=True)
        return hits[:limit]

    # -- integrity / stats -------------------------------------------------
    def verify_chain(self) -> bool:
        previous = "0" * 64
        for record in self._records:
            if record.get("prev_hash") != previous:
                return False
            body = {k: v for k, v in record.items() if k != "hash"}
            blob = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            if hashlib.sha256(blob.encode("utf-8")).hexdigest() != record.get("hash"):
                return False
            previous = str(record["hash"])
        return True

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for (ns, key), record in self._latest.items():
            out.setdefault(ns, {})[key] = record.get("value")
        return out

    def stats(self) -> Dict[str, Any]:
        by_namespace: Dict[str, int] = {}
        for record in self._records:
            ns = str(record.get("namespace", "unknown"))
            by_namespace[ns] = by_namespace.get(ns, 0) + 1
        return {
            "records": len(self._records),
            "keys": len(self._latest),
            "by_namespace": by_namespace,
            "chain_valid": self.verify_chain(),
            "path": str(self.path) if self.path else None,
        }
