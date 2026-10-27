"""Append-only evidence chain for detector findings.

Each record stores the hash of the previous record, so deleting or editing an
entry in the middle breaks :meth:`EvidenceChain.verify`.  The chain is
tamper-evident, not secret: it proves *what* was recorded and *in which order*,
and it makes silent edits visible.

Records are JSON lines on disk::

    {"seq": 1, "kind": "exchange", "payload_hash": "...", "prev_hash": "00..",
     "record_hash": "...", "timestamp": 1793...}
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.detectors.contract import Detection, ProbeExchange, sha256_json

GENESIS_HASH = "0" * 64


@dataclass
class ChainRecord:
    seq: int
    kind: str
    payload_hash: str
    prev_hash: str
    record_hash: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChainRecord":
        return cls(
            seq=int(data["seq"]),
            kind=str(data["kind"]),
            payload_hash=str(data["payload_hash"]),
            prev_hash=str(data["prev_hash"]),
            record_hash=str(data["record_hash"]),
            timestamp=float(data["timestamp"]),
        )


class EvidenceChain:
    """Hash-linked list of exchanges and detections."""

    def __init__(self, path: Optional[str] = None):
        self._path = Path(path) if path else None
        self._records: List[ChainRecord] = []
        self._last_hash = GENESIS_HASH
        if self._path and self._path.exists():
            for line in self._path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    record = ChainRecord.from_dict(json.loads(line))
                    self._records.append(record)
                    self._last_hash = record.record_hash

    @property
    def records(self) -> List[ChainRecord]:
        return list(self._records)

    def append(self, kind: str, payload: Any) -> ChainRecord:
        payload_hash = sha256_json(payload)
        body = {
            "seq": len(self._records) + 1,
            "kind": str(kind),
            "payload_hash": payload_hash,
            "prev_hash": self._last_hash,
            "timestamp": time.time(),
        }
        record = ChainRecord(record_hash=sha256_json(body), **body)
        self._records.append(record)
        self._last_hash = record.record_hash
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
        return record

    def append_exchange(self, exchange: ProbeExchange) -> ChainRecord:
        return self.append(
            "exchange",
            {
                "method": exchange.probe.method,
                "url": exchange.probe.url,
                "status_code": exchange.status_code,
                "request_hash": exchange.request_hash,
                "response_hash": exchange.response_hash,
                "truncated": exchange.truncated,
                "timestamp": exchange.timestamp,
            },
        )

    def append_detection(self, detection: Detection) -> ChainRecord:
        return self.append(
            "detection",
            {
                "detector": detection.detector,
                "vuln_class": detection.vuln_class,
                "confirmed": detection.confirmed,
                "confidence": detection.confidence,
                "reason": detection.reason,
                "finding_id": detection.finding.id if detection.finding else None,
                "exchanges": [
                    {
                        "request_hash": exchange.request_hash,
                        "response_hash": exchange.response_hash,
                    }
                    for exchange in detection.exchanges
                ],
            },
        )

    def append_all(self, detection: Detection) -> None:
        for exchange in detection.exchanges:
            self.append_exchange(exchange)
        self.append_detection(detection)

    def verify(self) -> bool:
        previous = GENESIS_HASH
        for expected_seq, record in enumerate(self._records, start=1):
            if record.seq != expected_seq:
                return False
            if record.prev_hash != previous:
                return False
            body = {
                "seq": record.seq,
                "kind": record.kind,
                "payload_hash": record.payload_hash,
                "prev_hash": record.prev_hash,
                "timestamp": record.timestamp,
            }
            if sha256_json(body) != record.record_hash:
                return False
            previous = record.record_hash
        return True

    def save(self, path: Optional[str] = None) -> str:
        target = Path(path) if path else self._path
        if target is None:
            raise ValueError("no path supplied for save()")
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("w", encoding="utf-8", newline="\n") as handle:
            for record in self._records:
                handle.write(json.dumps(record.to_dict(), sort_keys=True) + "\n")
        return str(target)

    @classmethod
    def load(cls, path: str) -> "EvidenceChain":
        return cls(path=path)
