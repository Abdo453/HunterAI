"""
ذاكرة ثلاثية الوحدات لـ HunterAI
 Working + Semantic + Failure Episodic
يدعم غير المتزامن (async)، السجلات، والتكوينات المركزية
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config.settings import config
from core.exceptions import MemoryError, HunterAIError
from core.logging.logger import logger


class MemoryType(str, Enum):
    WORKING = "working"
    SEMANTIC = "semantic"
    FAILURE_EPISODIC = "failure_episodic"


@dataclass
class MemoryEntry:
    entry_id: str
    memory_type: MemoryType
    target: str
    key: str
    value: Any
    ttl_seconds: Optional[int] = None
    created_at: float = field(default_factory=time.time)
    accessed_at: float = field(default_factory=time.time)
    access_count: int = 0
    tags: List[str] = field(default_factory=list)

    def is_expired(self) -> bool:
        if self.ttl_seconds is None:
            return False
        return (time.time() - self.created_at) > self.ttl_seconds

    def touch(self) -> None:
        self.accessed_at = time.time()
        self.access_count += 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "memory_type": self.memory_type.value,
            "target": self.target,
            "key": self.key,
            "value": self.value,
            "ttl_seconds": self.ttl_seconds,
            "created_at": self.created_at,
            "accessed_at": self.accessed_at,
            "access_count": self.access_count,
            "tags": self.tags,
        }


class TripleMemory:
    """
    نظام ذاكرة ثلاثي:
    1. Working: سياق المهمة الحالية (TTL قصير)
    2. Semantic: معرفة عامة عن الخدمات والثغرات (TTL طويل أو بدون)
    3. Failure Episodic: تسجيل الفشلات وأسبابها لمنع التكرار
    """

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = Path(storage_path or config.memory.storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._memory: Dict[str, MemoryEntry] = {}
        self._index: Dict[MemoryType, Dict[str, List[str]]] = {
            mt: {} for mt in MemoryType
        }
        self._lock = asyncio.Lock()
        self._load_state()

    def _load_state(self) -> None:
        """تحميل حالة الذاكرة من الملفات."""
        for mt in MemoryType:
            file_path = self.storage_path / f"{mt.value}.jsonl"
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                data = json.loads(line)
                                entry = MemoryEntry(
                                    entry_id=data["entry_id"],
                                    memory_type=MemoryType(data["memory_type"]),
                                    target=data["target"],
                                    key=data["key"],
                                    value=data["value"],
                                    ttl_seconds=data.get("ttl_seconds"),
                                    created_at=data.get("created_at", time.time()),
                                    accessed_at=data.get("accessed_at", time.time()),
                                    access_count=data.get("access_count", 0),
                                    tags=data.get("tags", []),
                                )
                                if not entry.is_expired():
                                    self._memory[entry.entry_id] = entry
                                    self._index[entry.memory_type].setdefault(entry.target, []).append(entry.entry_id)
                            except Exception as e:
                                logger.warning(f"[Memory] فشل تحميل إدخال: {e}")
                    logger.info(f"[Memory] تم تحميل {mt.value} ({len(self._index[mt])} أهداف)")
                except Exception as e:
                    logger.warning(f"[Memory] فشل تحميل ملف {mt.value}: {e}")

    async def _persist_async(self, entry: MemoryEntry) -> None:
        """حفظ إدخال بشكل غير متزامن."""
        file_path = self.storage_path / f"{entry.memory_type.value}_{entry.target}.jsonl"
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._append_jsonl, file_path, entry.to_dict())

    def _append_jsonl(self, file_path: Path, data: Dict[str, Any]) -> None:
        """إضافة سطر إلى ملف JSONL."""
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(data, ensure_ascii=False) + "\n")

    async def write_async(
        self,
        memory_type: MemoryType,
        target: str,
        key: str,
        value: Any,
        ttl_seconds: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """كتابة إدخال بشكل غير متزامن."""
        async with self._lock:
            return self._write_sync(memory_type, target, key, value, ttl_seconds, tags)

    def write(
        self,
        memory_type: MemoryType,
        target: str,
        key: str,
        value: Any,
        ttl_seconds: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        """كتابة إدخال بشكل متزامن."""
        return self._write_sync(memory_type, target, key, value, ttl_seconds, tags)

    def _write_sync(
        self,
        memory_type: MemoryType,
        target: str,
        key: str,
        value: Any,
        ttl_seconds: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        entry_id = f"{memory_type.value}-{uuid.uuid4().hex[:8]}"
        entry = MemoryEntry(
            entry_id=entry_id,
            memory_type=memory_type,
            target=target,
            key=key,
            value=value,
            ttl_seconds=ttl_seconds,
            tags=tags or [],
        )
        self._memory[entry_id] = entry
        self._index[memory_type].setdefault(target, []).append(entry_id)
        logger.debug(f"[Memory] كتب إدخال '{entry_id}' إلى {memory_type.value} للهدف {target}")
        return entry_id

    async def read_async(
        self,
        memory_type: MemoryType,
        target: str,
        key: str,
    ) -> Optional[MemoryEntry]:
        """قراءة إدخال بشكل غير متزامن."""
        async with self._lock:
            return self._read_sync(memory_type, target, key)

    def read(
        self,
        memory_type: MemoryType,
        target: str,
        key: str,
    ) -> Optional[MemoryEntry]:
        """قراءة إدخال بشكل متزامن."""
        return self._read_sync(memory_type, target, key)

    def _read_sync(
        self,
        memory_type: MemoryType,
        target: str,
        key: str,
    ) -> Optional[MemoryEntry]:
        candidates = self._index.get(memory_type, {}).get(target, [])
        for entry_id in candidates:
            entry = self._memory.get(entry_id)
            if entry and entry.key == key and not entry.is_expired():
                entry.touch()
                logger.debug(f"[Memory] قرأ إدخال '{entry_id}' من {memory_type.value} للهدف {target}")
                return entry
        return None

    async def read_all_by_target_async(
        self,
        memory_type: MemoryType,
        target: str,
    ) -> List[MemoryEntry]:
        """قراءة جميع entradas لنوع ذاكرة وهدف معين بشكل غير متزامن."""
        async with self._lock:
            return self._read_all_by_target_sync(memory_type, target)

    def read_all_by_target(
        self,
        memory_type: MemoryType,
        target: str,
    ) -> List[MemoryEntry]:
        """قراءة جميع entradas لنوع ذاكرة وهدف معين بشكل متزامن."""
        return self._read_all_by_target_sync(memory_type, target)

    def _read_all_by_target_sync(
        self,
        memory_type: MemoryType,
        target: str,
    ) -> List[MemoryEntry]:
        results = []
        for entry_id in self._index.get(memory_type, {}).get(target, []):
            entry = self._memory.get(entry_id)
            if entry and not entry.is_expired():
                entry.touch()
                results.append(entry)
        return results

    def record_failure(
        self,
        target: str,
        technique: str,
        reason: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """تسجيل فشل في الذاكرة العرضية لمنع تكراره."""
        value = {
            "technique": technique,
            "reason": reason,
            "context": context or {},
            "timestamp": time.time(),
        }
        entry_id = self.write(
            MemoryType.FAILURE_EPISODIC,
            target,
            f"failure-{technique}-{int(time.time())}",
            value,
            ttl_seconds=config.memory.failure_ttl_seconds,
            tags=["failure", technique],
        )
        logger.warning(f"[Memory] سجل فشل: الهدف={target}, التقنية={technique}, السبب={reason}")
        return entry_id

    def has_recent_failure(
        self,
        target: str,
        technique: str,
        within_seconds: int = 3600,
    ) -> bool:
        """التحقق مما إذا كانت نفس التقنية فشلت مؤخراً لهذا الهدف."""
        failures = self.read_all_by_target(MemoryType.FAILURE_EPISODIC, target)
        now = time.time()
        for f in failures:
            if f.value.get("technique") == technique:
                if (now - f.created_at) <= within_seconds:
                    return True
        return False

    def write_semantic(
        self,
        target: str,
        key: str,
        value: Any,
        tags: Optional[List[str]] = None,
    ) -> str:
        """كتابة معرفة دلالية عامة."""
        return self.write(
            MemoryType.SEMANTIC,
            target,
            key,
            value,
            ttl_seconds=None,
            tags=tags or [],
        )

    def write_working(
        self,
        target: str,
        key: str,
        value: Any,
        ttl_seconds: int = 600,
        tags: Optional[List[str]] = None,
    ) -> str:
        """كتابة إلى الذاكرة العاملة."""
        return self.write(
            MemoryType.WORKING,
            target,
            key,
            value,
            ttl_seconds=ttl_seconds,
            tags=tags or [],
        )

    def cleanup_expired(self) -> int:
        """تنظيف الإدخالات المنتهية الصلاحية."""
        expired = [
            eid for eid, e in self._memory.items() if e.is_expired()
        ]
        for eid in expired:
            entry = self._memory.pop(eid)
            target_entries = self._index.get(entry.memory_type, {}).get(entry.target, [])
            if eid in target_entries:
                target_entries.remove(eid)
        logger.info(f"[Memory] تم تنظيف {len(expired)} إدخال منتهي الصلاحية")
        return len(expired)

    def stats(self) -> Dict[str, Any]:
        """إرجاع إحصائيات الذاكرة."""
        return {
            "total_entries": len(self._memory),
            "by_type": {
                mt.value: len([e for e in self._memory.values() if e.memory_type == mt])
                for mt in MemoryType
            },
        }
