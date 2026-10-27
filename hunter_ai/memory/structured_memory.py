"""
HunterAI Structured Memory
==========================

تقسيم الذاكرة لوحدات وظيفية بدلًا من سجل مسطح واحد، لمنع النسيان والتشتت
في المهام الطويلة. مستوحى من إطار MAM-PT (أبحاث 2025-2026).

الوحدات الثلاث:
1. ذاكرة عاملة (Working Memory): حالة المهمة الحالية، السياق الفوري.
2. ذاكرة دلالية (Semantic Memory): المعرفة العامة (CWE، تقنيات ATT&CK، ثغرات معروفة).
3. ذاكرة عرضية للفشل (Failure Episodic Memory): الدروس المستفادة من الفشل السابق
   لتجنب تكرار المحاولات الفاشلة.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum


class MemoryType(str, Enum):  # type: ignore[misc, valid-type]
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
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    access_count: int = 0
    ttl_seconds: Optional[int] = None  # None = دائمة

    def is_expired(self) -> bool:
        if self.ttl_seconds is None:
            return False
        return (time.time() - self.created_at) > self.ttl_seconds

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["memory_type"] = self.memory_type.value
        return d


class StructuredMemory:
    """
    ذاكرة منظمة تقسم الذكريات إلى ثلاث وحدات وظيفية مع دعم TTL
    واسترجاع ذكي بناءً على النوع والهدف.
    """

    def __init__(self, root_dir: str = "memory/structured"):
        self.root_dir = Path(root_dir)
        self.working_dir = self.root_dir / "working"
        self.semantic_dir = self.root_dir / "semantic"
        self.failure_dir = self.root_dir / "failure_episodic"
        for d in [self.working_dir, self.semantic_dir, self.failure_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self._index_path = self.root_dir / "index.json"
        self._index: Dict[str, Dict[str, str]] = {
            "working": {},
            "semantic": {},
            "failure_episodic": {},
        }
        self._load_index()

    def _load_index(self) -> None:
        if self._index_path.exists():
            try:
                with open(self._index_path, "r", encoding="utf-8") as f:
                    self._index = json.load(f)
            except Exception:
                pass

    def _save_index(self) -> None:
        try:
            with open(self._index_path, "w", encoding="utf-8") as f:
                json.dump(self._index, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _dir_for(self, mem_type: MemoryType) -> Path:
        return {
            MemoryType.WORKING: self.working_dir,
            MemoryType.SEMANTIC: self.semantic_dir,
            MemoryType.FAILURE_EPISODIC: self.failure_dir,
        }[mem_type]

    def _sanitize_key(self, key: str) -> str:
        """تنظيف المفتاح ليكون صالحاً كاسم ملف على جميع الأنظمة."""
        invalid_chars = '<>:"/\\|?*'
        for ch in invalid_chars:
            key = key.replace(ch, "_")
        return key

    def write(
        self,
        memory_type: MemoryType,
        target: str,
        key: str,
        value: Any,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """كتابة إدخال ذاكرة جديد أو تحديث إدخال موجود."""
        entry_id = str(uuid.uuid4())[:8]
        entry = MemoryEntry(
            entry_id=entry_id,
            memory_type=memory_type,
            target=target,
            key=key,
            value=value,
            ttl_seconds=ttl_seconds,
        )
        mem_dir = self._dir_for(memory_type)
        target_dir = mem_dir / target.replace("://", "_").replace("/", "_")
        target_dir.mkdir(parents=True, exist_ok=True)
        safe_key = self._sanitize_key(key)
        entry_path = target_dir / f"{safe_key}.json"
        with open(entry_path, "w", encoding="utf-8") as f:
            json.dump(entry.to_dict(), f, indent=2, ensure_ascii=False)

        self._index[memory_type.value][f"{target}:{key}"] = str(entry_path)
        self._save_index()
        return entry_id

    def read(
        self,
        memory_type: MemoryType,
        target: str,
        key: str,
    ) -> Optional[MemoryEntry]:
        """قراءة إدخال ذاكرة."""
        path_str = self._index[memory_type.value].get(f"{target}:{key}")
        if not path_str:
            return None
        path = Path(path_str)
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            entry = MemoryEntry(
                entry_id=data["entry_id"],
                memory_type=MemoryType(data["memory_type"]),
                target=data["target"],
                key=data["key"],
                value=data["value"],
                created_at=data.get("created_at", time.time()),
                updated_at=data.get("updated_at", time.time()),
                access_count=data.get("access_count", 0) + 1,
                ttl_seconds=data.get("ttl_seconds"),
            )
            # تداداد عداد الوصول
            data["access_count"] = entry.access_count
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return entry
        except Exception:
            return None

    def list_keys(
        self,
        memory_type: MemoryType,
        target: Optional[str] = None,
    ) -> List[str]:
        """قائمة المفاتيح لنوع ذاكرة معين، مع فلترة اختيارية حسب الهدف."""
        keys = []
        for composite, path_str in self._index[memory_type.value].items():
            if target is None or composite.startswith(f"{target}:"):
                key = composite.split(":", 1)[1] if ":" in composite else composite
                keys.append(key)
        return keys

    def record_failure(
        self,
        target: str,
        technique: str,
        reason: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> str:
        """تسجيل فشل في ذاكرة الفشل العرضية لتجنبه مستقبلاً."""
        key = f"fail:{technique}"
        value = {
            "technique": technique,
            "reason": reason,
            "evidence": evidence or {},
            "recorded_at": time.time(),
        }
        return self.write(
            MemoryType.FAILURE_EPISODIC,
            target,
            key,
            value,
            ttl_seconds=None,  # دائمة — لا نريد نسيان الفشل
        )

    def has_failure(
        self,
        target: str,
        technique: str,
    ) -> bool:
        """التحقق مما إذا كانت تقنية معينة قد فشلت سابقًا لهذا الهدف."""
        entry = self.read(MemoryType.FAILURE_EPISODIC, target, f"fail:{technique}")
        return entry is not None

    def get_failures(self, target: str) -> List[MemoryEntry]:
        """استرجاع كل الفشل المسجل لهدف معين."""
        failures = []
        for key in self.list_keys(MemoryType.FAILURE_EPISODIC, target):
            entry = self.read(MemoryType.FAILURE_EPISODIC, target, key)
            if entry:
                failures.append(entry)
        return failures

    def clear_working(self, target: Optional[str] = None) -> int:
        """مسح الذاكرة العاملة (للبدء من جديد في مهمة جديدة)."""
        count = 0
        mem_dir = self.working_dir
        if target:
            target_dir = mem_dir / target.replace("://", "_").replace("/", "_")
            if target_dir.exists():
                for f in target_dir.glob("*.json"):
                    f.unlink()
                    count += 1
        else:
            for f in mem_dir.rglob("*.json"):
                f.unlink()
                count += 1
        self._index["working"] = {}
        self._save_index()
        return count

    def stats(self) -> Dict[str, Any]:
        """إحصائيات الذاكرة."""
        return {
            "working_entries": len(self._index["working"]),
            "semantic_entries": len(self._index["semantic"]),
            "failure_entries": len(self._index["failure_episodic"]),
            "total": sum(len(v) for v in self._index.values()),
        }

    # ═══════════════════════════════════════════════════════════════════════════════
    # RAG Integration Methods
    # ═══════════════════════════════════════════════════════════════════════════════

    def store_knowledge(
        self,
        target: str,
        item_id: str,
        title: str,
        content: str,
        source: str,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ttl_seconds: Optional[int] = None,
    ) -> str:
        """
        تخزين عنصر معرفة من محرك RAG في الذاكرة الدلالية.
        يسمح باسترجاع هذه المعرفة لاحقًا عبر RAG.
        """
        from hunter_ai.memory.structured_memory import MemoryType
        value = {
            "item_id": item_id,
            "title": title,
            "content": content,
            "source": source,
            "tags": tags or [],
            "metadata": metadata or {},
            "stored_at": time.time(),
        }
        return self.write(
            MemoryType.SEMANTIC,
            target,
            f"kb:{item_id}",
            value,
            ttl_seconds=ttl_seconds,
        )

    def retrieve_knowledge(
        self,
        target: str,
        query: str,
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        استرجاع معرفة من الذاكرة الدلالية بناءً على استعلام بسيط.
        يستخدم للتشغيل مع محرك RAG.
        """
        from hunter_ai.memory.structured_memory import MemoryType
        results = []
        for key in self.list_keys(MemoryType.SEMANTIC, target):
            entry = self.read(MemoryType.SEMANTIC, target, key)
            if entry and isinstance(entry.value, dict):
                content = entry.value.get("content", "")
                title = entry.value.get("title", "")
                # توافق بسيط بالكلمات المفتاحية
                query_lower = query.lower()
                text = (title + " " + content).lower()
                score = sum(1 for word in query_lower.split() if word in text) / max(len(query_lower.split()), 1)
                if score > 0:
                    results.append({
                        "item_id": entry.value.get("item_id", key),
                        "title": title,
                        "content": content,
                        "source": entry.value.get("source", "structured_memory"),
                        "tags": entry.value.get("tags", []),
                        "score": score,
                        "metadata": entry.value.get("metadata", {}),
                    })
        # ترتيب حسب النقاط
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]

    def get_all_semantic(self, target: str) -> List[Dict[str, Any]]:
        """
        استرجاع جميع عناصر الذاكرة الدلالية لهدف معين.
        يستخدم لفهرسة RAG.
        """
        from hunter_ai.memory.structured_memory import MemoryType
        results = []
        for key in self.list_keys(MemoryType.SEMANTIC, target):
            entry = self.read(MemoryType.SEMANTIC, target, key)
            if entry and isinstance(entry.value, dict):
                results.append(entry.value)
        return results

    def clear_semantic(self, target: Optional[str] = None) -> int:
        """
        مسح الذاكرة الدلالية (لإعادة الفهرسة).
        """
        count = 0
        mem_dir = self.semantic_dir
        if target:
            target_dir = mem_dir / target.replace("://", "_").replace("/", "_")
            if target_dir.exists():
                for f in target_dir.glob("*.json"):
                    f.unlink()
                    count += 1
        else:
            for f in mem_dir.rglob("*.json"):
                f.unlink()
                count += 1
        # إعادة بناء الفهرس للدلالية فقط
        self._index["semantic"] = {}
        self._save_index()
        return count
