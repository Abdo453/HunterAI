"""
╔══════════════════════════════════════════════════════════════════════════╗
║        WORLD ELITE VECTOR MEMORY — Semantic Agent Memory                ║
║                                                                          ║
║  مستوحى من:                                                              ║
║  • XBOW          → Persistent context across findings                   ║
║  • NSA CYBERCOM  → Classified intelligence correlation                  ║
║  • GRU Sandworm  → Long-term campaign memory                            ║
║  • Lazarus Group → Cross-campaign TTPs reuse                            ║
║                                                                          ║
║  للأغراض التعليمية فقط — على أهداف مصرح بها                             ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# MEMORY ENTRY
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MemoryEntry:
    """
    وحدة ذاكرة واحدة — تخزن observation أو finding مع metadata.
    """
    id: str
    content: str
    category: str           # "finding", "observation", "technique", "asset"
    target: str
    timestamp: float = field(default_factory=time.time)
    tags: List[str] = field(default_factory=list)
    importance: float = 0.5  # 0.0 → 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[List[float]] = None   # vector للبحث الدلالي

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "content": self.content[:500],
            "category": self.category,
            "target": self.target,
            "timestamp": self.timestamp,
            "tags": self.tags,
            "importance": self.importance,
            "metadata": self.metadata,
        }


# ─────────────────────────────────────────────────────────────────────────────
# VECTOR MEMORY ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class WorldEliteVectorMemory:
    """
    ذاكرة Agent دلالية (Semantic Memory).
    
    الميزات:
    1. تخزين كل observation مع embedding
    2. بحث دلالي (similarity search) في الذاكرة
    3. ذاكرة طويلة الأمد مستمرة (SQLite + JSON)
    4. تلخيص تلقائي عند امتلاء الذاكرة
    5. ربط findings عبر جلسات متعددة
    
    مستخدم: ChromaDB (إذا متاح) أو FAISS أو fallback لـ keyword search.
    """

    def __init__(
        self,
        storage_dir: str = "data/agent_memory",
        max_entries: int = 10_000,
        use_vector_db: bool = True,
    ):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.max_entries = max_entries
        self._entries: Dict[str, MemoryEntry] = {}
        self._vector_db = None
        self._embedding_model = None

        # محاولة تحميل ChromaDB
        if use_vector_db:
            self._init_vector_db()

        # تحميل الذاكرة المحفوظة
        self._load_from_disk()

    def _init_vector_db(self):
        """يحاول تهيئة ChromaDB للبحث الدلالي"""
        try:
            import chromadb
            client = chromadb.PersistentClient(path=str(self.storage_dir / "chroma"))
            self._vector_db = client.get_or_create_collection(
                name="agent_memory",
                metadata={"hnsw:space": "cosine"},
            )
            logger.info("✅ ChromaDB initialized — semantic search enabled")
        except ImportError:
            logger.warning("⚠️  chromadb not installed — using keyword search fallback")
            self._vector_db = None
        except Exception as exc:
            logger.warning("⚠️  ChromaDB init failed: %s — using fallback", exc)
            self._vector_db = None

    # ── Core Operations ───────────────────────────────────────────────────────

    def remember(
        self,
        content: str,
        category: str,
        target: str,
        tags: Optional[List[str]] = None,
        importance: float = 0.5,
        metadata: Optional[Dict] = None,
    ) -> MemoryEntry:
        """
        يحفظ observation أو finding في الذاكرة.
        
        مستوحى من XBOW: كل نتيجة تُحفظ فوراً للبحث لاحقاً.
        """
        entry_id = hashlib.sha256(
            f"{content}{target}{time.time()}".encode()
        ).hexdigest()[:16]

        entry = MemoryEntry(
            id=entry_id,
            content=content,
            category=category,
            target=target,
            tags=tags or [],
            importance=importance,
            metadata=metadata or {},
        )

        self._entries[entry_id] = entry

        # حفظ في ChromaDB إذا متاح
        if self._vector_db is not None:
            try:
                self._vector_db.upsert(
                    ids=[entry_id],
                    documents=[content],
                    metadatas=[{
                        "category": category,
                        "target": target,
                        "importance": str(importance),
                        "tags": ",".join(tags or []),
                    }],
                )
            except Exception as exc:
                logger.debug("ChromaDB upsert failed: %s", exc)

        # تنظيف إذا امتلأت الذاكرة
        if len(self._entries) > self.max_entries:
            self._evict_low_importance()

        self._save_to_disk()
        return entry

    def recall(
        self,
        query: str,
        n: int = 5,
        category: Optional[str] = None,
        target: Optional[str] = None,
        min_importance: float = 0.0,
    ) -> List[MemoryEntry]:
        """
        يبحث في الذاكرة ويرجع أكثر الـ entries صلة بالـ query.
        
        يستخدم semantic search إذا ChromaDB متاح،
        وإلا keyword search.
        """
        if self._vector_db is not None:
            return self._semantic_recall(query, n, category, target)
        else:
            return self._keyword_recall(query, n, category, target, min_importance)

    def _semantic_recall(
        self,
        query: str,
        n: int,
        category: Optional[str],
        target: Optional[str],
    ) -> List[MemoryEntry]:
        """بحث دلالي باستخدام ChromaDB"""
        try:
            where: Dict = {}
            if category:
                where["category"] = category
            if target:
                where["target"] = target

            results = self._vector_db.query(
                query_texts=[query],
                n_results=min(n, len(self._entries) or 1),
                where=where if where else None,
            )
            ids = results.get("ids", [[]])[0]
            return [self._entries[i] for i in ids if i in self._entries]
        except Exception as exc:
            logger.debug("Semantic recall failed: %s", exc)
            return self._keyword_recall(query, n, category, target)

    def _keyword_recall(
        self,
        query: str,
        n: int,
        category: Optional[str],
        target: Optional[str],
        min_importance: float = 0.0,
    ) -> List[MemoryEntry]:
        """بحث بالكلمات المفتاحية — fallback"""
        query_lower = query.lower()
        keywords = query_lower.split()

        scored = []
        for entry in self._entries.values():
            if category and entry.category != category:
                continue
            if target and entry.target != target:
                continue
            if entry.importance < min_importance:
                continue

            # حساب score بسيط: عدد الكلمات المشتركة
            content_lower = entry.content.lower()
            score = sum(1 for kw in keywords if kw in content_lower)
            score += entry.importance  # مكافأة للأهمية

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:n]]

    # ── Advanced Operations ───────────────────────────────────────────────────

    def get_findings_summary(self, target: str) -> Dict[str, Any]:
        """
        يلخص كل الـ findings لهدف معين.
        مستوحى من GRU: تجميع المعلومات عبر الزمن.
        """
        findings = [
            e for e in self._entries.values()
            if e.category == "finding" and e.target == target
        ]

        by_severity: Dict[str, List] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }

        for f in findings:
            severity = f.metadata.get("severity", "info")
            by_severity.get(severity, by_severity["info"]).append(f.to_dict())

        return {
            "target": target,
            "total_findings": len(findings),
            "by_severity": {k: len(v) for k, v in by_severity.items()},
            "top_critical": by_severity["critical"][:5],
            "top_high": by_severity["high"][:5],
        }

    def get_ttps_used(self, target: str) -> List[str]:
        """
        يرجع قائمة MITRE ATT&CK techniques المستخدمة.
        مستوحى من Lazarus: tracking TTPs عبر campaigns.
        """
        ttps: set = set()
        for entry in self._entries.values():
            if entry.target == target:
                mitre = entry.metadata.get("mitre_technique")
                if mitre:
                    ttps.add(mitre)
        return sorted(ttps)

    def cross_target_correlation(self, pattern: str) -> List[Dict]:
        """
        يبحث عن نفس النمط عبر targets مختلفة.
        مستوحى من VAPOR PANDA: lateral movement patterns.
        """
        related = []
        for entry in self._entries.values():
            if pattern.lower() in entry.content.lower():
                related.append({
                    "target": entry.target,
                    "category": entry.category,
                    "content_snippet": entry.content[:200],
                    "importance": entry.importance,
                })
        return sorted(related, key=lambda x: x["importance"], reverse=True)[:20]

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save_to_disk(self):
        """يحفظ الذاكرة على القرص (JSON)"""
        try:
            mem_file = self.storage_dir / "memory.json"
            data = {
                entry_id: entry.to_dict()
                for entry_id, entry in self._entries.items()
            }
            mem_file.write_text(
                json.dumps(data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:
            logger.error("Memory save failed: %s", exc)

    def _load_from_disk(self):
        """يحمل الذاكرة المحفوظة"""
        try:
            mem_file = self.storage_dir / "memory.json"
            if mem_file.exists():
                data = json.loads(mem_file.read_text(encoding="utf-8"))
                for entry_id, entry_dict in data.items():
                    self._entries[entry_id] = MemoryEntry(
                        id=entry_id,
                        content=entry_dict.get("content", ""),
                        category=entry_dict.get("category", "observation"),
                        target=entry_dict.get("target", ""),
                        timestamp=entry_dict.get("timestamp", time.time()),
                        tags=entry_dict.get("tags", []),
                        importance=entry_dict.get("importance", 0.5),
                        metadata=entry_dict.get("metadata", {}),
                    )
                logger.info("💾 Memory loaded: %d entries", len(self._entries))
        except Exception as exc:
            logger.warning("Memory load failed: %s", exc)

    def _evict_low_importance(self):
        """يحذف الـ entries الأقل أهمية عند امتلاء الذاكرة"""
        sorted_entries = sorted(
            self._entries.items(),
            key=lambda x: x[1].importance,
        )
        # احذف الـ 10% الأقل أهمية
        evict_count = max(1, len(sorted_entries) // 10)
        for entry_id, _ in sorted_entries[:evict_count]:
            del self._entries[entry_id]
        logger.info("🗑️  Evicted %d low-importance entries", evict_count)

    # ── Stats ─────────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        """إحصائيات الذاكرة"""
        categories: Dict[str, int] = {}
        targets: Dict[str, int] = {}

        for entry in self._entries.values():
            categories[entry.category] = categories.get(entry.category, 0) + 1
            targets[entry.target] = targets.get(entry.target, 0) + 1

        return {
            "total_entries": len(self._entries),
            "max_capacity": self.max_entries,
            "usage_percent": round(len(self._entries) / self.max_entries * 100, 1),
            "by_category": categories,
            "by_target": targets,
            "vector_db_enabled": self._vector_db is not None,
        }
