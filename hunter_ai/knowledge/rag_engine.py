"""
HunterAI RAG Engine — Retrieval-Augmented Generation
=====================================================

محرك استرجاع معرفي يزوّد الوكلاء بمعرفة متخصصة من قاعدة معرفية محلية
(CWE، OWASP، PortSwigger، تقنيات ATT&CK) بدلاً من الاعتماد على حفظ النموذج.

يستخدم تشابه جيب similarity cosinus بسيط على التمثيلات النomial (bag-of-words)
بدون الحاجة لمكتبات خارجية ثقيلة، مع إمكانية التكامل مع FAISS مستقبلاً.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class KnowledgeItem:
    item_id: str
    title: str
    content: str
    source: str  # cwe, owasp, mitre, portswigger, ...
    tags: List[str] = field(default_factory=list)
    score: float = 0.0  # نتيجة التشابه المحسوبة
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "title": self.title,
            "content": self.content,
            "source": self.source,
            "tags": self.tags,
            "score": self.score,
            "metadata": self.metadata,
        }


def _tokenize(text: str) -> List[str]:
    """تقسيم بسيط إلى كلمات (tokens) للبناء النomial."""
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    return [t for t in text.split() if len(t) > 2]


def _tfidf_vector(tokens: List[str], vocab: List[str]) -> List[float]:
    """إنشاء متجه TF نomial بسيط."""
    vec = [0.0] * len(vocab)
    token_set = set(tokens)
    for i, term in enumerate(vocab):
        if term in token_set:
            vec[i] = 1.0
    # تطبيع المتجه
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """حساب تشابه جيب بين متجهين."""
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class RAGEngine:
    """
    محرك استرجاع معرفي (RAG) يجلب العناصر الأكثر صلة باستعلام الوكيل.
    """

    def __init__(self, knowledge_dir: str = "data/knowledge_base"):
        self.knowledge_dir = Path(knowledge_dir)
        self.items: List[KnowledgeItem] = []
        self.vocab: List[str] = []
        self._vectors: List[List[float]] = []
        self._built = False
        self._load_knowledge()

    def _load_knowledge(self) -> None:
        """تحميل عناصر المعرفة من الملفات JSON و SQLite المتاحة."""
        # تحميل من ملفات JSON في دليل المعرفة
        if self.knowledge_dir.exists():
            for json_file in self.knowledge_dir.rglob("*.json"):
                try:
                    with open(json_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._ingest_json(data, source=json_file.stem)
                except Exception:
                    continue

        # بذرة افتراضية إذا كان الدليل فارغًا
        if not self.items:
            self._seed_default()

        self._build_index()

    def _ingest_json(self, data: Any, source: str) -> None:
        """إدخال بيانات JSON إلى قاعدة المعرفة."""
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, dict):
                    title = v.get("name", v.get("title", k))
                    content = json.dumps(v, ensure_ascii=False)
                    tags = v.get("tags", [])
                    if isinstance(tags, str):
                        tags = [tags]
                    item = KnowledgeItem(
                        item_id=f"{source}:{k}",
                        title=str(title),
                        content=content,
                        source=source,
                        tags=tags if isinstance(tags, list) else [],
                        metadata={"cwe_id": k} if k.startswith("CWE") else {},
                    )
                    self.items.append(item)
                elif isinstance(v, str):
                    item = KnowledgeItem(
                        item_id=f"{source}:{k}",
                        title=str(k),
                        content=v,
                        source=source,
                        tags=[],
                    )
                    self.items.append(item)
        elif isinstance(data, list):
            for i, entry in enumerate(data):
                if isinstance(entry, dict):
                    title = entry.get("title", entry.get("name", f"item_{i}"))
                    content = json.dumps(entry, ensure_ascii=False)
                    item = KnowledgeItem(
                        item_id=f"{source}:{i}",
                        title=str(title),
                        content=content,
                        source=source,
                        tags=entry.get("tags", []) if isinstance(entry.get("tags"), list) else [],
                    )
                    self.items.append(item)

    def _seed_default(self) -> None:
        """بذرة معرفية افتراضية لقواعد الثغرات الشائعة."""
        default_items = [
            KnowledgeItem(
                item_id="seed:cwe-89",
                title="CWE-89: SQL Injection",
                content="SQL Injection occurs when user input is improperly sanitized before being included in SQL queries, allowing attackers to read, modify, or delete database contents.",
                source="cwe",
                tags=["sqli", "injection", "database", "cwe-89"],
                metadata={"cwe_id": "CWE-89", "severity": "High"},
            ),
            KnowledgeItem(
                item_id="seed:cwe-79",
                title="CWE-79: Cross-Site Scripting",
                content="Cross-Site Scripting (XSS) allows attackers to inject client-side scripts into web pages viewed by other users, leading to session hijacking or defacement.",
                source="cwe",
                tags=["xss", "client-side", "injection", "cwe-79"],
                metadata={"cwe_id": "CWE-79", "severity": "Medium"},
            ),
            KnowledgeItem(
                item_id="seed:cwe-918",
                title="CWE-918: Server-Side Request Forgery",
                content="SSRF occurs when a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to access internal services.",
                source="cwe",
                tags=["ssrf", "network", "internal", "cwe-918"],
                metadata={"cwe_id": "CWE-918", "severity": "High"},
            ),
            KnowledgeItem(
                item_id="seed:cwe-639",
                title="CWE-639: Broken Object Level Authorization (IDOR)",
                content="IDOR occurs when an application provides direct access to objects based on user-supplied input without proper authorization checks.",
                source="cwe",
                tags=["idor", "bola", "authorization", "api", "cwe-639"],
                metadata={"cwe_id": "CWE-639", "severity": "High"},
            ),
            KnowledgeItem(
                item_id="seed:mitre-t1190",
                title="MITRE T1190: Exploit Public-Facing Application",
                content="Adversaries may exploit software vulnerabilities in public-facing applications to gain initial access. Common web vectors include SQLi, XSS, SSRF, and IDOR.",
                source="mitre",
                tags=["initial-access", "t1190", "web-exploitation"],
                metadata={"technique_id": "T1190", "tactic": "initial-access"},
            ),
            KnowledgeItem(
                item_id="seed:mitre-t1552",
                title="MITRE T1552: Unsecured Credentials",
                content="Adversaries may search for credentials stored in insecure locations such as JavaScript files, configuration files, or environment variables.",
                source="mitre",
                tags=["credential-access", "t1552", "secrets", "js-files"],
                metadata={"technique_id": "T1552", "tactic": "credential-access"},
            ),
        ]
        self.items.extend(default_items)

    def _build_index(self) -> None:
        """بناء فهرس المفردات والمتجهات للبحث."""
        all_tokens: List[List[str]] = []
        for item in self.items:
            tokens = _tokenize(item.title + " " + item.content + " " + " ".join(item.tags))
            all_tokens.append(tokens)

        # بناء المفردات من جميع المصطلحات
        vocab_set = set()
        for tokens in all_tokens:
            vocab_set.update(tokens)
        self.vocab = sorted(vocab_set)

        # بناء المتجهات
        self._vectors = [_tfidf_vector(tokens, self.vocab) for tokens in all_tokens]
        self._built = True

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        source_filter: Optional[str] = None,
        min_score: float = 0.1,
    ) -> List[KnowledgeItem]:
        """
        استرجاع أقوى K عناصر معرفة مرتبطة بالاستعلام.

        Args:
            query: استعلام البحث (نص طبيعي)
            top_k: عدد النتائج maxima
            source_filter: تصفية حسب مصدر (cwe, mitre, owasp, ...)
            min_score: الحد الأدنى لنتيجة التشابه
        """
        if not self._built or not self.items:
            return []

        query_tokens = _tokenize(query)
        query_vec = _tfidf_query(query_tokens, self.vocab)

        scored: List[Tuple[float, int]] = []
        for idx, item in enumerate(self.items):
            if source_filter and item.source != source_filter:
                continue
            sim = _cosine_similarity(query_vec, self._vectors[idx])
            if sim >= min_score:
                scored.append((sim, idx))

        scored.sort(key=lambda x: x[0], reverse=True)
        results: List[KnowledgeItem] = []
        for sim, idx in scored[:top_k]:
            item = self.items[idx]
            item.score = sim
            results.append(item)

        return results

    def search_cwe(self, cwe_id: str) -> Optional[KnowledgeItem]:
        """البحث عن إدخال CWE بالمعرف."""
        for item in self.items:
            if item.metadata.get("cwe_id", "").upper() == cwe_id.upper():
                return item
        return None

    def search_technique(self, technique_id: str) -> Optional[KnowledgeItem]:
        """البحث عن تقنية MITRE بالمعرف."""
        for item in self.items:
            if item.metadata.get("technique_id", "").upper() == technique_id.upper():
                return item
        return None

    def stats(self) -> Dict[str, Any]:
        sources: Dict[str, int] = {}
        for item in self.items:
            sources[item.source] = sources.get(item.source, 0) + 1
        return {
            "total_items": len(self.items),
            "vocab_size": len(self.vocab),
            "sources": sources,
        }

    # ═══════════════════════════════════════════════════════════════════════════════
    # RAG — Structured Memory Integration
    # ═══════════════════════════════════════════════════════════════════════════════

    def sync_to_structured_memory(
        self,
        target: str,
        structured_memory,
        ttl_seconds: Optional[int] = None,
    ) -> int:
        """
        مزامنة عناصر RAG إلى الذاكرة الدلالية المنظمة للتخزين الدائم.
        يتيح استرجاع المعرفة لاحقًا عبر الذاكرة المنظمة حتى بدون محرك RAG.
        """
        count = 0
        for item in self.items:
            try:
                structured_memory.store_knowledge(
                    target=target,
                    item_id=item.item_id,
                    title=item.title,
                    content=item.content,
                    source=item.source,
                    tags=item.tags,
                    metadata=item.metadata,
                    ttl_seconds=ttl_seconds,
                )
                count += 1
            except Exception:
                continue
        return count

    def load_from_structured_memory(
        self,
        target: str,
        structured_memory,
    ) -> int:
        """
        تحميل المعرفة من الذاكرة الدلالية المنظمة إلى فهرس RAG.
        يدمج المعرفة المخزنة مسبقًا مع العناصر الحالية.
        """
        kb_items = structured_memory.get_all_semantic(target)
        count = 0
        for kb in kb_items:
            try:
                item = KnowledgeItem(
                    item_id=kb.get("item_id", f"sm:{target}"),
                    title=kb.get("title", ""),
                    content=kb.get("content", ""),
                    source=kb.get("source", "structured_memory"),
                    tags=kb.get("tags", []),
                    metadata=kb.get("metadata", {}),
                )
                # تجنب التكرار
                if not any(i.item_id == item.item_id for i in self.items):
                    self.items.append(item)
                    count += 1
            except Exception:
                continue
        if count > 0:
            self._build_index()  # إعادة بناء الفهرس مع العناصر الجديدة
        return count

    def retrieve_with_memory(
        self,
        query: str,
        target: str,
        structured_memory,
        top_k: int = 5,
        source_filter: Optional[str] = None,
        min_score: float = 0.1,
    ) -> List[KnowledgeItem]:
        """
        استرجاع معرفة من محرك RAG والذاكرة المنظمة معًا.
        يدمج نتائج التشابه الجيبي من RAG مع نتائج التوافق بالكلمات المفتاحية من الذاكرة.
        """
        # نتائج من محرك RAG
        rag_results = self.retrieve(
            query=query,
            top_k=top_k,
            source_filter=source_filter,
            min_score=min_score,
        )

        # نتائج من الذاكرة المنظمة
        memory_results = structured_memory.retrieve_knowledge(
            target=target,
            query=query,
            top_k=top_k,
        )

        # دمج النتائج مع تجنب التكرار
        seen_ids = set()
        combined: List[KnowledgeItem] = []

        for item in rag_results:
            if item.item_id not in seen_ids:
                seen_ids.add(item.item_id)
                combined.append(item)

        for mem in memory_results:
            if mem["item_id"] not in seen_ids:
                seen_ids.add(mem["item_id"])
                combined.append(
                    KnowledgeItem(
                        item_id=mem["item_id"],
                        title=mem["title"],
                        content=mem["content"],
                        source=mem["source"],
                        tags=mem.get("tags", []),
                        score=mem.get("score", 0.0),
                        metadata=mem.get("metadata", {}),
                    )
                )

        # ترتيب حسب النقاط (إذا كانت متاحة)
        combined.sort(key=lambda x: x.score, reverse=True)
        return combined[:top_k]


def _tfidf_query(tokens: List[str], vocab: List[str]) -> List[float]:
    """إنشاء متجه للاستعلام بناءً على المفردات المعروفة."""
    vec = [0.0] * len(vocab)
    token_set = set(tokens)
    for i, term in enumerate(vocab):
        if term in token_set:
            vec[i] = 1.0
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec
