"""
Knowledge Base — Phase 3 of Self-Learning Pipeline
تخزين ثلاثي: SQLite (structured) + Vector embeddings (semantic) + File store (raw)
بدون dependencies ثقيلة: يعتمد على sqlite3 + numpy المدمجين في Python
"""
import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import time
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("learning.knowledge_base")

KB_DIR = Path("data/knowledge_base")
VECTOR_DIR = Path("data/vector_db")
RAW_DIR = Path("data/raw_writeups")

for d in [KB_DIR, VECTOR_DIR, RAW_DIR]:
    d.mkdir(parents=True, exist_ok=True)

DB_PATH = KB_DIR / "pentest_kb.sqlite3"


def _cosine_similarity(a: List[float], b: List[float]) -> float:
    """حساب Cosine Similarity بدون numpy"""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


class KnowledgeBase:
    """
    قاعدة المعرفة المركزية — ثلاثة طبقات:
    1. SQLite  → CVEs، Articles، Payloads، Techniques (Structured)
    2. Vectors → Embeddings للـ Semantic Search
    3. Files   → النصوص الخام (للاسترجاع الكامل)
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_schema()
        # Vector index (in-memory, saved to JSON file)
        self._vector_index: List[Dict] = []
        self._vector_file = VECTOR_DIR / "vector_index.json"
        self._load_vectors()
        self._seed_methodology_if_needed()

    def _seed_methodology_if_needed(self):
        try:
            with self._conn() as conn:
                count = conn.execute("SELECT COUNT(*) FROM techniques").fetchone()[0]
            if count < 5:
                from core.playbooks.bug_bounty_methodology import BugBountyMethodology
                bm = BugBountyMethodology()
                bm.register_methodology_in_kb(self)
        except Exception:
            pass

    # ── Schema ───────────────────────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS articles (
                id TEXT PRIMARY KEY,
                title TEXT,
                source_url TEXT UNIQUE,
                source_type TEXT,
                summary TEXT,
                severity TEXT,
                techniques TEXT,
                related_cves TEXT,
                related_tools TEXT,
                bypass_techniques TEXT,
                payloads TEXT,
                key_learnings TEXT,
                exploit_chain_hints TEXT,
                affected_technologies TEXT,
                embedding_text TEXT,
                raw_path TEXT,
                created_at REAL,
                updated_at REAL
            );

            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                published TEXT,
                affected_technologies TEXT,
                related_tools TEXT,
                techniques TEXT,
                payloads TEXT,
                poc_urls TEXT,
                created_at REAL
            );

            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload_type TEXT,
                payload_text TEXT UNIQUE,
                affected_technologies TEXT,
                waf_bypass_techniques TEXT,
                source_url TEXT,
                severity TEXT,
                created_at REAL
            );

            CREATE TABLE IF NOT EXISTS techniques (
                id TEXT PRIMARY KEY,
                name TEXT,
                category TEXT,
                description TEXT,
                required_tools TEXT,
                steps TEXT,
                bypass_methods TEXT,
                common_payloads TEXT,
                affected_tech TEXT,
                created_at REAL,
                updated_at REAL
            );

            CREATE TABLE IF NOT EXISTS exploit_chains (
                id TEXT PRIMARY KEY,
                name TEXT,
                description TEXT,
                steps TEXT,
                techniques TEXT,
                cve_ids TEXT,
                severity TEXT,
                source_url TEXT,
                created_at REAL
            );

            CREATE TABLE IF NOT EXISTS learning_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                source_url TEXT,
                source_type TEXT,
                key_learnings TEXT,
                related_cves TEXT,
                related_tools TEXT,
                techniques TEXT,
                status TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_articles_techniques ON articles(techniques);
            CREATE INDEX IF NOT EXISTS idx_articles_severity ON articles(severity);
            CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
            CREATE INDEX IF NOT EXISTS idx_payloads_type ON payloads(payload_type);
            CREATE INDEX IF NOT EXISTS idx_techniques_category ON techniques(category);
            """)

    # ── Vector Index (JSON-based, no external DB needed) ─────────────────────

    def _load_vectors(self):
        if self._vector_file.exists():
            try:
                self._vector_index = json.loads(self._vector_file.read_text(encoding="utf-8"))
                log.info(f"[KB] Loaded {len(self._vector_index)} vector embeddings")
            except Exception:
                self._vector_index = []

    def _save_vectors(self):
        try:
            self._vector_file.write_text(
                json.dumps(self._vector_index, ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception as e:
            log.warning(f"[KB] Vector save error: {e}")

    def _simple_embed(self, text: str) -> List[float]:
        """
        Embedding بسيط حتمي (TF-IDF-like, 128-dim).
        يُستبدل بـ Qwen/SentenceTransformer لما يكون متاح.
        """
        security_vocab = [
            "xss", "sqli", "rce", "ssrf", "idor", "csrf", "ssti", "xxe",
            "injection", "bypass", "payload", "exploit", "vulnerability",
            "authentication", "authorization", "privilege", "escalation",
            "traversal", "deserialization", "race", "condition", "overflow",
            "format", "string", "heap", "stack", "use-after-free", "null",
            "pointer", "integer", "logic", "timing", "channel", "blind",
            "error", "union", "select", "sleep", "benchmark", "load_file",
            "script", "alert", "onerror", "onload", "eval", "document",
            "cookie", "localStorage", "sessionStorage", "fetch", "xhr",
            "prototype", "pollution", "chain", "gadget", "serialize",
            "pickle", "yaml", "json", "xml", "dtd", "entity", "include",
            "template", "render", "jinja", "twig", "smarty", "freemarker",
            "redirect", "open", "cors", "origin", "credentials", "token",
            "jwt", "hmac", "signature", "header", "host", "x-forwarded",
            "upload", "file", "path", "directory", "local", "remote",
            "cve", "cvss", "nist", "cisa", "kev", "patch", "remediation",
            "nuclei", "sqlmap", "burp", "nmap", "ffuf", "amass", "subfinder",
            "metasploit", "hashcat", "nikto", "dalfox", "gobuster", "wfuzz",
            "apache", "nginx", "tomcat", "wordpress", "drupal", "php",
            "python", "java", "node", "ruby", "golang", "dotnet", "spring",
            "aws", "azure", "gcp", "kubernetes", "docker", "s3", "lambda",
            "critical", "high", "medium", "low", "severity", "score",
            "proof", "evidence", "confirmed", "verified", "reported",
            "bounty", "disclosure", "writeup", "hackerone", "bugcrowd",
            "portswigger", "lab", "practice", "ctf", "challenge",
            "network", "web", "mobile", "api", "graphql", "rest",
            "soap", "grpc", "websocket", "oauth", "saml", "oidc",
            "ldap", "smtp", "ftp", "ssh", "rdp", "smb", "snmp",
        ]
        text_lower = text.lower()
        words = re.findall(r"\w+", text_lower)
        word_freq: Dict[str, int] = {}
        for w in words:
            word_freq[w] = word_freq.get(w, 0) + 1
        total = len(words) or 1
        embedding = []
        for vocab_word in security_vocab:
            freq = word_freq.get(vocab_word, 0)
            embedding.append(freq / total)
        return embedding

    def add_embedding(self, doc_id: str, text: str, metadata: Dict):
        vec = self._simple_embed(text)
        # Extract normalized technique names for indexing
        raw_techs = metadata.get("techniques", metadata.get("technique_names", []))
        tech_names = [t.get("technique") if isinstance(t, dict) else str(t) for t in raw_techs]
        # Remove old entry if exists
        self._vector_index = [v for v in self._vector_index if v.get("id") != doc_id]
        self._vector_index.append({
            "id": doc_id,
            "vector": vec,
            "metadata": {
                "title": metadata.get("title", ""),
                "source_url": metadata.get("source_url", ""),
                "techniques": tech_names,
                "severity": metadata.get("severity", ""),
                "source_type": metadata.get("source_type", "article"),
            }
        })
        if len(self._vector_index) % 50 == 0:
            self._save_vectors()

    def semantic_search(
        self, query: str, top_k: int = 5, source_type: Optional[str] = None
    ) -> List[Dict]:
        """بحث دلالي عبر Cosine Similarity"""
        if not self._vector_index:
            return []
        query_vec = self._simple_embed(query)
        scored = []
        for entry in self._vector_index:
            if source_type and entry["metadata"].get("source_type") != source_type:
                continue
            sim = _cosine_similarity(query_vec, entry["vector"])
            scored.append({**entry["metadata"], "id": entry["id"], "score": sim})
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:top_k]

    # ── Article Storage ───────────────────────────────────────────────────────

    def _gen_id(self, text: str) -> str:
        return hashlib.md5(text.encode()).hexdigest()[:16]

    def save_article(self, analysis: Dict) -> str:
        """يحفظ مقال / writeup محلل"""
        url = analysis.get("source_url", "")
        doc_id = self._gen_id(url or analysis.get("summary", str(time.time())))
        raw_path = ""
        # Save raw text to file
        raw_text = analysis.get("embedding_text", "")
        if raw_text:
            raw_file = RAW_DIR / f"{doc_id}.txt"
            raw_file.write_text(raw_text, encoding="utf-8")
            raw_path = str(raw_file)

        now = time.time()
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO articles
                (id, title, source_url, source_type, summary, severity, techniques,
                 related_cves, related_tools, bypass_techniques, payloads, key_learnings,
                 exploit_chain_hints, affected_technologies, embedding_text, raw_path,
                 created_at, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                doc_id,
                analysis.get("title", ""),
                url,
                analysis.get("source_type", "article"),
                analysis.get("summary", ""),
                analysis.get("severity", "Unknown"),
                json.dumps(analysis.get("techniques", [])),
                json.dumps(analysis.get("related_cves", [])),
                json.dumps(analysis.get("related_tools", [])),
                json.dumps(analysis.get("bypass_techniques", [])),
                json.dumps(analysis.get("payloads", [])),
                json.dumps(analysis.get("key_learnings", [])),
                json.dumps(analysis.get("exploit_chain_hints", [])),
                json.dumps(analysis.get("affected_technologies", [])),
                analysis.get("embedding_text", "")[:2000],
                raw_path,
                now,
                now,
            ))
        self.add_embedding(doc_id, raw_text, analysis)
        return doc_id

    def save_cve(self, cve_analysis: Dict) -> str:
        """يحفظ CVE entry"""
        cve_id = cve_analysis.get("cve_id", "")
        if not cve_id:
            return ""
        now = time.time()
        with self._conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO cves
                (id, description, cvss_score, severity, published, affected_technologies,
                 related_tools, techniques, payloads, poc_urls, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (
                cve_id,
                cve_analysis.get("description", "")[:2000],
                cve_analysis.get("cvss_score", 0.0),
                cve_analysis.get("severity", "Unknown"),
                cve_analysis.get("published", ""),
                json.dumps(cve_analysis.get("affected_technologies", [])),
                json.dumps(cve_analysis.get("related_tools", [])),
                json.dumps(cve_analysis.get("techniques", [])),
                json.dumps(cve_analysis.get("payloads", [])),
                json.dumps(cve_analysis.get("poc_urls", [])),
                now,
            ))
        self.add_embedding(
            cve_id,
            f"{cve_id} {cve_analysis.get('description','')}",
            {**cve_analysis, "source_type": "cve"}
        )
        return cve_id

    def save_payload(self, payload_text: str, payload_type: str,
                     technologies: List[str] = None, bypass_techniques: List[str] = None,
                     source_url: str = "", severity: str = "High") -> int:
        """يحفظ payload جديد"""
        now = time.time()
        with self._conn() as conn:
            cur = conn.execute("""
                INSERT OR IGNORE INTO payloads
                (payload_type, payload_text, affected_technologies, waf_bypass_techniques,
                 source_url, severity, created_at)
                VALUES (?,?,?,?,?,?,?)
            """, (
                payload_type,
                payload_text[:2000],
                json.dumps(technologies or []),
                json.dumps(bypass_techniques or []),
                source_url,
                severity,
                now,
            ))
            return cur.lastrowid or 0

    def save_technique(self, technique_name: str, category: str, description: str,
                       tools: List[str] = None, steps: List[str] = None,
                       bypass_methods: List[str] = None, payloads: List[str] = None,
                       affected_tech: List[str] = None) -> str:
        """يحفظ/يُحدّث تقنية هجومية"""
        tech_id = self._gen_id(technique_name.lower())
        now = time.time()
        with self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM techniques WHERE id=?", (tech_id,)
            ).fetchone()
            if existing:
                conn.execute("""
                    UPDATE techniques SET description=?, required_tools=?, steps=?,
                    bypass_methods=?, common_payloads=?, affected_tech=?, updated_at=?
                    WHERE id=?
                """, (
                    description, json.dumps(tools or []), json.dumps(steps or []),
                    json.dumps(bypass_methods or []), json.dumps(payloads or []),
                    json.dumps(affected_tech or []), now, tech_id
                ))
            else:
                conn.execute("""
                    INSERT INTO techniques
                    (id, name, category, description, required_tools, steps, bypass_methods,
                     common_payloads, affected_tech, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    tech_id, technique_name, category, description,
                    json.dumps(tools or []), json.dumps(steps or []),
                    json.dumps(bypass_methods or []), json.dumps(payloads or []),
                    json.dumps(affected_tech or []), now, now
                ))
        return tech_id

    def log_learning(self, source_url: str, source_type: str,
                     analysis: Dict, status: str = "success"):
        """يسجّل كل جلسة تعلم للـ audit trail"""
        with self._conn() as conn:
            conn.execute("""
                INSERT INTO learning_logs
                (timestamp, source_url, source_type, key_learnings, related_cves,
                 related_tools, techniques, status)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                time.time(), source_url, source_type,
                json.dumps(analysis.get("key_learnings", [])),
                json.dumps(analysis.get("related_cves", [])),
                json.dumps(analysis.get("related_tools", [])),
                json.dumps(analysis.get("techniques", [])),
                status,
            ))

    # ── Query methods ─────────────────────────────────────────────────────────

    def get_techniques_for_target(self, tech_hints: List[str]) -> List[Dict]:
        """يُعيد تقنيات الهجوم المناسبة لتكنولوجيا الهدف"""
        if not tech_hints:
            return []
        with self._conn() as conn:
            results = []
            for tech in tech_hints[:5]:
                rows = conn.execute(
                    "SELECT * FROM techniques WHERE affected_tech LIKE ? LIMIT 5",
                    (f"%{tech}%",)
                ).fetchall()
                results.extend([dict(r) for r in rows])
        return results

    def get_payloads_by_type(self, payload_type: str, limit: int = 20) -> List[str]:
        """يُعيد payloads بحسب النوع"""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT payload_text FROM payloads WHERE payload_type=? LIMIT ?",
                (payload_type, limit)
            ).fetchall()
            return [r["payload_text"] for r in rows]

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """يجلب تفاصيل CVE"""
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM cves WHERE id=?", (cve_id,)).fetchone()
            if row:
                d = dict(row)
                for field in ["affected_technologies", "related_tools", "techniques", "payloads", "poc_urls"]:
                    try:
                        d[field] = json.loads(d.get(field) or "[]")
                    except Exception:
                        d[field] = []
                return d
        return None

    def find_relevant_for_scan(self, target_url: str, html_snippet: str, top_k: int = 5) -> Dict[str, Any]:
        """
        يجد المعرفة المرتبطة بهدف فحص محدد.
        يُستخدم من AutonomousBrain لتحسين خطة الهجوم.
        """
        query = f"{target_url} {html_snippet[:200]}"
        similar_articles = self.semantic_search(query, top_k=top_k)
        techniques = []
        payloads_by_type: Dict[str, List[str]] = {}
        cves_mentioned = []
        for art in similar_articles:
            raw_techs = art.get("techniques", [])
            for t in raw_techs:
                t_name = t.get("technique") if isinstance(t, dict) else str(t)
                if t_name and t_name not in techniques:
                    techniques.append(t_name)
                    pls = self.get_payloads_by_type(t_name, limit=5)
                    if pls:
                        payloads_by_type[t_name] = pls
        return {
            "similar_articles": similar_articles,
            "recommended_techniques": techniques[:8],
            "suggested_payloads": payloads_by_type,
            "related_cves": cves_mentioned[:5],
            "confidence": len(similar_articles) / top_k if similar_articles else 0.0,
        }

    def stats(self) -> Dict[str, int]:
        """إحصائيات قاعدة المعرفة"""
        with self._conn() as conn:
            return {
                "articles": conn.execute("SELECT COUNT(*) FROM articles").fetchone()[0],
                "cves": conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
                "payloads": conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0],
                "techniques": conn.execute("SELECT COUNT(*) FROM techniques").fetchone()[0],
                "exploit_chains": conn.execute("SELECT COUNT(*) FROM exploit_chains").fetchone()[0],
                "learning_logs": conn.execute("SELECT COUNT(*) FROM learning_logs").fetchone()[0],
                "vectors": len(self._vector_index),
            }

    def flush_vectors(self):
        """حفظ الـ vector index على الديسك"""
        self._save_vectors()
