"""
Hunter Agent Protocol v1: Memory Hierarchy System
=================================================
Manages 4 clean memory partitions:
1. short_term   -> Active mission memory & blackboard items
2. long_term    -> Historical missions, verified target attack paths, and SQLite records
3. knowledge    -> Vulnerability knowledge base (CWE, OWASP Top 10, PortSwigger vectors)
4. agent_memory -> What each agent learned (successful mutations, parameter heuristics)
"""
from __future__ import annotations

import os
import json
import time
import sqlite3
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set


class MemoryHierarchy:
    """
    نظام الذاكرة الهرمي (Memory Hierarchy System):
    يقسم الذاكرة إلى 4 فروع معزولة مع إمكانية البحث والاسترجاع.
    """

    def __init__(self, root_memory_dir: str = "memory"):
        self.root_dir = Path(root_memory_dir)
        self.short_term_dir = self.root_dir / "short_term"
        self.long_term_dir = self.root_dir / "long_term"
        self.knowledge_dir = self.root_dir / "knowledge"
        self.agent_memory_dir = self.root_dir / "agent_memory"

        for d in [self.short_term_dir, self.long_term_dir, self.knowledge_dir, self.agent_memory_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self._init_long_term_db()
        self._seed_knowledge_base()

    def _init_long_term_db(self):
        db_path = self.long_term_dir / "historical_missions.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mission_history (
                    job_id TEXT PRIMARY KEY,
                    target TEXT,
                    start_time REAL,
                    end_time REAL,
                    findings_count INTEGER,
                    status TEXT,
                    summary_json TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS verified_findings (
                    finding_id TEXT PRIMARY KEY,
                    job_id TEXT,
                    target TEXT,
                    vuln_type TEXT,
                    severity TEXT,
                    cwe_id TEXT,
                    endpoint TEXT,
                    param_name TEXT,
                    evidence_json TEXT
                )
            """)
            conn.commit()

    def _seed_knowledge_base(self):
        kb_file = self.knowledge_dir / "cwe_taxonomy.json"
        if not kb_file.exists():
            default_kb = {
                "CWE-89": {"name": "SQL Injection", "category": "Injection", "severity": "High"},
                "CWE-79": {"name": "Cross-Site Scripting", "category": "Input Validation", "severity": "Medium"},
                "CWE-918": {"name": "Server-Side Request Forgery", "category": "Network", "severity": "High"},
                "CWE-639": {"name": "Broken Object Level Authorization (IDOR)", "category": "Authorization", "severity": "High"},
                "CWE-22": {"name": "Path Traversal", "category": "File Access", "severity": "High"},
                "CWE-94": {"name": "Code Injection / SSTI", "category": "Execution", "severity": "Critical"}
            }
            with open(kb_file, "w", encoding="utf-8") as f:
                json.dump(default_kb, f, indent=2)

    # ── 1. Short-Term Memory ────────────────────────────────────────────────
    def save_short_term(self, job_id: str, key: str, value: Any):
        job_dir = self.short_term_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)
        with open(job_dir / f"{key}.json", "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2)

    def load_short_term(self, job_id: str, key: str) -> Optional[Any]:
        p = self.short_term_dir / job_id / f"{key}.json"
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    # ── 2. Long-Term Memory ─────────────────────────────────────────────────
    def record_completed_mission(
        self,
        job_id: str,
        target: str,
        start_time: float,
        findings: List[Dict[str, Any]],
        status: str = "completed"
    ):
        db_path = self.long_term_dir / "historical_missions.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO mission_history (job_id, target, start_time, end_time, findings_count, status, summary_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (job_id, target, start_time, time.time(), len(findings), status, json.dumps(findings)))

            for f in findings:
                conn.execute("""
                    INSERT OR REPLACE INTO verified_findings (finding_id, job_id, target, vuln_type, severity, cwe_id, endpoint, param_name, evidence_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    f.get("finding_id", f"fnd_{time.time()}"),
                    job_id,
                    target,
                    f.get("type", "Vulnerability"),
                    f.get("severity", "Medium"),
                    f.get("cwe_id", "CWE-Unknown"),
                    f.get("endpoint", ""),
                    f.get("param_name", ""),
                    json.dumps(f)
                ))
            conn.commit()

    # ── 3. Knowledge Base ───────────────────────────────────────────────────
    def query_knowledge(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        kb_file = self.knowledge_dir / "cwe_taxonomy.json"
        if kb_file.exists():
            with open(kb_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get(cwe_id.upper())
        return None

    # ── 4. Agent Memory (Learned Patterns) ───────────────────────────────────
    def record_agent_lesson(self, agent_name: str, lesson_key: str, lesson_data: Dict[str, Any]):
        agent_file = self.agent_memory_dir / f"{agent_name}_memory.json"
        existing = {}
        if agent_file.exists():
            with open(agent_file, "r", encoding="utf-8") as f:
                existing = json.load(f)

        existing[lesson_key] = {
            "timestamp": time.time(),
            "data": lesson_data
        }
        with open(agent_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)

    def get_agent_lessons(self, agent_name: str) -> Dict[str, Any]:
        agent_file = self.agent_memory_dir / f"{agent_name}_memory.json"
        if agent_file.exists():
            with open(agent_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}
