"""Durable Thread-Safe SQLite WAL Platform State Store.

Persists engagements, runs, ordered replayable events (global & per-run
monotone sequence numbers), Copilot conversations/messages/attachments,
human-in-the-loop approvals, active UI/API context, settings, and
notifications in ``data/platform_state.sqlite3``.

All stored text and JSON payloads pass through ``redact_payload`` so
credentials, Bearer/JWT tokens, cookies, and API keys are masked before
touching disk.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from core.secret_sanitizer import SecretSanitizer
from core.security_sanitizer import SecuritySanitizer

logger = logging.getLogger("hunter_ai.platform_store")

_REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = _REPO_ROOT / "data" / "platform_state.sqlite3"
_UNSET = object()

VALID_APPROVAL_STATUSES = ("pending", "approved", "rejected", "expired")
VALID_RUN_STATUSES = (
    "pending",
    "running",
    "paused",
    "stopping",
    "stopped",
    "completed",
    "failed",
    "interrupted",
)
STALE_ACTIVE_STATUSES = ("pending", "running", "paused", "stopping")

_SECRET_DICT_KEYS = frozenset({
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "refresh_token",
    "private_key",
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "bearer_token",
    "token",
    "gemini_api_key",
    "deepseek_api_key",
    "nvidia_api_key",
    "openai_api_key",
    "anthropic_api_key",
    "openrouter_api_key",
    "taskade_api_key",
    "groq_api_key",
    "ctfd_token",
})

_EXTRA_SECRET_PATTERNS: Tuple[Tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"), "AIza••••••••[REDACTED]"),
    (re.compile(r"\bnvapi-[0-9A-Za-z\-_]{16,}\b"), "nvapi-••••••••[REDACTED]"),
    (re.compile(r"\bsk-[0-9A-Za-z\-_]{16,}\b"), "sk-••••••••[REDACTED]"),
    (re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._\-+/=]{10,}"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(?i)\b(Basic\s+)[A-Za-z0-9+/=]{8,}"), r"\1[REDACTED_BASIC]"),
    (re.compile(r"(?im)^((?:Authorization|Proxy-Authorization|X-API-Key)\s*:\s*).+$"), r"\1[REDACTED_HEADER]"),
    (re.compile(r"(?im)^((?:Cookie|Set-Cookie)\s*:\s*).+$"), r"\1[REDACTED_COOKIE]"),
)


def new_id(prefix: str) -> str:
    """Generate a canonical prefixed identifier."""
    clean = re.sub(r"[^a-z0-9_]", "", prefix.lower()) or "id"
    return f"{clean}_{uuid.uuid4().hex[:12]}"


def redact_text(text: str) -> str:
    """Redact credentials, API keys, JWTs, cookies, and private keys from text."""
    if not text or not isinstance(text, str):
        return text
    out = SecretSanitizer.sanitize_text(text)
    out = SecuritySanitizer.mask_text(out)
    for pat, repl in _EXTRA_SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out


def redact_payload(value: Any, _parent_key: str = "") -> Any:
    """Recursively secret-redact strings, dicts, and lists prior to storage."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        key_l = _parent_key.strip().lower()
        if key_l in _SECRET_DICT_KEYS and value.strip():
            if "[REDACTED" in value or SecretSanitizer.MASK_BULLET in value:
                return value
            return SecretSanitizer.mask_string(value, prefix_len=3, suffix_len=2)
        return redact_text(value)
    if isinstance(value, dict):
        return {str(k): redact_payload(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_payload(item, _parent_key) for item in value]
    return redact_text(str(value))


def _json_dumps(data: Any, *, redact: bool = True) -> str:
    clean = redact_payload(data) if redact else data
    return json.dumps(clean, ensure_ascii=False, default=str)


def _json_loads(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


class PlatformStore:
    """Thread-safe SQLite WAL persistence layer for HunterAI Platform Hub & Copilot."""

    def __init__(self, db_path: Optional[str | Path] = None):
        env_path = os.getenv("HUNTER_PLATFORM_DB_PATH")
        resolved = Path(db_path) if db_path is not None else (Path(env_path) if env_path else DEFAULT_DB_PATH)
        self.db_path = resolved
        if str(self.db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=15.0,
        )
        self._conn.row_factory = sqlite3.Row
        self._event_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self._init_schema()

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def register_event_listener(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            if cb not in self._event_listeners:
                self._event_listeners.append(cb)

    def unregister_event_listener(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            if cb in self._event_listeners:
                self._event_listeners.remove(cb)

    def _init_schema(self) -> None:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL;")
            cur.execute("PRAGMA synchronous=NORMAL;")
            cur.execute("PRAGMA foreign_keys=ON;")
            cur.execute("PRAGMA busy_timeout=5000;")

            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS engagements (
                    engagement_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scope_json TEXT NOT NULL DEFAULT '[]',
                    out_of_scope_json TEXT NOT NULL DEFAULT '[]',
                    status TEXT NOT NULL DEFAULT 'authorized',
                    source TEXT NOT NULL DEFAULT 'local',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    engagement_id TEXT,
                    kind TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    current_phase TEXT NOT NULL DEFAULT 'INIT',
                    progress REAL NOT NULL DEFAULT 0.0,
                    task_id TEXT,
                    agent_id TEXT,
                    meta_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT NOT NULL DEFAULT '',
                    started_at REAL,
                    finished_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_runs_eng ON runs(engagement_id);
                CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);

                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT,
                    run_seq INTEGER NOT NULL DEFAULT 0,
                    engagement_id TEXT,
                    task_id TEXT,
                    agent_id TEXT,
                    tool_exec_id TEXT,
                    event_type TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'platform',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_run_seq ON events(run_id, run_seq);
                CREATE INDEX IF NOT EXISTS idx_events_eng ON events(engagement_id, seq);

                CREATE TABLE IF NOT EXISTS conversations (
                    conversation_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL DEFAULT 'New Conversation',
                    engagement_id TEXT,
                    run_id TEXT,
                    mode TEXT NOT NULL DEFAULT 'analyst',
                    model TEXT NOT NULL DEFAULT 'auto',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_conv_updated ON conversations(updated_at DESC);

                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    model TEXT NOT NULL DEFAULT '',
                    mode TEXT NOT NULL DEFAULT '',
                    engagement_id TEXT,
                    run_id TEXT,
                    citations_json TEXT NOT NULL DEFAULT '[]',
                    refs_json TEXT NOT NULL DEFAULT '[]',
                    approval_id TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    FOREIGN KEY (conversation_id) REFERENCES conversations(conversation_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_msg_conv ON messages(conversation_id, created_at ASC);

                CREATE TABLE IF NOT EXISTS attachments (
                    attachment_id TEXT PRIMARY KEY,
                    conversation_id TEXT,
                    filename TEXT NOT NULL,
                    content_type TEXT NOT NULL DEFAULT 'text/plain',
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    storage_path TEXT NOT NULL DEFAULT '',
                    excerpt TEXT NOT NULL DEFAULT '',
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    engagement_id TEXT,
                    run_id TEXT,
                    conversation_id TEXT,
                    task_id TEXT,
                    agent_id TEXT,
                    tool_exec_id TEXT,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL DEFAULT '',
                    tool_name TEXT NOT NULL DEFAULT '',
                    command_args TEXT NOT NULL DEFAULT '',
                    risk_tier TEXT NOT NULL DEFAULT 'TIER_2_PROBE',
                    rationale TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    decision_note TEXT NOT NULL DEFAULT '',
                    decided_by TEXT NOT NULL DEFAULT '',
                    decided_at REAL,
                    expires_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, created_at DESC);

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS context (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    active_engagement_id TEXT,
                    active_run_id TEXT,
                    active_conversation_id TEXT,
                    extra_json TEXT NOT NULL DEFAULT '{}',
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS notifications (
                    notification_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL DEFAULT 'info',
                    title TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    severity TEXT NOT NULL DEFAULT 'info',
                    ref_kind TEXT,
                    ref_id TEXT,
                    engagement_id TEXT,
                    run_id TEXT,
                    read INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_notif_created ON notifications(created_at DESC);
                """
            )
            now = time.time()
            cur.execute(
                "INSERT OR IGNORE INTO context (id, active_engagement_id, active_run_id, active_conversation_id, extra_json, updated_at) VALUES (1, NULL, NULL, NULL, '{}', ?)",
                (now,),
            )
            self._conn.commit()

    # ── Context ───────────────────────────────────────────────────────────────

    def get_context(self) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM context WHERE id = 1").fetchone()
            if not row:
                return {
                    "active_engagement_id": None,
                    "active_run_id": None,
                    "active_conversation_id": None,
                    "extra": {},
                    "updated_at": time.time(),
                }
            return {
                "active_engagement_id": row["active_engagement_id"],
                "active_run_id": row["active_run_id"],
                "active_conversation_id": row["active_conversation_id"],
                "extra": _json_loads(row["extra_json"], {}),
                "updated_at": row["updated_at"],
            }

    def update_context(
        self,
        *,
        active_engagement_id: Any = _UNSET,
        active_run_id: Any = _UNSET,
        active_conversation_id: Any = _UNSET,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            cur = self.get_context()
            eng = cur["active_engagement_id"] if active_engagement_id is _UNSET else (active_engagement_id or None)
            run = cur["active_run_id"] if active_run_id is _UNSET else (active_run_id or None)
            conv = cur["active_conversation_id"] if active_conversation_id is _UNSET else (active_conversation_id or None)
            merged_extra = dict(cur.get("extra") or {})
            if extra is not None:
                merged_extra.update(extra)
            now = time.time()
            self._conn.execute(
                """
                UPDATE context
                SET active_engagement_id = ?, active_run_id = ?, active_conversation_id = ?, extra_json = ?, updated_at = ?
                WHERE id = 1
                """,
                (eng, run, conv, _json_dumps(merged_extra), now),
            )
            self._conn.commit()
        ctx = self.get_context()
        self.append_event("CONTEXT_UPDATED", engagement_id=eng, run_id=run, payload=ctx)
        return ctx

    # ── Engagements ───────────────────────────────────────────────────────────

    def _row_to_engagement(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "engagement_id": row["engagement_id"],
            "name": row["name"],
            "target": row["target"],
            "in_scope": _json_loads(row["scope_json"], []),
            "out_of_scope": _json_loads(row["out_of_scope_json"], []),
            "status": row["status"],
            "source": row["source"],
            "metadata": _json_loads(row["metadata_json"], {}),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def upsert_engagement(
        self,
        *,
        target: str,
        name: Optional[str] = None,
        in_scope: Optional[List[str]] = None,
        out_of_scope: Optional[List[str]] = None,
        status: str = "authorized",
        source: str = "local",
        metadata: Optional[Dict[str, Any]] = None,
        engagement_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        eid = engagement_id or new_id("eng")
        clean_target = redact_text(target.strip())
        clean_name = redact_text((name or clean_target or eid).strip())
        scope_list = [str(s).strip() for s in (in_scope if in_scope is not None else ([clean_target] if clean_target else [])) if str(s).strip()]
        oos_list = [str(s).strip() for s in (out_of_scope or []) if str(s).strip()]
        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM engagements WHERE engagement_id = ?", (eid,)
            ).fetchone()
            if existing:
                old_meta = _json_loads(existing["metadata_json"], {})
                if metadata:
                    old_meta.update(redact_payload(metadata))
                self._conn.execute(
                    """
                    UPDATE engagements
                    SET name = ?, target = ?, scope_json = ?, out_of_scope_json = ?, status = ?, source = ?, metadata_json = ?, updated_at = ?
                    WHERE engagement_id = ?
                    """,
                    (
                        clean_name,
                        clean_target,
                        _json_dumps(scope_list),
                        _json_dumps(oos_list),
                        status,
                        source,
                        _json_dumps(old_meta),
                        now,
                        eid,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO engagements (engagement_id, name, target, scope_json, out_of_scope_json, status, source, metadata_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        eid,
                        clean_name,
                        clean_target,
                        _json_dumps(scope_list),
                        _json_dumps(oos_list),
                        status,
                        source,
                        _json_dumps(metadata or {}),
                        now,
                        now,
                    ),
                )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM engagements WHERE engagement_id = ?", (eid,)
            ).fetchone()
            return self._row_to_engagement(row)

    def get_engagement(self, engagement_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM engagements WHERE engagement_id = ?", (engagement_id,)
            ).fetchone()
            return self._row_to_engagement(row) if row else None

    def list_engagements(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM engagements ORDER BY updated_at DESC LIMIT ?", (max(1, min(limit, 500)),)
            ).fetchall()
            return [self._row_to_engagement(r) for r in rows]

    # ── Runs & Startup Reconciliation ─────────────────────────────────────────

    def _row_to_run(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "engagement_id": row["engagement_id"],
            "kind": row["kind"],
            "target": row["target"],
            "status": row["status"],
            "current_phase": row["current_phase"],
            "progress": row["progress"],
            "task_id": row["task_id"],
            "agent_id": row["agent_id"],
            "meta": _json_loads(row["meta_json"], {}),
            "error": row["error"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def upsert_run(
        self,
        *,
        run_id: Optional[str] = None,
        kind: str = "generic",
        target: str = "",
        engagement_id: Optional[str] = None,
        status: str = "pending",
        current_phase: str = "INIT",
        progress: float = 0.0,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        error: str = "",
        started_at: Optional[float] = None,
        finished_at: Optional[float] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        rid = run_id or new_id("run")
        clean_target = redact_text(target)
        clean_error = redact_text(error)[:1000] if error else ""
        with self._lock:
            existing = self._conn.execute(
                "SELECT * FROM runs WHERE run_id = ?", (rid,)
            ).fetchone()
            if existing:
                old_meta = _json_loads(existing["meta_json"], {})
                if meta:
                    old_meta.update(redact_payload(meta))
                self._conn.execute(
                    """
                    UPDATE runs
                    SET engagement_id = COALESCE(?, engagement_id),
                        kind = ?, target = ?, status = ?, current_phase = ?,
                        progress = ?, task_id = COALESCE(?, task_id),
                        agent_id = COALESCE(?, agent_id),
                        meta_json = ?, error = ?,
                        started_at = COALESCE(?, started_at),
                        finished_at = COALESCE(?, finished_at),
                        updated_at = ?
                    WHERE run_id = ?
                    """,
                    (
                        engagement_id,
                        kind or existing["kind"],
                        clean_target or existing["target"],
                        status,
                        current_phase or existing["current_phase"],
                        float(progress),
                        task_id,
                        agent_id,
                        _json_dumps(old_meta),
                        clean_error,
                        started_at,
                        finished_at,
                        now,
                        rid,
                    ),
                )
            else:
                self._conn.execute(
                    """
                    INSERT INTO runs (
                        run_id, engagement_id, kind, target, status, current_phase,
                        progress, task_id, agent_id, meta_json, error,
                        started_at, finished_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        rid,
                        engagement_id,
                        kind,
                        clean_target,
                        status,
                        current_phase,
                        float(progress),
                        task_id or new_id("task"),
                        agent_id,
                        _json_dumps(meta or {}),
                        clean_error,
                        started_at if started_at is not None else (now if status == "running" else None),
                        finished_at,
                        now,
                        now,
                    ),
                )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (rid,)).fetchone()
            return self._row_to_run(row)

    def update_run(self, run_id: str, **fields: Any) -> Optional[Dict[str, Any]]:
        allowed = {
            "engagement_id",
            "status",
            "current_phase",
            "progress",
            "task_id",
            "agent_id",
            "error",
            "started_at",
            "finished_at",
        }
        with self._lock:
            existing = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            if not existing:
                return None
            updates: List[str] = ["updated_at = ?"]
            params: List[Any] = [time.time()]
            for k, v in fields.items():
                if k == "meta" and isinstance(v, dict):
                    merged = _json_loads(existing["meta_json"], {})
                    merged.update(redact_payload(v))
                    updates.append("meta_json = ?")
                    params.append(_json_dumps(merged))
                elif k in allowed:
                    if k == "error" and v is not None:
                        v = redact_text(str(v))[:1000]
                    updates.append(f"{k} = ?")
                    params.append(v)
            params.append(run_id)
            self._conn.execute(f"UPDATE runs SET {', '.join(updates)} WHERE run_id = ?", params)
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            return self._row_to_run(row) if row else None

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            return self._row_to_run(row) if row else None

    def list_runs(
        self,
        *,
        kind: Optional[str] = None,
        engagement_id: Optional[str] = None,
        status: Optional[str] = None,
        active_only: bool = False,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if active_only:
            placeholders = ",".join("?" for _ in STALE_ACTIVE_STATUSES)
            clauses.append(f"status IN ({placeholders})")
            params.extend(STALE_ACTIVE_STATUSES)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM runs {where} ORDER BY created_at DESC LIMIT ?",
                params,
            ).fetchall()
            return [self._row_to_run(r) for r in rows]

    def reconcile_interrupted_runs(
        self,
        active_run_ids: Optional[Iterable[str]] = None,
        reason: str = "Interrupted by process restart before completion",
    ) -> List[Dict[str, Any]]:
        """Mark stale running/paused/pending runs from prior processes as interrupted."""
        live_ids: Set[str] = set(active_run_ids or ())
        now = time.time()
        reconciled: List[Dict[str, Any]] = []
        with self._lock:
            placeholders = ",".join("?" for _ in STALE_ACTIVE_STATUSES)
            rows = self._conn.execute(
                f"SELECT * FROM runs WHERE status IN ({placeholders})",
                STALE_ACTIVE_STATUSES,
            ).fetchall()
            for row in rows:
                rid = row["run_id"]
                if rid in live_ids:
                    continue
                self._conn.execute(
                    """
                    UPDATE runs
                    SET status = 'interrupted',
                        error = CASE WHEN error = '' THEN ? ELSE error END,
                        finished_at = COALESCE(finished_at, ?),
                        updated_at = ?
                    WHERE run_id = ?
                    """,
                    (redact_text(reason), now, now, rid),
                )
                updated = self._conn.execute("SELECT * FROM runs WHERE run_id = ?", (rid,)).fetchone()
                if updated:
                    reconciled.append(self._row_to_run(updated))
            self._conn.commit()

        for run in reconciled:
            self.append_event(
                "RUN_INTERRUPTED",
                run_id=run["run_id"],
                engagement_id=run.get("engagement_id"),
                task_id=run.get("task_id"),
                source="reconciler",
                payload={"previous_status": "active", "status": "interrupted", "reason": reason},
            )
            self.add_notification(
                kind="run_interrupted",
                title=f"Interrupted run reconciled: {run['run_id']}",
                message=f"Run on {run.get('target') or 'unknown target'} was active during shutdown and marked interrupted.",
                severity="warning",
                ref_kind="run",
                ref_id=run["run_id"],
                engagement_id=run.get("engagement_id"),
                run_id=run["run_id"],
            )
        return reconciled

    # ── Replayable Ordered Events ─────────────────────────────────────────────

    def _row_to_event(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "seq": row["seq"],
            "run_seq": row["run_seq"],
            "run_id": row["run_id"],
            "engagement_id": row["engagement_id"],
            "task_id": row["task_id"],
            "agent_id": row["agent_id"],
            "tool_exec_id": row["tool_exec_id"],
            "event_type": row["event_type"],
            "source": row["source"],
            "payload": _json_loads(row["payload_json"], {}),
            "created_at": row["created_at"],
        }

    def append_event(
        self,
        event_type: str,
        *,
        run_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_exec_id: Optional[str] = None,
        source: str = "platform",
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            if run_id:
                max_row = self._conn.execute(
                    "SELECT COALESCE(MAX(run_seq), 0) AS m FROM events WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                run_seq = int(max_row["m"]) + 1
            else:
                run_seq = 0
            cur = self._conn.execute(
                """
                INSERT INTO events (
                    run_id, run_seq, engagement_id, task_id, agent_id, tool_exec_id,
                    event_type, source, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    run_seq,
                    engagement_id,
                    task_id,
                    agent_id,
                    tool_exec_id,
                    event_type,
                    source,
                    _json_dumps(payload or {}),
                    now,
                ),
            )
            seq = cur.lastrowid
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM events WHERE seq = ?", (seq,)).fetchone()
            event = self._row_to_event(row)
            listeners = list(self._event_listeners)

        for cb in listeners:
            try:
                cb(event)
            except Exception as exc:
                logger.debug("Event listener failed: %s", exc)
        return event

    def latest_seq(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COALESCE(MAX(seq), 0) AS m FROM events").fetchone()
            return int(row["m"]) if row else 0

    def list_events(
        self,
        *,
        since_seq: int = 0,
        run_id: Optional[str] = None,
        since_run_seq: Optional[int] = None,
        engagement_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = ["seq > ?"]
        params: List[Any] = [max(0, int(since_seq))]
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        if since_run_seq is not None:
            clauses.append("run_seq > ?")
            params.append(max(0, int(since_run_seq)))
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        params.append(max(1, min(limit, 1000)))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM events WHERE {' AND '.join(clauses)} ORDER BY seq ASC LIMIT ?",
                params,
            ).fetchall()
            return [self._row_to_event(r) for r in rows]

    # ── Copilot Conversations, Messages & Attachments ─────────────────────────

    def _row_to_conversation(self, row: sqlite3.Row, message_count: Optional[int] = None) -> Dict[str, Any]:
        item = {
            "conversation_id": row["conversation_id"],
            "title": row["title"],
            "engagement_id": row["engagement_id"],
            "run_id": row["run_id"],
            "mode": row["mode"],
            "model": row["model"],
            "metadata": _json_loads(row["metadata_json"], {}),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        if message_count is not None:
            item["message_count"] = message_count
        return item

    def create_conversation(
        self,
        *,
        title: str = "New Investigation",
        engagement_id: Optional[str] = None,
        run_id: Optional[str] = None,
        mode: str = "analyst",
        model: str = "auto",
        metadata: Optional[Dict[str, Any]] = None,
        conversation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        cid = conversation_id or new_id("conv")
        clean_title = redact_text((title or "New Investigation").strip())[:200]
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO conversations (conversation_id, title, engagement_id, run_id, mode, model, metadata_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (cid, clean_title, engagement_id, run_id, mode, model, _json_dumps(metadata or {}), now, now),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM conversations WHERE conversation_id = ?", (cid,)).fetchone()
            return self._row_to_conversation(row, message_count=0)

    def get_conversation(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM conversations WHERE conversation_id = ?", (conversation_id,)
            ).fetchone()
            if not row:
                return None
            cnt_row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM messages WHERE conversation_id = ?", (conversation_id,)
            ).fetchone()
            return self._row_to_conversation(row, message_count=int(cnt_row["c"]) if cnt_row else 0)

    def list_conversations(
        self,
        *,
        engagement_id: Optional[str] = None,
        run_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if engagement_id:
            clauses.append("c.engagement_id = ?")
            params.append(engagement_id)
        if run_id:
            clauses.append("c.run_id = ?")
            params.append(run_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._conn.execute(
                f"""
                SELECT c.*, COALESCE(COUNT(m.message_id), 0) AS msg_count
                FROM conversations c
                LEFT JOIN messages m ON m.conversation_id = c.conversation_id
                {where}
                GROUP BY c.conversation_id
                ORDER BY c.updated_at DESC
                LIMIT ?
                """,
                params,
            ).fetchall()
            return [self._row_to_conversation(r, message_count=int(r["msg_count"])) for r in rows]

    def update_conversation(
        self,
        conversation_id: str,
        *,
        title: Any = _UNSET,
        engagement_id: Any = _UNSET,
        run_id: Any = _UNSET,
        mode: Any = _UNSET,
        model: Any = _UNSET,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM conversations WHERE conversation_id = ?", (conversation_id,)
            ).fetchone()
            if not row:
                return None
            new_title = redact_text(str(title).strip())[:200] if title is not _UNSET and title is not None else row["title"]
            new_eng = (engagement_id or None) if engagement_id is not _UNSET else row["engagement_id"]
            new_run = (run_id or None) if run_id is not _UNSET else row["run_id"]
            new_mode = str(mode) if mode is not _UNSET and mode is not None else row["mode"]
            new_model = str(model) if model is not _UNSET and model is not None else row["model"]
            old_meta = _json_loads(row["metadata_json"], {})
            if metadata:
                old_meta.update(redact_payload(metadata))
            self._conn.execute(
                """
                UPDATE conversations
                SET title = ?, engagement_id = ?, run_id = ?, mode = ?, model = ?, metadata_json = ?, updated_at = ?
                WHERE conversation_id = ?
                """,
                (new_title, new_eng, new_run, new_mode, new_model, _json_dumps(old_meta), time.time(), conversation_id),
            )
            self._conn.commit()
        return self.get_conversation(conversation_id)

    def delete_conversation(self, conversation_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM conversations WHERE conversation_id = ?", (conversation_id,)
            )
            deleted = cur.rowcount > 0
            if deleted:
                self._conn.execute(
                    "UPDATE context SET active_conversation_id = NULL WHERE id = 1 AND active_conversation_id = ?",
                    (conversation_id,),
                )
            self._conn.commit()
            return deleted

    def _row_to_message(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "message_id": row["message_id"],
            "conversation_id": row["conversation_id"],
            "role": row["role"],
            "content": row["content"],
            "model": row["model"],
            "mode": row["mode"],
            "engagement_id": row["engagement_id"],
            "run_id": row["run_id"],
            "citations": _json_loads(row["citations_json"], []),
            "refs": _json_loads(row["refs_json"], []),
            "approval_id": row["approval_id"],
            "metadata": _json_loads(row["metadata_json"], {}),
            "created_at": row["created_at"],
        }

    def add_message(
        self,
        *,
        conversation_id: str,
        role: str,
        content: str,
        message_id: Optional[str] = None,
        model: str = "",
        mode: str = "",
        engagement_id: Optional[str] = None,
        run_id: Optional[str] = None,
        citations: Optional[List[Dict[str, Any]]] = None,
        refs: Optional[List[Dict[str, Any]]] = None,
        approval_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        mid = message_id or new_id("msg")
        clean_content = redact_text(content)
        with self._lock:
            conv = self._conn.execute(
                "SELECT conversation_id FROM conversations WHERE conversation_id = ?", (conversation_id,)
            ).fetchone()
            if not conv:
                raise KeyError(f"Conversation '{conversation_id}' not found")
            self._conn.execute(
                """
                INSERT INTO messages (
                    message_id, conversation_id, role, content, model, mode,
                    engagement_id, run_id, citations_json, refs_json, approval_id, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    mid,
                    conversation_id,
                    role,
                    clean_content,
                    model,
                    mode,
                    engagement_id,
                    run_id,
                    _json_dumps(citations or []),
                    _json_dumps(refs or []),
                    approval_id,
                    _json_dumps(metadata or {}),
                    now,
                ),
            )
            self._conn.execute(
                "UPDATE conversations SET updated_at = ? WHERE conversation_id = ?",
                (now, conversation_id),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM messages WHERE message_id = ?", (mid,)).fetchone()
            return self._row_to_message(row)

    def list_messages(self, conversation_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC LIMIT ?",
                (conversation_id, max(1, min(limit, 1000))),
            ).fetchall()
            return [self._row_to_message(r) for r in rows]

    def save_attachment(
        self,
        *,
        filename: str,
        content_type: str,
        size_bytes: int,
        sha256: str,
        storage_path: str,
        excerpt: str,
        conversation_id: Optional[str] = None,
        attachment_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        aid = attachment_id or new_id("att")
        now = time.time()
        clean_excerpt = redact_text(excerpt)[:8000]
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO attachments (attachment_id, conversation_id, filename, content_type, size_bytes, sha256, storage_path, excerpt, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (aid, conversation_id, filename, content_type, int(size_bytes), sha256, storage_path, clean_excerpt, now),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM attachments WHERE attachment_id = ?", (aid,)).fetchone()
            return dict(row)

    def get_attachment(self, attachment_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM attachments WHERE attachment_id = ?", (attachment_id,)).fetchone()
            return dict(row) if row else None

    # ── Approvals ─────────────────────────────────────────────────────────────

    def _row_to_approval(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "approval_id": row["approval_id"],
            "engagement_id": row["engagement_id"],
            "run_id": row["run_id"],
            "conversation_id": row["conversation_id"],
            "task_id": row["task_id"],
            "agent_id": row["agent_id"],
            "tool_exec_id": row["tool_exec_id"],
            "action_type": row["action_type"],
            "target": row["target"],
            "tool_name": row["tool_name"],
            "command_args": row["command_args"],
            "risk_tier": row["risk_tier"],
            "rationale": row["rationale"],
            "payload": _json_loads(row["payload_json"], {}),
            "status": row["status"],
            "decision_note": row["decision_note"],
            "decided_by": row["decided_by"],
            "decided_at": row["decided_at"],
            "expires_at": row["expires_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_approval(
        self,
        *,
        action_type: str,
        target: str = "",
        tool_name: str = "",
        command_args: str = "",
        risk_tier: str = "TIER_2_PROBE",
        rationale: str = "",
        payload: Optional[Dict[str, Any]] = None,
        engagement_id: Optional[str] = None,
        run_id: Optional[str] = None,
        conversation_id: Optional[str] = None,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        tool_exec_id: Optional[str] = None,
        ttl_seconds: float = 3600.0,
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = time.time()
        aid = approval_id or new_id("apr")
        expires_at = now + max(60.0, float(ttl_seconds)) if ttl_seconds else None
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO approvals (
                    approval_id, engagement_id, run_id, conversation_id, task_id, agent_id, tool_exec_id,
                    action_type, target, tool_name, command_args, risk_tier, rationale, payload_json,
                    status, decision_note, decided_by, decided_at, expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', '', '', NULL, ?, ?, ?)
                """,
                (
                    aid,
                    engagement_id,
                    run_id,
                    conversation_id,
                    task_id,
                    agent_id,
                    tool_exec_id,
                    action_type,
                    redact_text(target),
                    tool_name,
                    redact_text(command_args),
                    risk_tier,
                    redact_text(rationale),
                    _json_dumps(payload or {}),
                    expires_at,
                    now,
                    now,
                ),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (aid,)).fetchone()
            rec = self._row_to_approval(row)

        self.append_event(
            "APPROVAL_REQUESTED",
            run_id=run_id,
            engagement_id=engagement_id,
            task_id=task_id,
            agent_id=agent_id,
            tool_exec_id=tool_exec_id,
            source="policy_gate",
            payload={"approval_id": aid, "action_type": action_type, "target": rec["target"], "tool_name": tool_name, "risk_tier": risk_tier},
        )
        self.add_notification(
            kind="approval_required",
            title=f"Approval required: {action_type}",
            message=f"{tool_name or action_type} on {rec['target'] or 'workspace'} ({risk_tier})",
            severity="warning",
            ref_kind="approval",
            ref_id=aid,
            engagement_id=engagement_id,
            run_id=run_id,
        )
        return rec

    def expire_stale_approvals(self) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE approvals
                SET status = 'expired', updated_at = ?
                WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at < ?
                """,
                (now, now),
            )
            self._conn.commit()
            return int(cur.rowcount)

    def get_approval(self, approval_id: str) -> Optional[Dict[str, Any]]:
        self.expire_stale_approvals()
        with self._lock:
            row = self._conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            return self._row_to_approval(row) if row else None

    def list_approvals(
        self,
        *,
        status: Optional[str] = None,
        engagement_id: Optional[str] = None,
        run_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        self.expire_stale_approvals()
        clauses: List[str] = []
        params: List[Any] = []
        if status and status != "all":
            clauses.append("status = ?")
            params.append(status)
        if engagement_id:
            clauses.append("engagement_id = ?")
            params.append(engagement_id)
        if run_id:
            clauses.append("run_id = ?")
            params.append(run_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(max(1, min(limit, 500)))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM approvals {where} ORDER BY created_at DESC LIMIT ?",
                params,
            ).fetchall()
            return [self._row_to_approval(r) for r in rows]

    def decide_approval(
        self,
        approval_id: str,
        decision: str,
        *,
        decided_by: str = "operator",
        note: str = "",
    ) -> Optional[Dict[str, Any]]:
        norm = decision.strip().lower()
        if norm in ("approve", "approved", "allow", "allowed"):
            new_status = "approved"
        elif norm in ("reject", "rejected", "deny", "denied"):
            new_status = "rejected"
        elif norm == "expired":
            new_status = "expired"
        else:
            raise ValueError(f"Invalid approval decision: {decision}")

        self.expire_stale_approvals()
        now = time.time()
        with self._lock:
            row = self._conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            if not row:
                return None
            if row["status"] != "pending":
                raise ValueError(f"Approval '{approval_id}' is already {row['status']}")
            self._conn.execute(
                """
                UPDATE approvals
                SET status = ?, decision_note = ?, decided_by = ?, decided_at = ?, updated_at = ?
                WHERE approval_id = ?
                """,
                (new_status, redact_text(note)[:500], redact_text(decided_by)[:120], now, now, approval_id),
            )
            self._conn.commit()
            updated = self._conn.execute("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,)).fetchone()
            rec = self._row_to_approval(updated)

        self.append_event(
            "APPROVAL_DECIDED",
            run_id=rec.get("run_id"),
            engagement_id=rec.get("engagement_id"),
            task_id=rec.get("task_id"),
            agent_id=rec.get("agent_id"),
            tool_exec_id=rec.get("tool_exec_id"),
            source="operator",
            payload={"approval_id": approval_id, "status": new_status, "decided_by": decided_by, "note": rec["decision_note"]},
        )
        return rec

    # ── Settings ──────────────────────────────────────────────────────────────

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
            return _json_loads(row["value_json"], default) if row else default

    def set_setting(self, key: str, value: Any) -> Any:
        now = time.time()
        clean_val = redact_payload(value, key)
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO settings (key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
                """,
                (key, _json_dumps(clean_val, redact=False), now),
            )
            self._conn.commit()
        return clean_val

    def get_all_settings(self) -> Dict[str, Any]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value_json FROM settings ORDER BY key ASC").fetchall()
            return {r["key"]: _json_loads(r["value_json"], None) for r in rows}

    def update_settings(self, mapping: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in mapping.items():
            self.set_setting(str(k), v)
        return self.get_all_settings()

    # ── Notifications ─────────────────────────────────────────────────────────

    def add_notification(
        self,
        *,
        kind: str,
        title: str,
        message: str = "",
        severity: str = "info",
        ref_kind: Optional[str] = None,
        ref_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        nid = new_id("ntf")
        now = time.time()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO notifications (
                    notification_id, kind, title, message, severity, ref_kind, ref_id,
                    engagement_id, run_id, read, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
                """,
                (
                    nid,
                    kind,
                    redact_text(title)[:240],
                    redact_text(message)[:1000],
                    severity,
                    ref_kind,
                    ref_id,
                    engagement_id,
                    run_id,
                    _json_dumps(metadata or {}),
                    now,
                ),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM notifications WHERE notification_id = ?", (nid,)).fetchone()
            return self._row_to_notification(row)

    def _row_to_notification(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "notification_id": row["notification_id"],
            "kind": row["kind"],
            "title": row["title"],
            "message": row["message"],
            "severity": row["severity"],
            "ref_kind": row["ref_kind"],
            "ref_id": row["ref_id"],
            "engagement_id": row["engagement_id"],
            "run_id": row["run_id"],
            "read": bool(row["read"]),
            "metadata": _json_loads(row["metadata_json"], {}),
            "created_at": row["created_at"],
        }

    def list_notifications(self, *, unread_only: bool = False, limit: int = 50) -> List[Dict[str, Any]]:
        where = "WHERE read = 0" if unread_only else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM notifications {where} ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
            return [self._row_to_notification(r) for r in rows]

    def mark_notification_read(self, notification_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE notifications SET read = 1 WHERE notification_id = ?",
                (notification_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    # ── Search Helpers ────────────────────────────────────────────────────────

    def search_conversations(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        q = (query or "").strip()
        if not q:
            return []
        like = f"%{q}%"
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT DISTINCT c.*
                FROM conversations c
                LEFT JOIN messages m ON m.conversation_id = c.conversation_id
                WHERE c.title LIKE ? OR c.conversation_id LIKE ? OR m.content LIKE ?
                ORDER BY c.updated_at DESC
                LIMIT ?
                """,
                (like, like, like, max(1, min(limit, 100))),
            ).fetchall()
            return [self._row_to_conversation(r) for r in rows]


_GLOBAL_PLATFORM_STORE: Optional[PlatformStore] = None
_STORE_LOCK = threading.Lock()


def get_platform_store(db_path: Optional[str | Path] = None) -> PlatformStore:
    """Return the process-wide singleton PlatformStore (or create one at db_path)."""
    global _GLOBAL_PLATFORM_STORE
    if db_path is not None:
        return PlatformStore(db_path=db_path)
    with _STORE_LOCK:
        if _GLOBAL_PLATFORM_STORE is None:
            _GLOBAL_PLATFORM_STORE = PlatformStore()
        return _GLOBAL_PLATFORM_STORE
