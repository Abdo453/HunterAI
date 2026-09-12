"""
Experience Store & Episodic Investigation Memory
Stores complete investigation episodes, actions attempted, outcomes,
and extracted lessons for past experience retrieval.
"""
import sqlite3
import json
import time
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("core.learning.experience_store")

DATA_DIR = Path("data/experience_db")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "pentest_experiences.sqlite3"


class InvestigationEpisode(BaseModel):
    """حلقة تجربة استقصائية كاملة"""
    episode_id: str
    target: str
    topic: str = "general"
    initial_state: Dict[str, Any] = Field(default_factory=dict)
    hypotheses_evaluated: List[Dict[str, Any]] = Field(default_factory=list)
    actions_taken: List[str] = Field(default_factory=list)
    observations_recorded: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_collected: List[str] = Field(default_factory=list)
    final_outcome: str = "INCONCLUSIVE"  # SUCCESS_CONFIRMED, REFUTED, INCONCLUSIVE
    decision_regret_score: float = 0.0
    lessons: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ExperienceStore:
    """
    قاعدة بيانات التجارب السابقة (Experience Database):
    تحفظ نتائج التحقيقات السابقة وتمكن الـ Agent من استرجاع ما نجح وما فشل
    """

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS episodes (
                    episode_id TEXT PRIMARY KEY,
                    target TEXT,
                    topic TEXT,
                    initial_state TEXT,
                    hypotheses TEXT,
                    actions_taken TEXT,
                    observations TEXT,
                    evidence TEXT,
                    final_outcome TEXT,
                    decision_regret REAL,
                    lessons TEXT,
                    created_at REAL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exp_topic ON episodes(topic)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_exp_outcome ON episodes(final_outcome)")
            conn.commit()

    def save_episode(self, episode: InvestigationEpisode):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO episodes (
                    episode_id, target, topic, initial_state, hypotheses,
                    actions_taken, observations, evidence, final_outcome,
                    decision_regret, lessons, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                episode.episode_id,
                episode.target,
                episode.topic,
                json.dumps(episode.initial_state),
                json.dumps(episode.hypotheses_evaluated),
                json.dumps(episode.actions_taken),
                json.dumps(episode.observations_recorded),
                json.dumps(episode.evidence_collected),
                episode.final_outcome,
                episode.decision_regret_score,
                json.dumps(episode.lessons),
                episode.created_at
            ))
            conn.commit()

    def get_episode(self, episode_id: str) -> Optional[InvestigationEpisode]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM episodes WHERE episode_id = ?", (episode_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_episode(row)

    def get_recent_episodes(self, limit: int = 10) -> List[InvestigationEpisode]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM episodes ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [self._row_to_episode(r) for r in rows]

    def find_similar_episodes(self, topic: str, outcome: Optional[str] = None) -> List[InvestigationEpisode]:
        """استرجاع التجارب السابقة المشابهة حسب الموضوع والنتيجة"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if outcome:
                cursor.execute(
                    "SELECT * FROM episodes WHERE topic = ? AND final_outcome = ? ORDER BY created_at DESC",
                    (topic, outcome)
                )
            else:
                cursor.execute(
                    "SELECT * FROM episodes WHERE topic = ? ORDER BY created_at DESC",
                    (topic,)
                )
            rows = cursor.fetchall()
            return [self._row_to_episode(r) for r in rows]

    def _row_to_episode(self, row) -> InvestigationEpisode:
        return InvestigationEpisode(
            episode_id=row[0],
            target=row[1],
            topic=row[2],
            initial_state=json.loads(row[3]),
            hypotheses_evaluated=json.loads(row[4]),
            actions_taken=json.loads(row[5]),
            observations_recorded=json.loads(row[6]),
            evidence_collected=json.loads(row[7]),
            final_outcome=row[8],
            decision_regret_score=row[9],
            lessons=json.loads(row[10]),
            created_at=row[11]
        )
