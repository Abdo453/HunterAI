"""Session Manager — حفظ واستكمال جلسات الـ pentest"""
import json, uuid
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional


@dataclass
class Finding:
    id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    tool: str
    evidence: str
    recommendation: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class PentestSession:
    id: str
    target: str
    mode: str
    status: str
    created_at: str
    updated_at: str
    findings: List[Finding] = field(default_factory=list)
    tools_run: List[Dict] = field(default_factory=list)
    strategy: Optional[Dict] = None
    notes: str = ""


class SessionManager:
    def __init__(self, sessions_dir: str = "data/sessions"):
        self.dir = Path(sessions_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def create_session(self, target: str, mode: str) -> PentestSession:
        now = datetime.now().isoformat()
        s = PentestSession(id=str(uuid.uuid4())[:8], target=target, mode=mode,
                           status="running", created_at=now, updated_at=now)
        self.save(s)
        return s

    def save(self, session: PentestSession):
        session.updated_at = datetime.now().isoformat()
        with open(self.dir / f"{session.id}.json", "w", encoding="utf-8") as f:
            json.dump(asdict(session), f, indent=2, ensure_ascii=False)

    def load(self, sid: str) -> Optional[PentestSession]:
        p = self.dir / f"{sid}.json"
        if not p.exists(): return None
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        findings = [Finding(**x) for x in d.pop("findings", [])]
        s = PentestSession(**d)
        s.findings = findings
        return s

    def list_all(self) -> List[Dict]:
        out = []
        for p in sorted(self.dir.glob("*.json"), reverse=True):
            try:
                with open(p, encoding="utf-8") as f:
                    d = json.load(f)
                out.append({"id": d.get("id"), "target": d.get("target"),
                            "mode": d.get("mode"), "status": d.get("status"),
                            "created_at": d.get("created_at"),
                            "findings_count": len(d.get("findings", []))})
            except Exception:
                pass
        return out

    def add_finding(self, session: PentestSession, finding: Finding):
        session.findings.append(finding)
        self.save(session)

    def add_tool_result(self, session: PentestSession, agent: str, tool: str, output: str, duration: float):
        session.tools_run.append({"agent": agent, "tool": tool, "output": output[:2000],
                                  "duration": duration, "timestamp": datetime.now().isoformat()})
        self.save(session)

    def complete(self, session: PentestSession):
        session.status = "completed"
        self.save(session)
