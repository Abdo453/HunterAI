"""
Task Memory — ذاكرة المهام والمحادثات
"""
import json
import uuid
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class TaskRecord:
    id: str
    timestamp: str
    user_input: str
    task_type: str
    route: str
    models_used: List[str]
    final_answer: str
    duration_seconds: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConversationMessage:
    role: str       # user | assistant | system
    content: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


class TaskMemory:
    """
    ذاكرة المهام:
    - تحفظ كل محادثة
    - تحفظ تاريخ المهام
    - توفر context للموديلات
    """

    def __init__(self, storage_dir: str = "data/memory"):
        self.dir = Path(storage_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.conversation: List[ConversationMessage] = []
        self.tasks: List[TaskRecord] = []
        self.session_id = str(uuid.uuid4())[:8]

    def add_user_message(self, content: str, metadata: dict = None):
        self.conversation.append(ConversationMessage(
            role="user", content=content, metadata=metadata or {}
        ))

    def add_assistant_message(self, content: str, model: str = "", metadata: dict = None):
        self.conversation.append(ConversationMessage(
            role="assistant", content=content,
            metadata={"model": model, **(metadata or {})}
        ))

    def add_task(self, task: TaskRecord):
        self.tasks.append(task)
        self._save_task(task)

    def clear_conversation(self):
        self.conversation.clear()

    def get_context(self, max_messages: int = 4) -> str:
        """سياق المحادثة الأخيرة للموديل"""
        recent = [
            m for m in self.conversation[-max_messages:]
            if not m.content.startswith("Error connecting to OpenRouter") and not m.content.startswith("Error:")
        ]
        if not recent:
            return ""
        lines = []
        for m in recent:
            lines.append(f"{m.role.upper()}: {m.content}")
        return "\n".join(lines)

    def get_ollama_messages(self, max_messages: int = 6) -> List[dict]:
        """تحويل المحادثة لصيغة Ollama"""
        recent = self.conversation[-max_messages:]
        return [{"role": m.role, "content": m.content} for m in recent]

    def clear_conversation(self):
        self.conversation.clear()

    def _save_task(self, task: TaskRecord):
        p = self.dir / f"{task.id}.json"
        with open(p, "w", encoding="utf-8") as f:
            json.dump(asdict(task), f, indent=2, ensure_ascii=False)

    def load_session_history(self) -> List[TaskRecord]:
        tasks = []
        for p in sorted(self.dir.glob("*.json"), reverse=True)[:20]:
            try:
                with open(p, encoding="utf-8") as f:
                    d = json.load(f)
                tasks.append(TaskRecord(**d))
            except Exception:
                pass
        return tasks

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "messages": len(self.conversation),
            "tasks_completed": len(self.tasks),
        }
