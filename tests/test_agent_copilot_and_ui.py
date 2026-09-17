import pytest
from fastapi.testclient import TestClient
from ui.web.app import app, copilot_state
from core.brain.autonomous_brain import AutonomousBrain
from unittest.mock import MagicMock


def test_agent_hint_endpoint():
    client = TestClient(app)
    
    # 1. Post a user hint for the agent
    resp = client.post("/api/agent/hint", json={
        "hint": "Target server runs PostgreSQL 15, test UNION SELECT NULL",
        "category": "user_advice"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "accepted"
    assert "PostgreSQL" in data["hint"]["hint"]

    # 2. Get active hints
    resp_get = client.get("/api/agent/hints")
    assert resp_get.status_code == 200
    hints_data = resp_get.json()
    assert hints_data["total"] >= 1
    assert any("PostgreSQL" in h["hint"] for h in hints_data["hints"])


def test_agent_question_and_answer_flow():
    client = TestClient(app)
    
    # Simulate Agent adding a question for the user
    q = copilot_state.add_question(
        question="Found admin panel at /secret-admin. Do you authorize high-intensity fuzzing?",
        options=["Yes, authorize", "Skip path", "Custom directive"]
    )
    assert q["id"].startswith("q_")

    # 1. User retrieves pending questions
    resp_q = client.get("/api/agent/questions")
    assert resp_q.status_code == 200
    q_data = resp_q.json()
    assert len(q_data["pending_questions"]) >= 1
    target_q = [x for x in q_data["pending_questions"] if x["id"] == q["id"]][0]
    assert "admin panel" in target_q["question"]

    # 2. User answers the question
    resp_ans = client.post("/api/agent/answer", json={
        "question_id": q["id"],
        "answer": "Yes, authorize"
    })
    assert resp_ans.status_code == 200
    ans_data = resp_ans.json()
    assert ans_data["status"] == "answered"
    assert ans_data["question"]["answer"] == "Yes, authorize"

    # 3. Verify question is no longer pending
    resp_q2 = client.get("/api/agent/questions")
    assert not any(x["id"] == q["id"] for x in resp_q2.json()["pending_questions"])


def test_autonomous_brain_ingests_user_hints():
    rm = MagicMock()
    tm = MagicMock()
    brain = AutonomousBrain(rm, tm)
    
    assert len(brain.user_hints) == 0
    brain.add_user_hint("Focus on catalog endpoint")
    assert len(brain.user_hints) == 1
    assert brain.user_hints[0]["hint"] == "Focus on catalog endpoint"
