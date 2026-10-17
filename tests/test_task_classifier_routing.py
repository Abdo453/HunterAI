"""Task-classifier routing: word-boundary keyword matching.

Regression guard for a real defect: the one-letter language keyword ``"r"`` was
matched with a plain ``kw in text`` substring test, so it fired inside
``user`` / ``vulnerability`` / ``through``. Combined with the English memory
scaffolding that the router appends, *almost every* message — including plain
Arabic chat — was classified as CODING, which meant the ``auto`` branch never
reached the cloud-first GENERAL route.
"""
from __future__ import annotations

from orchestrator.task_classifier import TaskClassifier, TaskType


def _c() -> TaskClassifier:
    return TaskClassifier()


def test_neutral_english_is_general_not_coding():
    # "reply", "user", "through", "assistant" used to trigger "r" and force CODING.
    res = _c().classify("Reply with a short greeting for the user through the assistant.")
    assert res.task_type is TaskType.GENERAL


def test_arabic_chat_with_english_memory_scaffolding_is_general():
    # The memory context is prefixed with English labels ("User:", "Assistant:")
    # that contain an "r"; this must not flip an Arabic chat to CODING.
    res = _c().classify("مرحبا، إزاي حالك النهارده؟", context="User: مرحبا\nAssistant: أهلاً")
    assert res.task_type is TaskType.GENERAL


def test_explicit_coding_task_is_coding():
    res = _c().classify("Write a Python script to parse a JSON file.")
    assert res.task_type is TaskType.CODING


def test_explicit_security_task_is_security():
    res = _c().classify("Analyze this SQL injection vulnerability in the login form.")
    assert res.task_type is TaskType.SECURITY


def test_standalone_language_letter_still_matches():
    # A genuine mention of the "R" language must still be detected.
    res = _c().classify("Show me an R script for statistical analysis.")
    assert res.task_type is TaskType.CODING


def test_symbol_keywords_still_match_by_substring():
    res = _c().classify("Explain C++ templates and the CI/CD pipeline.")
    assert res.task_type is TaskType.CODING
