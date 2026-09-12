"""
Test Suite for Agent Cognitive Manifesto & Programmatic Interface
"""
from __future__ import annotations

import pytest
from core.playbooks.cognitive_manifesto import CognitiveManifesto


def test_manifesto_file_and_content_retrieval():
    content = CognitiveManifesto.get_full_manifesto()
    assert len(content) > 1000
    assert "THE AGENT COGNITIVE PYRAMID" in content
    assert "Architect First, Hunter Second" in content
    assert "Zero-Noise Surgical Probing Rule" in content
    assert "The Skeptic's Creed" in content


def test_manifesto_section_lookup():
    section_intent = CognitiveManifesto.get_section("Decoding Developer Intent")
    assert "Developer Intent" in section_intent
    assert "The Naive Assumption Audit" in section_intent

    section_critic = CognitiveManifesto.get_section("Skeptic's Creed")
    assert "403 Forbidden" in section_critic
    assert "The 8-Question Gate" in section_critic


def test_manifesto_golden_rules():
    rules = CognitiveManifesto.get_golden_rules_summary()
    assert len(rules) == 8
    assert any("Zero-Noise Probing" in r for r in rules)
    assert any("Multi-Role Matrix" in r for r in rules)
    assert any("403 Forbidden is a working security control" in r for r in rules)
