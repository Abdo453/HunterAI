"""
Unit Tests for Structured KnowledgeStore
Tests: Schema validation, canonical seeding, topic querying, and signal-based knowledge retrieval.
"""
import pytest
from pathlib import Path

from core.learning.knowledge_store import KnowledgeStore, KnowledgeItem


class TestKnowledgeStore:
    def test_knowledge_store_initialization_and_seeding(self, tmp_path):
        db_file = tmp_path / "test_knowledge.sqlite3"
        store = KnowledgeStore(db_path=db_file)

        items = store.get_all_items()
        assert len(items) >= 6

        # Check canonical BOLA entry
        bola = store.get_item("authz_001")
        assert bola is not None
        assert bola.topic == "authorization"
        assert "resource_identifier" in bola.signals
        assert "baseline_response_200" in bola.evidence_requirements

    def test_query_by_signals(self, tmp_path):
        db_file = tmp_path / "test_knowledge.sqlite3"
        store = KnowledgeStore(db_path=db_file)

        # Signals observed in HTTP traffic: numeric_id + multi_tenant
        observed = ["numeric_id", "multi_tenant", "authenticated_request"]
        matches = store.query_by_signals(observed)

        assert len(matches) > 0
        top_match = matches[0]
        assert top_match.id == "authz_001"  # Highest signal overlap

    def test_save_and_retrieve_custom_knowledge_item(self, tmp_path):
        db_file = tmp_path / "test_knowledge.sqlite3"
        store = KnowledgeStore(db_path=db_file)

        custom = KnowledgeItem(
            id="graphql_001",
            item_type="vulnerability",
            topic="graphql",
            name="GraphQL Introspection Enabled",
            signals=["graphql_endpoint", "introspection_query"],
            verification_strategy="Send __schema query to endpoint",
            evidence_requirements=["schema_json_dump"]
        )
        store.save_item(custom)

        retrieved = store.get_item("graphql_001")
        assert retrieved is not None
        assert retrieved.name == "GraphQL Introspection Enabled"

        by_topic = store.get_by_topic("graphql")
        assert len(by_topic) == 1
        assert by_topic[0].id == "graphql_001"
