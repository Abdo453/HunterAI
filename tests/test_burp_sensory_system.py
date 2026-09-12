"""
Comprehensive Unit & Integration Tests for BurpAgent Sensory System
Tests:
- Request Normalizer (strips bloat, preserves LLM context window)
- Response Normalizer (detects error signatures, SHA256 hashes)
- Artifact Collector (uploads & downloads with MIME and SHA256)
- Cookie & Identity Collector (session cookies & JWTs)
- Unified Evidence Store (cryptographic tamper-evident storage)
- Sensory Event Bus (asynchronous pub/sub streaming)
- Burp Extension Bridge (end-to-end sensory ingestion)
- REST APIs (/api/burp/ingest, /api/burp/artifacts, /api/burp/evidence, /api/burp/sensory_events)
"""
import pytest
import httpx
from pathlib import Path

from agents.burp_agent.normalization.request_normalizer import RequestNormalizer
from agents.burp_agent.normalization.response_normalizer import ResponseNormalizer
from agents.burp_agent.collectors.artifact_collector import ArtifactCollector
from agents.burp_agent.collectors.cookie_collector import CookieCollector
from agents.burp_agent.evidence.evidence_model import UnifiedEvidenceStore, UnifiedEvidence, BurpEvidenceType
from agents.burp_agent.streaming.sensory_event_bus import SensoryEventBus, SensoryEvent, SensoryMessage
from agents.burp_agent.extension.burp_extension_bridge import BurpExtensionBridge
from ui.web.app import app


class TestBurpSensorySystem:
    def test_request_normalizer_extracts_params_and_signals(self):
        url = "https://shop.corp.internal/api/v2/items/105?filter=recent&sort=price"
        headers = {
            "Host": "shop.corp.internal",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID",
            "Content-Type": "application/json"
        }
        body = '{"search_term": "laptop", "in_stock": true}'

        norm = RequestNormalizer.normalize("POST", url, headers, body)

        assert norm.method == "POST"
        assert norm.path == "/api/v2/items/105"
        assert norm.query_params["filter"] == "recent"
        assert norm.query_params["sort"] == "price"
        assert norm.body_params["search_term"] == "laptop"
        assert "bearer_token" in norm.signals
        assert "jwt_structure" in norm.signals
        assert "numeric_id" in norm.signals
        assert "POST /api/v2/items/105" in norm.summary
        assert len(norm.sha256) == 64

    def test_response_normalizer_detects_database_errors_and_hashes(self):
        body = "Database error: syntax error at or near 'admin'' (PostgreSQL error 42601)"
        headers = {"Content-Type": "text/html; charset=utf-8"}

        norm = ResponseNormalizer.normalize(500, headers, body)

        assert norm.status_code == 500
        assert norm.is_error is True
        assert norm.error_signature == "postgresql"
        assert "postgresql_detected" in norm.signals
        assert len(norm.sha256) == 64

    def test_artifact_collector_captures_uploads_and_downloads(self, tmp_path):
        db_file = tmp_path / "test_artifacts.sqlite3"
        collector = ArtifactCollector(db_path=db_file)

        # 1. Upload Test
        multipart_body = (
            '--boundary123\r\n'
            'Content-Disposition: form-data; name="avatar"; filename="shell.php"\r\n'
            'Content-Type: application/x-php\r\n\r\n'
            '<?php echo "test"; ?>\r\n'
            '--boundary123--'
        )
        uploads = collector.capture_upload("tx_100", "multipart/form-data; boundary=boundary123", multipart_body)
        assert len(uploads) == 1
        assert uploads[0].filename == "shell.php"
        assert uploads[0].direction == "upload"
        assert uploads[0].mime_type == "application/x-php"

        # 2. Download Test
        resp_headers = {"Content-Disposition": 'attachment; filename="statement.pdf"'}
        download = collector.capture_download("tx_101", "application/pdf", resp_headers, "%PDF-1.4 sample content")
        assert download is not None
        assert download.filename == "statement.pdf"
        assert download.direction == "download"

        # 3. Retrieve All
        all_artifacts = collector.get_all_artifacts()
        assert len(all_artifacts) == 2

    def test_cookie_collector_tracks_jwt_and_session_state(self):
        collector = CookieCollector()

        req_headers = {
            "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG69pk",
            "Cookie": "PHPSESSID=s891238912739; user=admin"
        }
        resp_headers = {
            "Set-Cookie": "remember_token=abc123xyz; Path=/; Secure; HttpOnly"
        }

        tokens = collector.inspect_transaction("tx_200", "https://api.corp.local", req_headers, resp_headers)
        assert len(tokens) >= 3

        token_names = [t.token_name for t in tokens]
        assert "Authorization" in token_names
        assert "PHPSESSID" in token_names
        assert "remember_token" in token_names

    def test_unified_evidence_store_crud(self, tmp_path):
        db_file = tmp_path / "test_evid.sqlite3"
        store = UnifiedEvidenceStore(db_path=db_file)

        evid = UnifiedEvidence(
            id="EVID-TEST-01",
            evidence_type=BurpEvidenceType.DIFF,
            source="Burp_Repeater",
            sha256="abc123sha256hash",
            parent_transaction_id="tx_300",
            summary="Differential behavior between 1=1 and 1=2 verified",
            metadata={"diff_delta_bytes": 1420}
        )
        store.store_evidence(evid)

        retrieved = store.get_evidence("EVID-TEST-01")
        assert retrieved is not None
        assert retrieved.evidence_type == BurpEvidenceType.DIFF
        assert retrieved.parent_transaction_id == "tx_300"

        by_tx = store.get_by_transaction("tx_300")
        assert len(by_tx) == 1

    @pytest.mark.asyncio
    async def test_sensory_event_bus_pub_sub(self):
        bus = SensoryEventBus()
        received_messages = []

        async def handler(msg: SensoryMessage):
            received_messages.append(msg)

        bus.subscribe(SensoryEvent.HTTP_REQUEST_OBSERVED, handler)

        test_msg = SensoryMessage(
            event=SensoryEvent.HTTP_REQUEST_OBSERVED,
            transaction_id="tx_400",
            timestamp=12345.0,
            summary="GET /login",
            data={"method": "GET"}
        )
        await bus.publish(SensoryEvent.HTTP_REQUEST_OBSERVED, test_msg)

        assert len(received_messages) == 1
        assert received_messages[0].transaction_id == "tx_400"
        assert received_messages[0].summary == "GET /login"

    @pytest.mark.asyncio
    async def test_burp_extension_bridge_end_to_end(self, tmp_path):
        bus = SensoryEventBus()
        evid_store = UnifiedEvidenceStore(db_path=tmp_path / "evid.sqlite3")
        art_coll = ArtifactCollector(db_path=tmp_path / "art.sqlite3")
        cookie_coll = CookieCollector()

        bridge = BurpExtensionBridge(
            event_bus=bus,
            evidence_store=evid_store,
            artifact_collector=art_coll,
            cookie_collector=cookie_coll
        )

        multipart_upload = (
            '--boundary\r\n'
            'Content-Disposition: form-data; name="doc"; filename="resume.pdf"\r\n'
            'Content-Type: application/pdf\r\n\r\n'
            '%PDF-dummy-data\r\n'
            '--boundary--'
        )

        receipt = await bridge.ingest_transaction(
            method="POST",
            url="https://portal.bank.org/api/v1/documents",
            request_headers={"Content-Type": "multipart/form-data; boundary=boundary", "Authorization": "Bearer token123"},
            request_body=multipart_upload,
            response_status=201,
            response_headers={"Content-Type": "application/json", "Set-Cookie": "doc_session=xyz"},
            response_body='{"status": "uploaded", "doc_id": 992}',
            tool="repeater"
        )

        assert receipt.status == "INGESTED_AND_BROADCAST"
        assert receipt.artifacts_captured >= 1
        assert receipt.tokens_captured >= 2
        assert "bearer_token" in receipt.signals_detected

        # Verify evidence was persisted
        evids = evid_store.get_by_transaction(receipt.transaction_id)
        assert len(evids) == 2  # Request + Response evidence

    @pytest.mark.asyncio
    async def test_rest_api_burp_sensory_endpoints(self):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. Ingest via REST
            payload = {
                "method": "GET",
                "url": "https://api.testlab.net/users/42",
                "request_headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc"},
                "response_status": 200,
                "response_body": '{"id": 42, "name": "Alice"}',
                "tool": "proxy"
            }
            res_ingest = await client.post("/api/burp/ingest", json=payload)
            assert res_ingest.status_code == 200
            receipt = res_ingest.json()["receipt"]
            assert receipt["status"] == "INGESTED_AND_BROADCAST"

            # 2. Check Evidence API
            res_evid = await client.get("/api/burp/evidence")
            assert res_evid.status_code == 200
            assert res_evid.json()["total"] >= 2

            # 3. Check Artifacts API
            res_art = await client.get("/api/burp/artifacts")
            assert res_art.status_code == 200
            assert "artifacts" in res_art.json()

            # 4. Check Sensory Events API
            res_events = await client.get("/api/burp/sensory_events")
            assert res_events.status_code == 200
            assert res_events.json()["total"] >= 2
