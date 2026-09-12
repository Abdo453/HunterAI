"""
Artifact & File Collector for BurpAgent
Extracts and registers all files transferred via Burp Suite:
- Uploads (multipart/form-data, binary POSTs)
- Downloads (Content-Disposition attachments, PDFs, documents, images)
Computes SHA256 fingerprints, classifies MIME types, and extracts text content when applicable.
"""
import os
import re
import hashlib
import sqlite3
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

log = logging.getLogger("burp_agent.collectors.artifact")

ARTIFACTS_DIR = Path("data/artifacts")
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path("data/learning/artifacts_metadata.sqlite3")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


class CapturedArtifact(BaseModel):
    """بيانات وصفية للملف أو الأرتيفاكت الملتقط عبر Burp Suite"""
    artifact_id: str
    filename: str
    mime_type: str
    size_bytes: int
    sha256: str
    direction: str                     # "upload" | "download"
    source_transaction_id: str
    is_textual: bool = False
    extracted_text_snippet: Optional[str] = None
    saved_file_path: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ArtifactCollector:
    """
    مجمع الأرتيفاكت والملفات:
    يلتقط الملفات الصادرة والواردة بدون إغراق الـ LLM بالبيانات الثنائية
    """

    TEXTUAL_MIMES = {
        "text/plain", "text/html", "application/json", "application/xml",
        "text/xml", "text/csv", "application/javascript", "text/javascript"
    }

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS captured_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    filename TEXT,
                    mime_type TEXT,
                    size_bytes INTEGER,
                    sha256 TEXT,
                    direction TEXT,
                    source_transaction_id TEXT,
                    is_textual INTEGER,
                    extracted_text_snippet TEXT,
                    saved_file_path TEXT,
                    metadata TEXT
                )
            """)
            conn.commit()

    def capture_upload(
        self,
        transaction_id: str,
        content_type: str,
        request_body: str
    ) -> List[CapturedArtifact]:
        """فحص والتقاط ملفات الرفع (Uploads) من الطلب"""
        artifacts = []
        if not request_body or "multipart/form-data" not in (content_type or "").lower():
            return artifacts

        matches = re.finditer(
            r'Content-Disposition:\s*form-data;[^\r\n]*filename=["\']([^"\']+)["\'](?:[^\r\n]*\r?\nContent-Type:\s*([^\r\n]+))?',
            request_body,
            re.IGNORECASE
        )

        for match in matches:
            filename = match.group(1)
            declared_mime = (match.group(2) or "application/octet-stream").strip()
            # Approximate content or extract text
            sha256 = hashlib.sha256(request_body.encode("utf-8")).hexdigest()
            size = len(request_body.encode("utf-8"))
            is_textual = any(m in declared_mime.lower() for m in self.TEXTUAL_MIMES)

            art_id = f"art_up_{sha256[:8]}"
            snippet = request_body[:500] if is_textual else None

            artifact = CapturedArtifact(
                artifact_id=art_id,
                filename=filename,
                mime_type=declared_mime,
                size_bytes=size,
                sha256=sha256,
                direction="upload",
                source_transaction_id=transaction_id,
                is_textual=is_textual,
                extracted_text_snippet=snippet,
                metadata={"declared_filename": filename}
            )
            self._save_artifact(artifact)
            artifacts.append(artifact)

        return artifacts

    def capture_download(
        self,
        transaction_id: str,
        content_type: str,
        response_headers: Dict[str, str],
        response_body: str
    ) -> Optional[CapturedArtifact]:
        """فحص والتقاط ملفات التنزيل (Downloads) من الاستجابة"""
        # Check Content-Disposition attachment
        disposition = ""
        for h, v in response_headers.items():
            if h.lower() == "content-disposition":
                disposition = v
                break

        filename = "downloaded_file"
        if "filename=" in disposition:
            m = re.search(r'filename=["\']?([^"\';\r\n]+)["\']?', disposition)
            if m:
                filename = m.group(1).strip()
        elif any(ext in content_type.lower() for ext in ["pdf", "zip", "octet-stream", "csv", "json"]):
            filename = f"file_{transaction_id[:6]}"
        else:
            return None  # Normal web page response

        body_bytes = response_body.encode("utf-8") if isinstance(response_body, str) else response_body
        sha256 = hashlib.sha256(body_bytes).hexdigest()
        size = len(body_bytes)
        is_textual = any(m in content_type.lower() for m in self.TEXTUAL_MIMES)

        art_id = f"art_down_{sha256[:8]}"
        snippet = response_body[:500] if is_textual and isinstance(response_body, str) else None

        artifact = CapturedArtifact(
            artifact_id=art_id,
            filename=filename,
            mime_type=content_type,
            size_bytes=size,
            sha256=sha256,
            direction="download",
            source_transaction_id=transaction_id,
            is_textual=is_textual,
            extracted_text_snippet=snippet,
            metadata={"disposition": disposition}
        )
        self._save_artifact(artifact)
        return artifact

    def _save_artifact(self, artifact: CapturedArtifact):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO captured_artifacts (
                    artifact_id, filename, mime_type, size_bytes, sha256,
                    direction, source_transaction_id, is_textual,
                    extracted_text_snippet, saved_file_path, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                artifact.artifact_id,
                artifact.filename,
                artifact.mime_type,
                artifact.size_bytes,
                artifact.sha256,
                artifact.direction,
                artifact.source_transaction_id,
                1 if artifact.is_textual else 0,
                artifact.extracted_text_snippet,
                artifact.saved_file_path,
                json.dumps(artifact.metadata)
            ))
            conn.commit()

    def get_all_artifacts(self, limit: int = 50) -> List[CapturedArtifact]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM captured_artifacts ORDER BY size_bytes DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            return [
                CapturedArtifact(
                    artifact_id=r[0],
                    filename=r[1],
                    mime_type=r[2],
                    size_bytes=r[3],
                    sha256=r[4],
                    direction=r[5],
                    source_transaction_id=r[6],
                    is_textual=bool(r[7]),
                    extracted_text_snippet=r[8],
                    saved_file_path=r[9],
                    metadata=json.loads(r[10])
                )
                for r in rows
            ]
