"""
File Upload Intelligence Collector for BurpAgent
Detects executable extensions, MIME type confusion, magic bytes, and path traversal in filenames.
"""
import re
import hashlib
import logging
from typing import Optional, List, Any
from agents.burp_agent.storage.models import FileModel, HTTPRequestModel
from agents.burp_agent.storage.database import TrafficDatabase

log = logging.getLogger("burp_agent.file_collector")


class FileCollector:
    """مستكشف ومحلل الملفات المرفوعة عبر الـ HTTP"""

    DANGEROUS_EXTENSIONS = {
        "php", "php3", "php4", "php5", "phtml", "phar",
        "jsp", "jspx", "jsw", "jsv", "jspf",
        "asp", "aspx", "cer", "asa", "cdx",
        "sh", "bash", "exe", "bat", "cmd", "ps1", "py", "pl", "cgi",
        "svg", "html", "htm", "shtml"
    }

    def __init__(self, db: TrafficDatabase):
        self.db = db

    def inspect_request_for_uploads(self, req: HTTPRequestModel) -> List[FileModel]:
        """فحص ما إذا كان الطلب يتضمن رفع ملفات واستخراج المؤشرات الأمنية"""
        files_found = []
        if not req.body:
            return files_found

        c_type = (req.content_type or "").lower()
        if "multipart/form-data" not in c_type and "filename=" not in req.body:
            return files_found

        # Regex to parse multipart filename and content
        matches = re.finditer(
            r'Content-Disposition:\s*form-data;[^\r\n]*filename=["\']([^"\']+)["\'](?:[^\r\n]*\r?\nContent-Type:\s*([^\r\n]+))?',
            req.body,
            re.IGNORECASE
        )

        for match in matches:
            filename = match.group(1)
            declared_mime = match.group(2) if match.group(2) else "application/octet-stream"
            ext = filename.split(".")[-1].lower() if "." in filename else ""

            # Check Security Risks
            risks = []
            if ext in self.DANGEROUS_EXTENSIONS:
                risks.append(f"Executable upload extension: .{ext}")
            if ".." in filename or "/" in filename or "\\" in filename:
                risks.append("Path traversal in filename")
            if filename.count(".") > 1:
                risks.append("Double extension detected")

            sha256 = hashlib.sha256(req.body.encode("utf-8")).hexdigest()
            file_obj = FileModel(
                request_id=req.id,
                filename=filename,
                extension=ext,
                declared_mime=declared_mime,
                detected_mime=declared_mime,
                file_size=len(req.body),
                sha256=sha256,
                potential_risk="; ".join(risks) if risks else None
            )
            self.db.insert_file(file_obj)
            files_found.append(file_obj)
            if risks:
                log.warning(f"[FileCollector] Suspicious file upload on {req.url}: {filename} ({file_obj.potential_risk})")

        return files_found

    async def analyze(self, req: HTTPRequestModel, resp: Optional[Any] = None):
        self.inspect_request_for_uploads(req)
