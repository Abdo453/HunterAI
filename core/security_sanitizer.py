"""
HunterAI Security Sanitizer & Session Purge Engine
==================================================
Protects credentials, cookies, tokens, and PII across:
- Terminal logs and search indices
- HTTP traces and markdown reports
- Session data wipeout upon engagement completion
"""
from __future__ import annotations

import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.security_sanitizer")

COOKIE_PATTERNS = [
    r"(?i)(sessionid|connect\.sid|phpsessid|jsessionid|token|auth_token|access_token|jwt)=([a-zA-Z0-9_\-\.%+=]+)"
]

HEADER_PATTERNS = [
    (r"(?i)((?:authorization:\s*)?bearer\s+)[a-zA-Z0-9_\-\.=]+\.[a-zA-Z0-9_\-\.=]+(?:\.[a-zA-Z0-9_\-\.=/+]*)?", r"\1[MASKED_JWT_TOKEN]"),
    (r"(?i)(authorization:\s*basic\s+)[a-zA-Z0-9+/=]{8,}", r"\1[MASKED_BASIC_AUTH]"),
    (r"(?i)(cookie:\s*.*)", r"Cookie: [MASKED_COOKIE_HEADER]")
]


class SecuritySanitizer:
    """Masks secrets and session indicators from logs, evidence, and terminal output"""

    @classmethod
    def mask_cookies(cls, text: str) -> str:
        if not text:
            return ""
        masked = text
        for pat in COOKIE_PATTERNS:
            masked = re.sub(pat, r"\1=\2[:4]...[MASKED]", masked)
        return masked

    @classmethod
    def mask_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        safe = {}
        for k, v in headers.items():
            low_k = k.lower()
            if low_k in ("authorization", "cookie", "set-cookie", "x-api-key", "token"):
                if "bearer " in v.lower():
                    token_part = v[7:].strip()
                    safe[k] = f"Bearer {token_part[:6]}...[MASKED]"
                elif "basic " in v.lower():
                    safe[k] = "Basic [MASKED]"
                else:
                    safe[k] = f"{v[:4]}...[MASKED_CREDENTIAL]"
            else:
                safe[k] = v
        return safe

    @classmethod
    def mask_text(cls, text: str) -> str:
        if not text:
            return ""
        result = text
        for pat, repl in HEADER_PATTERNS:
            result = re.sub(pat, repl, result)
        result = cls.mask_cookies(result)
        return result


class SessionDataPurge:
    """Securely purges session cache, temporary traces, and sensitive evidence files"""

    @classmethod
    def purge_directory(cls, dir_path: Path) -> int:
        if not dir_path.exists():
            return 0
        count = 0
        for item in dir_path.iterdir():
            if item.is_file():
                try:
                    item.unlink()
                    count += 1
                except Exception as e:
                    logger.warning(f"Could not delete {item}: {e}")
            elif item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
                count += 1
        return count

    @classmethod
    def wipe_session(cls, session_id: str, data_dir: Optional[Path] = None) -> Dict[str, Any]:
        """Completely wipes session traces and credentials from disk"""
        base_dir = data_dir or (Path(__file__).resolve().parent.parent / "data" / "sessions" / session_id)
        wiped_items = cls.purge_directory(base_dir) if base_dir.exists() else 0
        logger.info(f"Purged session {session_id}: {wiped_items} artifacts removed.")
        return {
            "session_id": session_id,
            "status": "PURGED",
            "artifacts_removed": wiped_items
        }
