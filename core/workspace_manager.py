"""
Workspace Manager — مدير الـ Workspace المنظم
ينشئ مجلدات منظمة لكل Target ويكتب/يقرأ ملفات الـ Output
"""
from __future__ import annotations

import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# Default workspace root next to project
WORKSPACE_ROOT = Path(os.environ.get("MISSION_WORKSPACE", "workspace"))

# Category → sub-folder mapping
CATEGORY_FOLDERS = {
    "recon": "recon",
    "nmap": "nmap",
    "port_scan": "nmap",
    "web": "web",
    "crawling": "web",
    "endpoint_discovery": "web",
    "parameter_discovery": "web",
    "js_analysis": "web",
    "ffuf": "ffuf",
    "takeover": "takeover",
    "vulnerability": "vulnerabilities",
    "xss": "vulnerabilities",
    "sqli": "vulnerabilities",
    "ssrf": "vulnerabilities",
    "idor": "vulnerabilities",
    "ssti": "vulnerabilities",
    "lfi": "vulnerabilities",
    "jwt": "vulnerabilities",
    "file_upload": "vulnerabilities",
    "browser": "browser",
    "screenshots": "screenshots",
    "evidence": "evidence",
    "reports": "reports",
    "logs": ".",
}


class WorkspaceManager:
    """
    مدير الـ Workspace — ينشئ هيكل مجلدات منظم لكل هدف وكل جلسة
    """

    def __init__(self, root: Path = WORKSPACE_ROOT):
        self.root = Path(root)

    def get_workspace_path(self, target: str, session_id: str = "") -> Path:
        """يرجع مسار الـ workspace الخاص بالـ target"""
        safe = self._safe_name(target)
        if session_id:
            return self.root / safe / session_id
        return self.root / safe

    def create_workspace(self, target: str, session_id: str = "") -> Path:
        """ينشئ مجلدات الـ workspace الكاملة للـ target"""
        ws = self.get_workspace_path(target, session_id)

        # Create all standard sub-directories
        sub_dirs = set(CATEGORY_FOLDERS.values()) | {
            "recon", "nmap", "web", "browser", "ffuf",
            "takeover", "vulnerabilities",
            "screenshots", "evidence", "reports"
        }
        for sub in sub_dirs:
            if sub != ".":
                (ws / sub).mkdir(parents=True, exist_ok=True)

        # Create agent.log
        log_file = ws / "agent.log"
        if not log_file.exists():
            log_file.write_text(
                f"# Agent Log — {target}\n"
                f"# Session: {session_id}\n"
                f"# Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n",
                encoding="utf-8"
            )

        logger.info(f"[WorkspaceManager] Created workspace at: {ws}")
        return ws

    def write_file(
        self,
        target: str,
        category: str,
        filename: str,
        content: str,
        session_id: str = "",
        append: bool = False,
    ) -> Path:
        """يكتب ملف في المجلد الصح بناءً على الـ category"""
        ws = self.get_workspace_path(target, session_id)
        sub_folder = CATEGORY_FOLDERS.get(category, category)
        folder = ws / sub_folder if sub_folder != "." else ws
        folder.mkdir(parents=True, exist_ok=True)

        file_path = folder / filename
        mode = "a" if append else "w"
        with open(file_path, mode, encoding="utf-8") as fh:
            fh.write(content)

        return file_path

    def read_file(
        self,
        target: str,
        category: str,
        filename: str,
        session_id: str = "",
    ) -> Optional[str]:
        """يقرأ ملف من الـ workspace"""
        ws = self.get_workspace_path(target, session_id)
        sub_folder = CATEGORY_FOLDERS.get(category, category)
        folder = ws / sub_folder if sub_folder != "." else ws
        file_path = folder / filename

        if not file_path.exists():
            return None
        return file_path.read_text(encoding="utf-8")

    def append_log(self, target: str, session_id: str, message: str) -> None:
        """يكتب رسالة في ملف agent.log"""
        ws = self.get_workspace_path(target, session_id)
        log_file = ws / "agent.log"
        ts = time.strftime("%H:%M:%S")
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {message}\n")

    def list_files(
        self,
        target: str,
        category: str = "",
        session_id: str = "",
    ) -> List[Dict[str, str]]:
        """يرجع قائمة الملفات الموجودة في الـ workspace"""
        ws = self.get_workspace_path(target, session_id)
        if category:
            sub_folder = CATEGORY_FOLDERS.get(category, category)
            search_path = ws / sub_folder if sub_folder != "." else ws
        else:
            search_path = ws

        files = []
        if search_path.exists():
            for f in sorted(search_path.rglob("*")):
                if f.is_file():
                    files.append({
                        "name": f.name,
                        "path": str(f),
                        "size": f.stat().st_size,
                        "category": f.parent.name,
                    })
        return files

    def get_state_file(self, target: str, session_id: str) -> Path:
        """مسار ملف الـ State JSON"""
        ws = self.get_workspace_path(target, session_id)
        return ws / "mission_state.json"

    def get_report_path(self, target: str, session_id: str) -> Path:
        """مسار التقرير النهائي"""
        ws = self.get_workspace_path(target, session_id)
        return ws / "reports" / "final_report.md"

    def workspace_summary(self, target: str, session_id: str = "") -> Dict:
        """ملخص للملفات الموجودة في الـ workspace"""
        ws = self.get_workspace_path(target, session_id)
        summary: Dict = {"workspace": str(ws), "categories": {}}

        if not ws.exists():
            return summary

        for sub in ws.iterdir():
            if sub.is_dir():
                files = list(sub.iterdir())
                summary["categories"][sub.name] = {
                    "file_count": len(files),
                    "files": [f.name for f in files if f.is_file()],
                }
        return summary

    @staticmethod
    def _safe_name(target: str) -> str:
        """تحويل الـ target لاسم مجلد آمن"""
        safe = target.replace("https://", "").replace("http://", "")
        safe = safe.replace("/", "_").replace(":", "_").replace("*", "")
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in safe)
        return safe.strip("_")[:80]
