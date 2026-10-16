"""
HunterAI SAST Scanner — مسح الكود المصدري للثغرات بدون هدف مباشر
مقتبس من ميزة Xalgorix --source Code-scan
"""
from __future__ import annotations

import os
import re
import logging
import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from pathlib import Path
import json

log = logging.getLogger("hunter_ai.sast")


@dataclass
class SASTFinding:
    record_id: str
    rule_id: str
    rule_message: str
    file_path: str
    line_number: int
    severity: str
    code_snippet: str
    confidence: float
    evidence_level: str = "E0"

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "rule_id": self.rule_id,
            "rule_message": self.rule_message,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "severity": self.severity,
            "code_snippet": self.code_snippet,
            "confidence": self.confidence,
            "evidence_level": self.evidence_level,
        }


class SASTScanner:
    """
    ماسح الكود المصدري — يكتشف الثغرات في الكود بدون الحاجة لهدف مباشر.
    يعتمد على أنماط regex وقواعد Semgrep-like مبسطة.
    """

    # أنماط الثغرات الشائعة (مستوحاة من Semgrep و Bandit)
    VULNERABILITY_PATTERNS: List[Dict[str, Any]] = [
        {
            "rule_id": "python.sql_injection",
            "message": "احتمال وجود ثغرة حقن SQL في استعلام قاعدة البيانات",
            "severity": "high",
            "patterns": [
                r"execute\s*\(.*%.*\)",
                r"execute\s*\(.*\+.*\)",
                r"query\s*\(.*%.*\)",
                r"\.execute\(.*\.format\(",
            ],
            "languages": ["python"],
        },
        {
            "rule_id": "python.command_injection",
            "message": "احتمال وجود ثغرة تنفيذ أوامر نظام (Command Injection)",
            "severity": "critical",
            "patterns": [
                r"os\.system\s*\(",
                r"subprocess\.call\s*\(.*shell\s*=\s*True",
                r"subprocess\.Popen\s*\(.*shell\s*=\s*True",
                r"commands\.getoutput\s*\(",
            ],
            "languages": ["python"],
        },
        {
            "rule_id": "python.hardcoded_secret",
            "message": "سر مكتشف داخل الكود (Hardcoded Secret)",
            "severity": "high",
            "patterns": [
                r"api_key\s*=\s*['\"][^'\"]+['\"]",
                r"password\s*=\s*['\"][^'\"]+['\"]",
                r"secret\s*=\s*['\"][^'\"]+['\"]",
                r"token\s*=\s*['\"][^'\"]+['\"]",
                r"aws_access_key_id\s*=\s*['\"][^'\"]+['\"]",
            ],
            "languages": ["python", "javascript", "typescript", "java", "go"],
        },
        {
            "rule_id": "javascript.xss",
            "message": "احتمال وجود ثغرة XSS في عملية عرض المحتوى",
            "severity": "high",
            "patterns": [
                r"innerHTML\s*=",
                r"outerHTML\s*=",
                r"document\.write\s*\(",
                r"eval\s*\(",
            ],
            "languages": ["javascript", "typescript"],
        },
        {
            "rule_id": "javascript.eval_injection",
            "message": "احتمال وجود ثغرة تنفيذ أكواد JavaScript (Eval Injection)",
            "severity": "critical",
            "patterns": [
                r"eval\s*\(",
                r"setTimeout\s*\(.*\+",
                r"setInterval\s*\(.*\+",
                r"new\s+Function\s*\(",
            ],
            "languages": ["javascript", "typescript"],
        },
        {
            "rule_id": "java.sql_injection",
            "message": "احتمال وجود ثغرة حقن SQL في Java",
            "severity": "high",
            "patterns": [
                r"createStatement\s*\(.*\+",
                r"prepareStatement\s*\(.*\+",
                r"executeQuery\s*\(.*\+",
            ],
            "languages": ["java"],
        },
        {
            "rule_id": "php.sql_injection",
            "message": "احتمال وجود ثغرة حقن SQL في PHP",
            "severity": "high",
            "patterns": [
                r"mysql_query\s*\(.*\+",
                r"mysqli_query\s*\(.*\+",
                r"\$_GET\s*\[.*\]\s*\+",
                r"\$_POST\s*\[.*\]\s*\+",
            ],
            "languages": ["php"],
        },
    ]

    # امتدادات الملفات المدعومة
    SUPPORTED_EXTENSIONS = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".go": "go",
        ".php": "php",
        ".rb": "ruby",
    }

    def __init__(self):
        self.findings: List[SASTFinding] = []
        self._record_counter = 0

    def _next_id(self) -> str:
        self._record_counter += 1
        return f"sast_{self._record_counter:04d}"

    def scan_file(self, file_path: str) -> List[SASTFinding]:
        """
        مسح ملف واحد للثغرات
        """
        path = Path(file_path)
        if not path.exists():
            return []

        ext = path.suffix.lower()
        language = self.SUPPORTED_EXTENSIONS.get(ext)
        if not language:
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            log.debug(f"Cannot read {file_path}: {e}")
            return []

        findings: List[SASTFinding] = []
        lines = content.splitlines()

        for rule in self.VULNERABILITY_PATTERNS:
            if language not in rule.get("languages", []):
                continue

            for pattern in rule["patterns"]:
                try:
                    regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                except re.error:
                    continue

                for i, line in enumerate(lines, 1):
                    match = regex.search(line)
                    if match:
                        finding = SASTFinding(
                            record_id=self._next_id(),
                            rule_id=rule["rule_id"],
                            rule_message=rule["message"],
                            file_path=str(path),
                            line_number=i,
                            severity=rule["severity"],
                            code_snippet=line.strip()[:200],
                            confidence=0.7,  # SAST confidence initial
                        )
                        findings.append(finding)
                        break  # نمط واحد لكل سطر وقاعدة

        self.findings.extend(findings)
        return findings

    def scan_directory(self, directory: str) -> List[SASTFinding]:
        """
        مسح دليل كامل للثغرات
        """
        path = Path(directory)
        if not path.exists() or not path.is_dir():
            return []

        all_findings: List[SASTFinding] = []
        for file_path in path.rglob("*"):
            if file_path.is_file():
                findings = self.scan_file(str(file_path))
                all_findings.extend(findings)

        return all_findings

    def scan_git_url(self, git_url: str) -> List[SASTFinding]:
        """
        مسح مستودع Git (يحتاج git installé)
        """
        import tempfile
        import subprocess

        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", git_url, tmpdir],
                    capture_output=True,
                    timeout=120,
                    check=True,
                )
            except Exception as e:
                log.error(f"Git clone failed: {e}")
                return []

            return self.scan_directory(tmpdir)

    def get_findings(self) -> List[dict]:
        return [f.to_dict() for f in self.findings]

    def clear(self):
        self.findings.clear()
        self._record_counter = 0
