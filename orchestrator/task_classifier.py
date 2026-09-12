"""
Task Classifier — تصنيف المهام (CODING / SECURITY / MIXED)
يحدد نوع المهمة لتوجيه الـ Router الصحيح
"""
import re
from enum import Enum
from dataclasses import dataclass
from typing import List, Tuple


class TaskType(str, Enum):
    CODING = "CODING"
    SECURITY = "SECURITY"
    MIXED = "MIXED"
    GENERAL = "GENERAL"


@dataclass
class ClassificationResult:
    task_type: TaskType
    confidence: float          # 0.0 - 1.0
    reasoning: str
    security_score: float
    coding_score: float
    suggested_models: List[str]
    use_local_first: bool


# ─── كلمات مفتاحية للتصنيف ───────────────────────────────────
SECURITY_KEYWORDS = {
    # هجمات
    "pentest", "penetration", "exploit", "vulnerability", "vuln", "cve",
    "injection", "sqli", "sql injection", "xss", "xxe", "ssrf", "rce",
    "lfi", "rfi", "idor", "csrf", "ssti",
    # أدوات
    "nmap", "nuclei", "burp", "metasploit", "sqlmap", "nikto",
    "gobuster", "ffuf", "hydra", "hashcat", "john", "wireshark",
    "masscan", "rustscan", "subfinder", "amass", "shodan",
    # مصطلحات
    "recon", "reconnaissance", "payload", "shellcode", "reverse shell",
    "bind shell", "privilege escalation", "privesc", "lateral movement",
    "persistence", "bypass", "evasion", "obfuscation",
    "ctf", "capture the flag", "flag", "hack", "hacking",
    "red team", "blue team", "purple team",
    "malware", "ransomware", "rootkit", "backdoor", "trojan",
    "phishing", "osint", "footprint", "enumeration",
    "fuzzing", "brute force", "password crack", "hash",
    "network scan", "port scan", "service detection",
    "web application", "api security", "authentication bypass",
    "ثغرة", "اختراق", "أمن", "هجوم", "اكسبلويت"
}

CODING_KEYWORDS = {
    # لغات
    "python", "javascript", "typescript", "java", "c++", "c#", "go", "rust",
    "php", "ruby", "kotlin", "swift", "r", "matlab", "bash", "powershell",
    # مصطلحات
    "code", "script", "function", "class", "algorithm", "api",
    "debug", "fix", "error", "exception", "bug", "refactor",
    "unit test", "testing", "framework", "library", "module",
    "database", "sql", "mongodb", "redis", "orm",
    "docker", "kubernetes", "ci/cd", "git", "devops",
    "async", "thread", "concurrent", "regex", "parser",
    "loop", "array", "list", "dict", "json", "xml", "yaml",
    "اكتب", "برمجة", "كود", "سكربت", "دالة"
}


class TaskClassifier:
    """
    يصنف المهمة لتحديد:
    1. نوعها (CODING/SECURITY/MIXED/GENERAL)
    2. أي موديلات محلية تُستخدم
    3. هل نحتاج API خارجي
    """

    def classify(self, user_input: str, context: str = "") -> ClassificationResult:
        text = (user_input + " " + context).lower()

        # حساب النقاط
        sec_hits = [kw for kw in SECURITY_KEYWORDS if kw in text]
        cod_hits = [kw for kw in CODING_KEYWORDS if kw in text]

        sec_score = min(1.0, len(sec_hits) / 3.0)
        cod_score = min(1.0, len(cod_hits) / 3.0)

        # تحديد النوع — لو coding keywords كتير, مش security by default
        # "write python tool" → CODING حتى لو فيه nmap
        cod_dominant = cod_score > 0 and cod_score >= sec_score * 0.8

        if sec_score >= 0.6 and cod_score >= 0.4:
            task_type = TaskType.MIXED
            confidence = (sec_score + cod_score) / 2
        elif sec_score >= 0.5 and not cod_dominant:
            task_type = TaskType.SECURITY
            confidence = sec_score
        elif cod_score >= 0.3 or cod_dominant:
            task_type = TaskType.CODING
            confidence = cod_score
        elif sec_score >= 0.3:
            task_type = TaskType.SECURITY
            confidence = sec_score
        else:
            # Fallback — تحليل السياق
            task_type = self._context_classify(text)
            confidence = 0.5

        # اختيار الموديلات
        suggested, use_local_first = self._suggest_models(task_type, sec_score, cod_score)

        reasoning = self._build_reasoning(task_type, sec_hits, cod_hits)

        return ClassificationResult(
            task_type=task_type,
            confidence=confidence,
            reasoning=reasoning,
            security_score=sec_score,
            coding_score=cod_score,
            suggested_models=suggested,
            use_local_first=use_local_first
        )

    def _context_classify(self, text: str) -> TaskType:
        """Heuristic fallback"""
        if any(w in text for w in ["analyze", "scan", "find", "detect", "check vulnerability",
                                    "حلل", "افحص", "ابحث"]):
            return TaskType.SECURITY
        if any(w in text for w in ["write", "create", "build", "make", "implement",
                                    "اكتب", "انشئ", "اعمل"]):
            return TaskType.CODING
        return TaskType.GENERAL

    def _suggest_models(self, task_type: TaskType, sec: float, cod: float) -> Tuple[List[str], bool]:
        """
        تحديد أي موديلات تُستخدم وبأي ترتيب
        Returns: (models_list, use_local_first)
        """
        if task_type == TaskType.SECURITY:
            return (
                [
                    "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",  # أول
                    "xploiter/pentester:latest",                               # تاني
                ],
                True  # محلي أولاً
            )
        elif task_type == TaskType.CODING:
            return (
                ["qwen2.5-coder:14b"],  # محلي
                True
            )
        elif task_type == TaskType.MIXED:
            # Security API + Qwen محلي بالتوازي
            if sec > cod:
                return (
                    ["WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
                     "qwen2.5-coder:14b"],
                    True
                )
            else:
                return (
                    ["qwen2.5-coder:14b",
                     "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"],
                    True
                )
        else:  # GENERAL
            return (["qwen2.5-coder:14b"], True)

    def _build_reasoning(self, task_type: TaskType, sec_hits: list, cod_hits: list) -> str:
        parts = [f"Task classified as: {task_type.value}"]
        if sec_hits:
            parts.append(f"Security signals: {', '.join(sec_hits[:5])}")
        if cod_hits:
            parts.append(f"Coding signals: {', '.join(cod_hits[:5])}")
        return " | ".join(parts)
