"""
HunterAI 22-Phase Pentesting Methodology
منظمة وفق منهجية Xalgorix مع تكيف لـ HunterAI evidence tiers (E0→E5)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import time


class PhaseStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


@dataclass
class MethodologyPhase:
    phase_id: int
    name: str
    description: str
    tools: List[str] = field(default_factory=list)
    status: str = PhaseStatus.PENDING
    findings_count: int = 0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    notes: str = ""

    def start(self):
        self.status = PhaseStatus.IN_PROGRESS
        self.started_at = time.time()

    def complete(self, findings_count: int = 0):
        self.status = PhaseStatus.COMPLETED
        self.completed_at = time.time()
        self.findings_count = findings_count

    def to_dict(self) -> dict:
        return {
            "phase_id": self.phase_id,
            "name": self.name,
            "description": self.description,
            "tools": self.tools,
            "status": self.status,
            "findings_count": self.findings_count,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "notes": self.notes,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 22 Phases (منهجية Xalgorix محدثة لـ HunterAI)
# ─────────────────────────────────────────────────────────────────────────────

PHASES_22: List[MethodologyPhase] = [
    MethodologyPhase(1, " Reconnaissance", " descubrir surface目标، النطاقات الفرعية، المنافذ، والتقنيات", ["subfinder", "katana", "httpx", "nmap"]),
    MethodologyPhase(2, " Manual Vulnerability Discovery", "اكتشاف الثغرات اليدوية عبر تحليل الاستجابات والسلوك", ["burp", "manual_review"]),
    MethodologyPhase(3, " Directory and File Discovery", "كشف المسارات والملفات المخفية", ["ffuf", "gobuster", "dirsearch"]),
    MethodologyPhase(4, " CORS and Cookie Analysis", "فحص إعدادات CORS وملفات تعريف الارتباط للأمان", ["burp", "httpx"]),
    MethodologyPhase(5, " Authentication and Session Testing", "فحص آليات المصادقة وإدارة الجلسات", ["sqlmap", "burp"]),
    MethodologyPhase(6, " Injection Testing", "اختبار حقن SQL، XSS، SSRF، وغيرها", ["sqlmap", "dalfox", "nuclei"]),
    MethodologyPhase(7, " SSRF Testing", "فحص طلبات الخادم المزيفة (Server-Side Request Forgery)", ["burp", "nuclei"]),
    MethodologyPhase(8, " IDOR and Broken Access Control", "فحص التعرف غير المباشر على الكائنات والتحكم المكسور في الوصول", ["burp", "manual_review"]),
    MethodologyPhase(9, " API and GraphQL Testing", "فحص واجهات برمجة التطبيقات و GraphQL", ["katana", "burp", "nuclei"]),
    MethodologyPhase(10, " File Upload Testing", "فحص تحميل الملفات والثغرات المرتبطة", ["burp", "manual_review"]),
    MethodologyPhase(11, " Deserialization and RCE", "فschluss التسلسل غير الآمن وتنفيذ الأكواد عن بعد", ["nuclei", "manual_review"]),
    MethodologyPhase(12, " Race Conditions and Business Logic", "فحص حالات السباق والمنطق التجاري", ["burp", "manual_review"]),
    MethodologyPhase(13, " Subdomain Takeover", "فحص قدرة الاستيلاء على النطاقات الفرعية المعلقة", ["subfinder", "nuclei"]),
    MethodologyPhase(14, " Open Redirect Testing", "فحص التوجيهات المفتوحة", ["dalfox", "nuclei"]),
    MethodologyPhase(15, " Email Security Testing", "فحص أمان البريد الإلكتروني", ["theharvester", "manual_review"]),
    MethodologyPhase(16, " Cloud and Infrastructure", "فحص البنية التحتية السحابية والإعدادات الخاطئة", ["nmap", "trivy"]),
    MethodologyPhase(17, " WebSocket Testing", "فحص اتصالات WebSocket للأمان", ["burp"]),
    MethodologyPhase(18, " CMS-specific Testing", "فحص ثغرات أنظمة إدارة المحتوى المحددة", ["wpscan", "nuclei"]),
    MethodologyPhase(19, " Broken Link Hijacking and Content Spoofing", "فحص اختطاف الروابط المكسورة وانتحال المحتوى", ["manual_review"]),
    MethodologyPhase(20, " Exploit Verification", "التحقق من الاستغلال لكل نتيجة قبل الإبلاغ (Independent Verifier)", ["burp", "browser_worker"]),
    MethodologyPhase(21, " Novel Vulnerability Discovery", "اكتشاف الثغرات الجديدة beyond التemplating", ["llm_reasoning", "manual_review"]),
    MethodologyPhase(22, " Final Report", "إنشاء التقرير النهائي مع CVSS، PoC، و Remediation", ["pdf_generator", "reporting"]),
]


def get_phase(phase_id: int) -> Optional[MethodologyPhase]:
    for p in PHASES_22:
        if p.phase_id == phase_id:
            return p
    return None


def get_all_phases() -> List[MethodologyPhase]:
    return list(PHASES_22)
