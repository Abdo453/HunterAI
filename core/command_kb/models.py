"""
نموذج الأوامر في قاعدة المعرفة القابلة للتنفيذ (EKG-CG).
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field


class CommandSafetyLevel(str, Enum):
    """مستوى أمان الأمر."""
    SAFE = "safe"               # أمر استكشاف سلبي (nmap -sn, ffuf دون payload)
    MODERATE = "moderate"       # أمر استكشاف نشط لكنه غير مدمّر (nmap -sV, sqlmap --batch)
    INTRUSIVE = "intrusive"     # أمر استغلال أو رفع صلاحيات (sqlmap --os-shell, Metasploit)
    DESTRUCTIVE = "destructive" # أمر قد يسبب DoS أو تلف بيانات (لم يسمح به افتراضياً)


class CommandCategory(str, Enum):
    """فئة الأمر."""
    RECON = "recon"             # اكتشاف الخدمات والمنافذ
    ENUMERATION = "enumeration" #Enumerate الدلائل والمعلمات
    VULN_SCAN = "vuln_scan"     # مسح الثغرات (nuclei, nuclei templates)
    EXPLOIT = "exploit"         # استغلال ثغرة مؤكدة
    PRIVESC = "priv_esc"        # رفع صلاحيات
    POST_EXPLOIT = "post_exploit" # ما بعد الاستغلال
    UTILITY = "utility"         # أدوات مساعدة (curl, whois, dig)


class CommandEntry(BaseModel):
    """
    أمر موثق مسبقاً في قاعدة المعرفة.
    كل أمر يُنفذ بواسطة Executor يجب أن يكون موجوداً هنا،
    ويمر عبر فحص توافق البيئة قبل التنفيذ.
    """
    id: str = Field(default_factory=lambda: f"CMD-{uuid.uuid4().hex[:8]}")
    tool: str                                  # nmap, ffuf, sqlmap, curl, ...
    command_template: str                      # الأمر مع placeholders مثل {target}, {port}, {url}
    description: str
    category: CommandCategory
    safety_level: CommandSafetyLevel = CommandSafetyLevel.MODERATE

    # متطلبات البيئة التي يجب أن تتوافر قبل التنفيذ
    required_tools: List[str] = Field(default_factory=list)   # أدوات نظام يجب أن تكون مثبتة
    required_ports: List[int] = Field(default_factory=list)   # منافذ يجب أن تكون مفتوحة
    required_endpoints: List[str] = Field(default_factory=list) # نقاط نهاية يجب أن تكون مكتشفة
    required_privileges: List[str] = Field(default_factory=list) # صلاحيات مطلوبة (root, sudo, ...)

    # علامات للتصنيف والبحث
    tags: List[str] = Field(default_factory=list)

    # metadata
    created_at: float = Field(default_factory=time.time)
    validated_count: int = 0
    last_validated: Optional[float] = None
    notes: str = ""

    def render(self, **kwargs) -> str:
        """
        توليد الأمر النهائي بتعويض placeholders بالقيم الفعلية.
        مثال: render(target="10.10.10.10") -> "nmap -sV 10.10.10.10"
        """
        try:
            return self.command_template.format(**kwargs)
        except KeyError as exc:
            missing = str(exc).strip("'")
            raise ValueError(
                f"Missing placeholder value for command {self.id}: {missing}"
            ) from exc

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
