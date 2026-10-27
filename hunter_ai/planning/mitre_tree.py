"""
HunterAI Guided Reasoning — MITRE ATT&CK Deterministic Task Tree
================================================================

شجرة مهام حتمية مستوحاة من MITRE ATT&CK لحصر تفكير الوكيل في تكتيكات
وتقنيات وإجراءات (TTPs) محددة، ومنعه من اتباع مسارات غير منتجة.

يستخدم الشجرة لتوجيه كل وكيل خلال مراحل الهجوم المعروفة، مع معرّفات TECHNIQUE
مثل T1190 (Exploitation of Public-Facing Application)، T1078 (Valid Accounts)، إلخ.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MITRENode:
    """عقدة في شجرة ATT&CK — تكتيك أو تقنية أو إجراء."""
    technique_id: str  # مثلاً: T1190, T1078, T1021
    name: str
    tactic: str  # reconnaissance, resource-development, initial-access, ...
    description: str
    commands: List[str] = field(default_factory=list)  # الأوامر المسموحة لهذه العقدة
    children: Dict[str, "MITRENode"] = field(default_factory=dict)
    parent: Optional["MITRENode"] = None
    verified: bool = False  # هل تم التحقق من هذه التقنية بنجاح؟
    attempts: int = 0
    successes: int = 0

    def add_child(self, child: "MITRENode") -> None:
        child.parent = self
        self.children[child.technique_id] = child

    def success_rate(self) -> float:
        if self.attempts == 0:
            return 0.0
        return self.successes / self.attempts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "commands": self.commands,
            "verified": self.verified,
            "attempts": self.attempts,
            "successes": self.successes,
            "success_rate": self.success_rate(),
            "children": {k: v.to_dict() for k, v in self.children.items()},
        }


class MITREATTACKTree:
    """
    شجرة ATT&CK الحتمية — توجه الوكلاء عبر تقنيات هجوم محددة
    وتمنعهم من اتباع مسارات غير منتجة أو غير مصرح بها.
    """

    def __init__(self):
        self.root = MITRENode(
            technique_id="ROOT",
            name="Root",
            tactic="root",
            description="نقطة بداية شجرة ATT&CK",
        )
        self._build_default_tree()
        self._current_path: List[str] = []  # مسار التقنيات الحالية

    def _build_default_tree(self) -> None:
        """بناء شجرة ATT&CK الافتراضية مع التقنيات الشائعة في اختبار الاختراق الويب."""

        # Reconnaissance (TA0043)
        recon = MITRENode(
            technique_id="T1592",
            name="Host Reconnaissance",
            tactic="reconnaissance",
            description="جمع معلومات عن المضيف المستهدف (بورتات، خدمات، تقنيات)",
            commands=[
                "nmap -sV <target>",
                "httpx -probe <target>",
                "whatweb <target>",
            ],
        )
        recon.add_child(MITRENode(
            technique_id="T1592.001",
            name="Scanning IP Blocks",
            tactic="reconnaissance",
            description="مسح نطاقات عناوين IP",
            commands=["nmap -sP <cidr>", "masscan <cidr>"],
        ))
        recon.add_child(MITRENode(
            technique_id="T1592.002",
            name="Subdomain Enumeration",
            tactic="reconnaissance",
            description="كشف النطاقات الفرعية",
            commands=["subfinder -d <target>", "assetfinder <target>"],
        ))

        # Resource Development (TA0042)
        res_dev = MITRENode(
            technique_id="T1583",
            name="Acquire Infrastructure",
            tactic="resource-development",
            description="تأمين البنية التحتية للهجوم (VPS، نطاقات، خادم C2)",
            commands=[],
        )

        # Initial Access (TA0002)
        initial_access = MITRENode(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactic="initial-access",
            description="استغلال تطبيقات عامة الوصول (ثغرات الويب)",
            commands=[
                "nuclei -t <template> <target>",
                "sqlmap -u <url>",
                "ffuf -w <wordlist> -u <url>",
            ],
        )
        initial_access.add_child(MITRENode(
            technique_id="T1190.001",
            name="SQL Injection",
            tactic="initial-access",
            description="حقن SQL عبر 매개 متغيرات الويب",
            commands=["sqlmap -u '<url>' --batch", "sqlmap -u '<url>' --level=5 --risk=3"],
        ))
        initial_access.add_child(MITRENode(
            technique_id="T1190.002",
            name="Cross-Site Scripting (XSS)",
            tactic="initial-access",
            description="حقن سكريبتات خبيثة في صفحات الويب",
            commands=["dalfox url <url>", "xsstrike -u <url>"],
        ))
        initial_access.add_child(MITRENode(
            technique_id="T1190.003",
            name="Server-Side Request Forgery (SSRF)",
            tactic="initial-access",
            description="إجبار الخادم على إجراء طلبات إلى موارد داخلية",
            commands=["curl '<target>?url=http://internal'"],
        ))
        initial_access.add_child(MITRENode(
            technique_id="T1190.004",
            name="IDOR / BOLA",
            tactic="initial-access",
            description="كسر تفويض الكائن على مستوى الجسم",
            commands=["burpsuite -repeater /api/users/{id}"],
        ))

        # WAF Bypass Techniques (2025-2026 Research)
        initial_access.add_child(MITRENode(
            technique_id="T1190.WAF_PADDING",
            name="WAF Payload Padding",
            tactic="initial-access",
            description="وضع حمولة خبيثة خلف بيانات حميدة كبيرة لتجاوز حدود التفتيش في WAF",
            commands=["pentest waf-padding <target> <payload>"],
        ))
        initial_access.add_child(MITRENode(
            technique_id="T1190.WAF_PARSER",
            name="WAF Parser Bug Exploitation",
            tactic="initial-access",
            description="استغلال أخطاء محللات WAF (مثل Coraza jsDecode off-by-one) لتجاوز الفحص",
            commands=["pentest waf-parser-bug <target> <bug_id> <payload>"],
        ))
        initial_access.add_child(MITRENode(
            technique_id="T1190.WAF_SEMANTIC",
            name="WAF Semantic Pollution",
            tactic="initial-access",
            description="حقن تعليمات داخل الطلب لتضليل WAF المعتمد على LLM",
            commands=["pentest waf-semantic <target> <waf_product> <payload>"],
        ))
        initial_access.add_child(MITRENode(
            technique_id="T1190.WAF_WEBSOCKET",
            name="WAF WebSocket Bypass",
            tactic="initial-access",
            description="إرسال الحمولات الخبيثة عبر رسائل WebSocket بعد ترقية الاتصال",
            commands=["pentest waf-protocol <target> websocket <payload>"],
        ))
        initial_access.add_child(MITRENode(
            technique_id="T1190.WAF_GRPC",
            name="WAF gRPC Bypass",
            tactic="initial-access",
            description="إرسال الحمولات الخبيثة داخل تدفقات gRPC ثنائية الاتجاه",
            commands=["pentest waf-protocol <target> grpc <payload>"],
        ))
        initial_access.add_child(MITRENode(
            technique_id="T1190.WAF_FINGERPRINT",
            name="WAF Fingerprint Spoofing",
            tactic="initial-access",
            description="محاكاة بصمة متصفح حقيقي (TLS/HTTP/2/TCP) لتجاوز فلاتر مكافحة البوتات",
            commands=["pentest waf-fingerprint <target> <profile>"],
        ))

        # Execution (TA0002)
        execution = MITRENode(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic="execution",
            description="تنفيذ أوامر عبر مترجمات البرمجة",
            commands=[],
        )

        # Persistence (TA0003)
        persistence = MITRENode(
            technique_id="T1505",
            name="Web Shell",
            tactic="persistence",
            description="تثبيت شل ويب للوصول المستمر",
            commands=[],
        )

        # Privilege Escalation (TA0004)
        priv_esc = MITRENode(
            technique_id="T1068",
            name="Exploitation for Privilege Escalation",
            tactic="privilege-escalation",
            description="استغلال ثغرات لرفع الصلاحيات",
            commands=[],
        )

        # Defense Evasion (TA0005)
        defense_evasion = MITRENode(
            technique_id="T1027",
            name="Obfuscated Files or Information",
            tactic="defense-evasion",
            description="تشفير أو إخفاء الملفات والمعلومات",
            commands=[],
        )

        # Credential Access (TA0006)
        cred_access = MITRENode(
            technique_id="T1552",
            name="Unsecured Credentials",
            tactic="credential-access",
            description="وصول إلى بيانات اعتماد غير مؤمنة",
            commands=[],
        )
        cred_access.add_child(MITRENode(
            technique_id="T1552.001",
            name="Credentials in Files",
            tactic="credential-access",
            description="البحث عن بيانات اعتماد في ملفات JS أو إعدادات",
            commands=["secretfinder <dir>", "trufflehog <dir>"],
        ))

        # Discovery (TA0007)
        discovery = MITRENode(
            technique_id="T1087",
            name="Account Discovery",
            tactic="discovery",
            description="اكتشاف الحسابات على النظام",
            commands=[],
        )

        # Lateral Movement (TA0008)
        lateral = MITRENode(
            technique_id="T1021",
            name="Remote Services",
            tactic="lateral-movement",
            description="التنقل الأفقي عبر خدمات عن بعد",
            commands=[],
        )

        # Collection (TA0009)
        collection = MITRENode(
            technique_id="T1005",
            name="Data from Local System",
            tactic="collection",
            description="جمع البيانات من النظام المحلي",
            commands=[],
        )

        # Exfiltration (TA0010)
        exfiltration = MITRENode(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            tactic="exfiltration",
            description="تصدير البيانات عبر قناة C2",
            commands=[],
        )

        # Impact (TA0040)
        impact = MITRENode(
            technique_id="T1499",
            name="Endpoint Denial of Service",
            tactic="impact",
            description="حرمان الخدمة عن نقاط النهاية",
            commands=[],  # مقصوداً فارغ — manœuvres مدمرة محظورة افتراضياً
        )

        # إضافة 모든 الفروع للجذر
        for node in [recon, res_dev, initial_access, execution, persistence,
                     priv_esc, defense_evasion, cred_access, discovery,
                     lateral, collection, exfiltration, impact]:
            self.root.add_child(node)

    def get_node(self, technique_id: str) -> Optional[MITRENode]:
        """البحث عن عقدة بالمعرف في كامل الشجرة."""
        return self._search(self.root, technique_id)

    def _search(self, node: MITRENode, technique_id: str) -> Optional[MITRENode]:
        if node.technique_id == technique_id:
            return node
        for child in node.children.values():
            result = self._search(child, technique_id)
            if result:
                return result
        return None

    def get_children(self, technique_id: str) -> List[MITRENode]:
        """الحصول على أبناء عقدة معينة."""
        node = self.get_node(technique_id)
        if node:
            return list(node.children.values())
        return []

    def get_root_children(self) -> List[MITRENode]:
        """الحصول على أبناء الجذر (التكتيكات العليا)."""
        return list(self.root.children.values())

    def record_attempt(self, technique_id: str, succeeded: bool) -> None:
        """تسجيل محاولة وتحديث نسبة النجاح."""
        node = self.get_node(technique_id)
        if node:
            node.attempts += 1
            if succeeded:
                node.successes += 1
                node.verified = True

    def get_recommended_techniques(self, tactic: str, max_results: int = 5) -> List[MITRENode]:
        """الحصول على التقنيات الموصى بها لتكتيك معين، مرتبة حسب نسبة النجاح."""
        candidates = []
        self._collect_by_tactic(self.root, tactic, candidates)
        candidates.sort(key=lambda n: n.success_rate(), reverse=True)
        return candidates[:max_results]

    def _collect_by_tactic(self, node: MITRENode, tactic: str, out: List[MITRENode]) -> None:
        if node.tactic == tactic:
            out.append(node)
        for child in node.children.values():
            self._collect_by_tactic(child, tactic, out)

    def get_path_to_root(self, technique_id: str) -> List[str]:
        """الحصول على المسار من العقدة إلى الجذر (للتصعيد والمراجعة)."""
        node = self.get_node(technique_id)
        path: List[str] = []
        while node:
            path.append(node.technique_id)
            node = node.parent
        return list(reversed(path))

    def export_tree(self) -> Dict[str, Any]:
        return self.root.to_dict()
