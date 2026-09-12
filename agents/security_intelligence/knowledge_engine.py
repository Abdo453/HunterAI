"""
Security Knowledge Engine & Knowledge Graph
Provides structured domain knowledge, CWE/OWASP taxonomies, detection heuristics, and remediation standards.
"""
from typing import Dict, List, Any, Optional


class KnowledgeEngine:
    """محرك وقاعدة المعرفة الأمنية: ربط الثغرات بالتصنيفات، الأدلة المطلوبة، وطرق المعالجة"""

    def __init__(self):
        self._vuln_database: Dict[str, Dict[str, Any]] = self._init_database()

    def get_vulnerability(self, vuln_type: str) -> Optional[Dict[str, Any]]:
        vuln_type_clean = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")
        for k, v in self._vuln_database.items():
            if k == vuln_type_clean or vuln_type_clean in k or k in vuln_type_clean:
                return v
        return None

    def search_by_keyword(self, keyword: str) -> List[Dict[str, Any]]:
        kw = keyword.lower()
        results = []
        for name, data in self._vuln_database.items():
            if (kw in name or 
                kw in data.get("title", "").lower() or 
                kw in data.get("cwe", "").lower() or 
                kw in data.get("owasp", "").lower() or
                any(kw in p.lower() for p in data.get("indicators", []))):
                results.append(data)
        return results

    def _init_database(self) -> Dict[str, Dict[str, Any]]:
        return {
            "bola": {
                "id": "VULN-BOLA",
                "title": "Broken Object Level Authorization (BOLA / IDOR)",
                "cwe": "CWE-639",
                "owasp": "API1:2023",
                "severity": "HIGH",
                "indicators": ["id", "user_id", "account_id", "order_id", "doc_id", "uuid", "profile_id"],
                "required_evidence": [
                    "User-controlled object identifier in URI/body",
                    "Authenticated endpoint",
                    "Different user accessing resource without permission",
                    "Response returns victim's sensitive data or allows modification"
                ],
                "counter_evidence": [
                    "Strict server-side ownership check returning 403 Forbidden",
                    "Object ID is non-guessable and scoped to session token"
                ],
                "root_cause": "The application relies on user-provided object IDs without validating whether the requesting user owns the object.",
                "remediation": "Implement object-level access control checks in data access layer using the verified session identity (e.g. SELECT * FROM orders WHERE id = ? AND user_id = current_user_id).",
                "arabic_concept": "السماح للمستخدم بالوصول إلى بيانات كائن (Object) خاص بمستخدم آخر بمجرد تعديل المعرف الرقمي أو الـ ID."
            },
            "bfla": {
                "id": "VULN-BFLA",
                "title": "Broken Function Level Authorization (BFLA / Privilege Escalation)",
                "cwe": "CWE-285",
                "owasp": "API5:2023",
                "severity": "HIGH",
                "indicators": ["/admin", "/manage", "/api/v1/users/delete", "role", "is_admin", "promote"],
                "required_evidence": [
                    "Administrative or privileged function endpoint",
                    "Low-privileged token able to execute privileged function",
                    "HTTP 200 OK / state change on unauthorized action"
                ],
                "counter_evidence": [
                    "Server validates role and returns 403 Forbidden",
                    "RBAC middleware strictly applied at router level"
                ],
                "root_cause": "Endpoints assume the client interface hides admin buttons, failing to enforce role-based access control (RBAC) on the backend.",
                "remediation": "Enforce strict role and permission checks on every administrative endpoint handler.",
                "arabic_concept": "تنفيذ مستخدم عادي لوظائف أو صلاحيات خاصة بالمدير (Admin) لغياب التحقق من مستوى الصلاحيات في السيرفر."
            },
            "sqli": {
                "id": "VULN-SQLI",
                "title": "SQL Injection",
                "cwe": "CWE-89",
                "owasp": "A03:2021",
                "severity": "CRITICAL",
                "indicators": ["' or 1=1", "syntax error", "mysql", "postgresql", "ora-", "sqlite3", "syntax error in query"],
                "required_evidence": [
                    "Database error message disclosure or timing delay differential",
                    "Altered query logic returning unauthorized dataset",
                    "Boolean response differential on injected truth/falsity"
                ],
                "counter_evidence": [
                    "Parameterized queries (Prepared Statements) used across all database calls",
                    "ORM properly escaping inputs with type checking"
                ],
                "root_cause": "Concatenating untrusted user input directly into SQL queries.",
                "remediation": "Use Prepared Statements (Parameterized Queries) or safe ORM mappers with typed inputs.",
                "arabic_concept": "حقن أوامر SQL داخل استعلام قاعدة البيانات لتنفيذ منطق غير مصرح به واستخراج البيانات أو التلاعب بها."
            },
            "ssrf": {
                "id": "VULN-SSRF",
                "title": "Server-Side Request Forgery (SSRF)",
                "cwe": "CWE-918",
                "owasp": "A10:2021",
                "severity": "HIGH",
                "indicators": ["url", "dest", "redirect", "webhook", "feed", "fetch", "http://169.254.169.254", "http://127.0.0.1"],
                "required_evidence": [
                    "Server initiates outbound network connection to target specified by user",
                    "Response reflects internal resource or timing shows internal port status"
                ],
                "counter_evidence": [
                    "Strict whitelist of allowed destination domains and protocols",
                    "Internal IP ranges (RFC 1918, link-local 169.254) blocked at network/application layer"
                ],
                "root_cause": "The server fetches remote resources without validating destination IP addresses or protocols.",
                "remediation": "Validate and whitelist destination hostnames, disable unused URL schemes (file://, gopher://), and block private IP address ranges.",
                "arabic_concept": "إجبار خادم الويب على إرسال طلبات HTTP لشبكات داخلية أو خدمات سحابية (مثل AWS Metadata) لا يمكن الوصول إليها من الخارج."
            },
            "jwt_weakness": {
                "id": "VULN-JWT",
                "title": "JWT Insecure Processing / Signature Flaws",
                "cwe": "CWE-347",
                "owasp": "A07:2021",
                "severity": "HIGH",
                "indicators": ["Bearer eyJ", "alg: none", "weak secret", "exp missing", "kid injection"],
                "required_evidence": [
                    "Server accepts token with 'alg': 'none'",
                    "Signature verification omitted or using easily crackable secret",
                    "Tampered payload accepted by server with 200 OK"
                ],
                "counter_evidence": [
                    "Server enforces strong asymmetric algorithm (RS256/ES256)",
                    "Token expiration and claims strictly validated on backend"
                ],
                "root_cause": "Flawed JWT library configuration or trusting the client-specified algorithm header.",
                "remediation": "Enforce explicit asymmetric algorithm verification and reject 'none' or mismatched algorithms.",
                "arabic_concept": "خلل في التحقق من توقيع رموز JWT مما يسمح بتعديل بيانات المستخدم أو الصلاحيات دون رفض الطلب."
            },
            "xss": {
                "id": "VULN-XSS",
                "title": "Cross-Site Scripting (Reflected / Stored / DOM)",
                "cwe": "CWE-79",
                "owasp": "A03:2021",
                "severity": "MEDIUM",
                "indicators": ["<script>", "alert(", "onload=", "onerror=", "javascript:"],
                "required_evidence": [
                    "User input rendered in HTML response without context-aware output encoding",
                    "JavaScript executes in the victim's browser context"
                ],
                "counter_evidence": [
                    "Strict Content-Security-Policy (CSP) headers without 'unsafe-inline'",
                    "Context-aware output encoding applied to all reflected inputs"
                ],
                "root_cause": "Rendering untrusted input as active HTML/JavaScript content in browser.",
                "remediation": "Apply context-aware output encoding (HTML, Attribute, JavaScript) and deploy a strong CSP header.",
                "arabic_concept": "تنفيذ كود JavaScript خبيث في متصفح الضحية لسرقة الجلسات أو التلاعب بالواجهة."
            },
            "mass_assignment": {
                "id": "VULN-MASS-ASSIGN",
                "title": "Mass Assignment / Object Property Injection",
                "cwe": "CWE-915",
                "owasp": "API3:2023",
                "severity": "MEDIUM",
                "indicators": ["role", "is_admin", "is_verified", "balance", "permissions", "credits"],
                "required_evidence": [
                    "Client sends extra properties in JSON payload (e.g., {'is_admin': true})",
                    "Server persists properties without DTO filtering or schema whitelisting"
                ],
                "counter_evidence": [
                    "Explicit Data Transfer Objects (DTOs) or field whitelists used during model binding"
                ],
                "root_cause": "Binding client JSON payloads directly to database entities without whitelisting allowed fields.",
                "remediation": "Use explicit schema DTOs and whitelist only user-editable properties.",
                "arabic_concept": "تمرير خصائص إضافية في طلب الـ JSON (مثل role أو balance) وتحديثها مباشرة في قاعدة البيانات دون تدقيق."
            }
        }
