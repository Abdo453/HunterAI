"""
Remediation Code & Developer Fix Generator
"Automated Secure Code Recommendations across Python, Node.js, PHP, & Server Configs"

يولد كود إصلاح أمني فوري ومباشر للمطورين:
1. استعلامات SQL الآمنة (Parameterized Queries & ORM)
2. تطهير وترميز المخرجات ضد XSS (Context-Aware Output Encoding)
3. التحقق من الصلاحيات لمنع IDOR (Role-Based Access Control)
4. إعدادات الهيدرز الأمنية لـ Nginx و Apache و Express
"""
from typing import Any, Dict, List, Optional


class RemediationGenerator:
    """مولد حلول الترقيع وأكواد الإصلاح البرمجية"""

    REMEDIATION_TEMPLATES = {
        "sqli": {
            "title": "Mitigating SQL Injection (SQLi)",
            "owasp": "A03:2021-Injection",
            "cwe": "CWE-89",
            "python": """# ✅ Python (SQLite / psycopg2 / MySQL): Use Parameterized Queries
cursor.execute("SELECT * FROM users WHERE username = %s AND id = %s", (username, user_id))

# ✅ Django ORM: Always uses parameterized queries by default
users = User.objects.filter(username=username, id=user_id)""",
            "nodejs": """// ✅ Node.js (mysql2 / pg): Use Parameterized Placeholders
const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);

// ✅ Prisma ORM:
const user = await prisma.user.findUnique({ where: { id: Number(userId) } });""",
            "php": """// ✅ PHP (PDO): Use Prepared Statements
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute(['id' => $userId]);
$user = $stmt->fetch();"""
        },
        "xss": {
            "title": "Mitigating Cross-Site Scripting (XSS)",
            "owasp": "A03:2021-Injection",
            "cwe": "CWE-79",
            "python": """# ✅ Python (Flask / Jinja2): Automatic HTML escaping is enabled by default.
# If generating manual responses, use markupsafe:
from markupsafe import escape
safe_html = f"<h1>Welcome {escape(user_input)}</h1>" """,
            "nodejs": """// ✅ Node.js (Express): Use DOMPurify or template escaping
import DOMPurify from 'isomorphic-dompurify';
const cleanHtml = DOMPurify.sanitize(userInput);
res.send(`<h1>Welcome ${cleanHtml}</h1>`);""",
            "php": """// ✅ PHP: Always encode output using htmlspecialchars with UTF-8
echo "<h1>Welcome " . htmlspecialchars($userInput, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "</h1>";"""
        },
        "idor": {
            "title": "Mitigating Insecure Direct Object References (IDOR)",
            "owasp": "A01:2021-Broken Access Control",
            "cwe": "CWE-639",
            "python": """# ✅ Python: Validate ownership at the database query level
# Do NOT just query by object ID; scope by authenticated user's account ID:
document = Document.objects.filter(id=doc_id, owner=request.user).first()
if not document:
    raise PermissionDenied("Access Denied")""",
            "nodejs": """// ✅ Node.js: Enforce user ownership in query logic
const document = await prisma.document.findFirst({
  where: { id: docId, ownerId: req.user.id }
});
if (!document) return res.status(403).json({ error: 'Access forbidden' });"""
        },
        "cors": {
            "title": "Hardening Cross-Origin Resource Sharing (CORS)",
            "owasp": "A05:2021-Security Misconfiguration",
            "cwe": "CWE-942",
            "nginx": """# ✅ Nginx: Whitelist trusted origins explicitly (Do NOT use wildcard * with credentials)
map $http_origin $cors_origin {
    default "";
    "~^https://(trusted1\\.com|app\\.example\\.com)$" "$http_origin";
}
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;""",
            "nodejs": """// ✅ Express cors middleware with strict whitelist
import cors from 'cors';
const allowedOrigins = ['https://trusted.example.com'];
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Blocked by CORS'));
    }
  },
  credentials: true
}));"""
        },
        "headers": {
            "title": "Essential HTTP Security Headers Configuration",
            "owasp": "A05:2021-Security Misconfiguration",
            "cwe": "CWE-16",
            "nginx": """# ✅ Nginx Security Headers
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;"""
        }
    }

    @classmethod
    def get_remediation_for_vuln(cls, vuln_type: str) -> Dict[str, Any]:
        """استرجاع كود وتوصيات الترقيع للثغرة المحددة"""
        vt = vuln_type.lower()
        for key, guide in cls.REMEDIATION_TEMPLATES.items():
            if key in vt:
                return guide
        return {
            "title": f"Remediation Guidance for {vuln_type}",
            "owasp": "OWASP Standard Best Practices",
            "cwe": "N/A",
            "general_fix": "Validate and sanitize all user-supplied input, enforce least privilege access controls, and apply vendor security patches."
        }
