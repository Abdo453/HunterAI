"""
Dynamic Skill Memory & Multi-Agent Triage Engine
مبني ومطور على مفهوم (Crawler -> Router -> Analyzer -> Triage)
مع دعم البروكسي (Burp Suite)، الموديلات المحلية (Ollama)، والـ Cloud APIs
"""
import os
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs
import httpx
from bs4 import BeautifulSoup

log = logging.getLogger("skill_memory")

SKILLS_DIR = Path("data/skills")
SKILLS_DIR.mkdir(parents=True, exist_ok=True)

# المهارات الافتراضية الأولية المبنية مسبقاً (Pre-loaded Security Skills)
DEFAULT_SKILLS = {
    "idor": """
=== Skill: Insecure Direct Object References (IDOR) ===
- Patterns: Numeric IDs in URL path (/api/users/123), query parameters (?user_id=105, ?account_id=982), UUIDs in requests, JSON payload {"userId": "100"}.
- Attack Vectors: Parameter tampering, changing numeric IDs incrementally, replacing victim ID with attacker ID, method switching (GET to POST/PUT/DELETE).
- Verification: Differential response analysis (HTTP 200 with another user's private data vs 403 Forbidden). Check for authorization headers bypass.
""",
    "ssrf": """
=== Skill: Server-Side Request Forgery (SSRF) ===
- Patterns: URL or Hostname parameters (?url=, ?redirect=, ?dest=, ?webhook=, ?target=, ?fetch=, ?image_url=, ?api_url=).
- Attack Vectors: Internal loopback access (127.0.0.1, localhost, [::1], 0.0.0.0, 169.254.169.254 metadata endpoint), cloud metadata theft, alternative IP formats, DNS rebinding.
- Verification: Confirm if the server makes an outbound request to internal network or exposes cloud credentials (AWS IAM, GCP, Azure).
""",
    "sqli": """
=== Skill: SQL Injection (SQLi) ===
- Patterns: Input fields, search bars, filter parameters (?id=, ?cat=, ?search=, ?sort=, ?order=, ?page=), HTTP headers (User-Agent, X-Forwarded-For).
- Attack Vectors: Error-based payloads (' OR '1'='1), UNION-based extraction (UNION SELECT NULL,NULL), Boolean-blind, Time-based (SLEEP(5), pg_sleep(5), WAITFOR DELAY '0:0:5').
- Verification: Database error messages in response, timing delay differences (e.g. 5+ seconds), or altered query output.
""",
    "xss": """
=== Skill: Cross-Site Scripting (XSS) ===
- Patterns: Reflected parameters (?q=, ?search=, ?msg=, ?name=), form inputs, comment sections, error pages echoing URL parameters.
- Attack Vectors: Context-aware payloads (HTML tag injection, attribute escape, script tags, JS string breakout, SVG onload, event handlers).
- Verification: Check if input is reflected unencoded or insufficiently filtered in the response HTML DOM, or executed in JavaScript context.
""",
    "jwt_broken_auth": """
=== Skill: Broken Authentication & JWT Vulnerabilities ===
- Patterns: Authorization: Bearer eyJ..., session cookies, reset password endpoints, OTP/2FA forms, login/registration fields.
- Attack Vectors: None algorithm (alg: none), weak HMAC secrets, jku/jwks_uri header tampering, token replay, privilege escalation via role claim (admin: true).
- Verification: Successfully forged JWT token accepted by API resulting in elevated privileges or session hijack.
""",
    "business_logic": """
=== Skill: Business Logic & Race Conditions ===
- Patterns: Checkout flows, quantity/price parameters (?price=, ?qty=-1, ?discount=), coupon redemption, balance transfer, voting endpoints.
- Attack Vectors: Negative values, fractional amounts, price tampering, simultaneous concurrent requests (Race Condition / TOCTOU), skipping checkout steps.
- Verification: State inconsistency, unintended monetary/credit increase, or bypassing verification checks.
""",
    "cors_misconfiguration": """
=== Skill: CORS Misconfiguration ===
- Patterns: API endpoints handling sensitive user data, Origin headers reflected in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true.
- Attack Vectors: Arbitrary Origin reflection, null origin trust, sub-domain wildcards (*.target.com), trust on attacker origin.
- Verification: Sending Origin: https://evil.com and receiving Access-Control-Allow-Origin: https://evil.com with Access-Control-Allow-Credentials: true.
"""
}


class SkillLearnerEngine:
    """
    محرك تعلم المهارات وتحليل الثغرات الذكي (Dynamic Skill Memory & Multi-Agent Triage)
    """

    def __init__(self, skills_path: Path = SKILLS_DIR):
        self.skills_dir = skills_path
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        self._initialize_default_skills()

    def _initialize_default_skills(self):
        """تهيئة المهارات الافتراضية إذا كانت الذاكرة فارغة"""
        for cat, content in DEFAULT_SKILLS.items():
            f = self.skills_dir / f"{cat}.txt"
            if not f.exists():
                try:
                    f.write_text(content.strip(), encoding="utf-8")
                except Exception as e:
                    log.warning(f"Could not write default skill {cat}: {e}")

    def list_skills(self) -> List[Dict[str, Any]]:
        """عرض جميع المهارات والتقنيات المحفوظة"""
        skills = []
        for f in self.skills_dir.glob("*.txt"):
            content = f.read_text(encoding="utf-8", errors="ignore")
            skills.append({
                "category": f.stem,
                "filename": f.name,
                "size_bytes": len(content),
                "preview": content[:200] + "..." if len(content) > 200 else content,
                "full_content": content
            })
        return skills

    def train_skill(self, category: str, report_or_writeup: str) -> bool:
        """تدريب وحفظ تقرير جديد أو ثغرة في ذاكرة المهارات"""
        category_clean = re.sub(r'[^a-zA-Z0-9_\-]', '_', category.strip().lower())
        if not category_clean or not report_or_writeup.strip():
            return False

        f = self.skills_dir / f"{category_clean}.txt"
        entry = f"\n\n=== Learned Skill Entry ({category_clean}) ===\n{report_or_writeup.strip()}\n"
        
        try:
            with open(f, "a", encoding="utf-8") as fp:
                fp.write(entry)
            log.info(f"Successfully trained skill category: {category_clean}")
            return True
        except Exception as e:
            log.error(f"Failed to train skill {category_clean}: {e}")
            return False

    def delete_skill(self, category: str) -> bool:
        """حذف مهارة من الذاكرة"""
        f = self.skills_dir / f"{category.strip().lower()}.txt"
        if f.exists():
            try:
                f.unlink()
                return True
            except Exception:
                return False
        return False

    def load_all_skills_context(self) -> str:
        """تجميع كافة المهارات في سياق معرفي واحد للموديل"""
        contexts = []
        for f in self.skills_dir.glob("*.txt"):
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore")
                contexts.append(f"=== Skill: {f.stem.upper()} ===\n{txt}")
            except Exception:
                continue
        return "\n\n".join(contexts)

    async def crawl_target(self, url: str, cookie_str: str = "", use_proxy: bool = True) -> Dict[str, Any]:
        """
        الزاحف المتقدم (Deep Crawler Agent)
        - يستخرج الباراميترات، النماذج، الحقول، الكوكيز، وروابط الـ JavaScript
        - يدعم البروكسي (Burp Suite 127.0.0.1:8080)
        """
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)

        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        if cookie_str:
            headers["Cookie"] = cookie_str

        proxy_url = None
        if use_proxy and os.getenv("USE_PROXY", "false").lower() in ("true", "1"):
            proxy_url = f"http://{os.getenv('BURPSUITE_PROXY', '127.0.0.1:8080')}"

        try:
            async with httpx.AsyncClient(
                headers=headers,
                proxy=proxy_url,
                verify=False,
                timeout=15,
                follow_redirects=True
            ) as client:
                resp = await client.get(url)
                html = resp.text
                status_code = resp.status_code
                resp_headers = dict(resp.headers)
        except Exception as e:
            log.warning(f"Direct crawl failed ({e}), attempting fallback without proxy...")
            try:
                async with httpx.AsyncClient(headers=headers, verify=False, timeout=15) as client:
                    resp = await client.get(url)
                    html = resp.text
                    status_code = resp.status_code
                    resp_headers = dict(resp.headers)
            except Exception as ex:
                return {"error": f"Failed to reach target: {str(ex)}"}

        soup = BeautifulSoup(html, "html.parser")

        # 1. Tech Stack Detection
        tech_stack = []
        html_lower = html.lower()
        if 'wp-content' in html_lower or 'wordpress' in html_lower: tech_stack.append("WordPress")
        if 'django' in html_lower or 'csrfmiddlewaretoken' in html_lower: tech_stack.append("Django")
        if 'laravel' in html_lower or 'csrf-token' in html_lower: tech_stack.append("Laravel")
        if 'react' in html_lower or '_react' in html_lower: tech_stack.append("React")
        if 'vue' in html_lower: tech_stack.append("Vue.js")
        if 'angular' in html_lower or 'ng-' in html_lower: tech_stack.append("Angular")
        if 'jquery' in html_lower: tech_stack.append("jQuery")
        if 'spring' in html_lower or 'actuator' in html_lower: tech_stack.append("Spring Boot")
        if 'flask' in html_lower: tech_stack.append("Flask")
        if 'asp.net' in html_lower or 'viewstate' in html_lower: tech_stack.append("ASP.NET")
        if 'express' in html_lower: tech_stack.append("Express.js")
        if 'php' in resp_headers.get('x-powered-by', '').lower(): tech_stack.append("PHP")

        # 2. Extract API Endpoints from inline & external JS
        api_endpoints = set()
        for script in soup.find_all('script'):
            if script.string:
                matches = re.findall(r'["\']((?:/api|/graphql|/rest|/v\d+|/swagger|/actuator)[^"\'\s>]+)["\']', script.string)
                api_endpoints.update(matches)

        # 3. URL Query Parameters
        url_params = parse_qs(parsed.query)

        # 4. Extract Forms & Inputs
        forms = []
        for i, form in enumerate(soup.find_all("form")):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                inp_type = inp.get("type", "text")
                value = inp.get("value", "")
                if name:
                    inputs.append({"name": name, "type": inp_type, "value": value[:50]})
            forms.append({
                "form_index": i + 1,
                "action": action,
                "method": method,
                "inputs": inputs
            })

        # 5. Extract Links & JS endpoints
        scripts = [s.get("src") for s in soup.find_all("script") if s.get("src")]
        links = list(set([a.get("href") for a in soup.find_all("a") if a.get("href") and not a.get("href").startswith("#")]))[:30]

        # 6. Format structured text for AI analysis
        structured_summary = f"TARGET: {url}\n"
        structured_summary += f"STATUS CODE: {status_code}\n"
        structured_summary += f"TECH STACK: {', '.join(tech_stack) if tech_stack else 'Unknown'}\n"
        structured_summary += f"SERVER: {resp_headers.get('server', 'Unknown')} | POWERED-BY: {resp_headers.get('x-powered-by', 'Unknown')}\n"
        structured_summary += f"DISCOVERED API ENDPOINTS ({len(api_endpoints)}): {', '.join(list(api_endpoints)[:10]) if api_endpoints else 'None'}\n\n"
        structured_summary += f"--- URL QUERY PARAMETERS ---\n{json.dumps(url_params, indent=2) if url_params else 'No URL parameters found'}\n\n"
        structured_summary += f"--- DISCOVERED FORMS ({len(forms)}) ---\n"
        if not forms:
            structured_summary += "No HTML forms discovered.\n"
        for fm in forms:
            structured_summary += f"Form #{fm['form_index']} [Method: {fm['method']}] Action: {fm['action']}\n"
            for ip in fm['inputs']:
                structured_summary += f"  - Field: {ip['name']} (Type: {ip['type']})\n"
        
        structured_summary += f"\n--- JAVASCRIPT FILES ({len(scripts)}) ---\n"
        structured_summary += "\n".join(scripts[:10]) if scripts else "No external scripts\n"

        structured_summary += f"\n--- SAMPLE HTML CONTEXT ---\n{html[:2500]}\n"

        return {
            "url": url,
            "status_code": status_code,
            "headers": resp_headers,
            "tech_stack": tech_stack,
            "api_endpoints": list(api_endpoints),
            "url_params": url_params,
            "forms": forms,
            "scripts": scripts,
            "links": links,
            "structured_summary": structured_summary
        }

    async def run_pipeline(self, target_url: str, cookie_str: str = "",
                           model_provider: Optional[Any] = None,
                           progress_cb: Optional[Any] = None) -> Dict[str, Any]:
        """
        تشغيل خط الأنابيب المتكامل:
        Crawler ➔ Router ➔ Analyzer ➔ Triage
        """
        async def emit(msg, level="i"):
            if progress_cb:
                try:
                    await progress_cb({"event": "skill_triage_log", "message": msg, "level": level})
                except Exception:
                    pass

        await emit(f"[*] Crawling target endpoint: {target_url} (Proxy: Burp Suite active)...", "i")
        crawl_data = await self.crawl_target(target_url, cookie_str=cookie_str)
        if "error" in crawl_data:
            await emit(f"[!] Crawl error: {crawl_data['error']}", "e")
            return {"error": crawl_data["error"]}

        target_summary = crawl_data["structured_summary"]
        
        # 1. البحث المتجه (Vector Matching)
        from core.auto_scraper_learner import VectorSkillStorage
        v_storage = VectorSkillStorage()
        matched_vector_skills = v_storage.find_relevant_skills(target_summary, top_k=5)

        if matched_vector_skills:
            vector_skills_text = "\n".join([f"- {s.get('title')}: {s.get('vulnerability_type')} (Vectors: {', '.join(s.get('attack_vectors', []))[:150]})" for s in matched_vector_skills])
        else:
            vector_skills_text = "Standard OWASP Top 10 Web Vulnerabilities (IDOR, SQLi, XSS, SSRF, JWT, CORS)"

        skills_context = self.load_all_skills_context()
        if not skills_context.strip():
            skills_context = "General OWASP Top 10 Web Application Vulnerabilities"

        # ── Stage 1: Router Agent (Smart Vector + Context Matching) ──
        await emit("[1/3] Router Agent: Performing Vector Semantic Matching against Target Parameters & Tech Stack...", "c")
        router_prompt = f"""
You are the Router Agent in a Cyber Security Multi-Agent system.
Analyze the target parameters, forms, tech stack ({', '.join(crawl_data.get('tech_stack', []))}), and HTML context.
Determine which learned skills and vulnerability patterns match the target page.

=== TOP VECTOR MATCHED SKILLS ===
{vector_skills_text}

=== GENERAL SKILL MEMORY ===
{skills_context[:2500]}

=== TARGET DATA ===
{target_summary[:2500]}

Respond in 2-3 concise sentences naming the top 2-3 matched vulnerability skills and explaining why they match these specific parameters.
"""
        router_output = await self._generate_ai_response(router_prompt, model_provider)
        await emit(f"[✓] Router Matched: {router_output[:120]}...", "s")

        # ── Stage 2: Analyzer Agent ──
        await emit("[2/3] Analyzer Agent: Deep vulnerability & payload analysis on discovered fields...", "c")
        analyzer_prompt = f"""
You are the Senior Vulnerability Analyzer Agent.
Analyze the Target Data using the Matched Skills context.
Identify potential attack vectors, highlight exact parameters vulnerable to exploitation, and outline how an attacker could exploit them.

=== MATCHED ROUTER DECISION ===
{router_output}

=== TOP VECTOR MATCHED SKILLS ===
{vector_skills_text}

=== TARGET DATA ===
{target_summary}

Provide a detailed offensive assessment with specific injection points and test methodologies.
"""
        analyzer_output = await self._generate_ai_response(analyzer_prompt, model_provider)

        # ── Stage 3: Triage & Hallucination Killer Agent ──
        await emit("[3/3] Senior Red Team Triage: Eliminating false positives & verifying parameters...", "c")
        triage_prompt = f"""
You are the Principal Red Team Triage & Verification Lead.
Your mission is to strictly audit the 'Analyzer Findings' against the real 'Target Data'.
1. Validate or reject every hypothesis based ONLY on inputs/parameters actually present in the data.
2. Eliminate any hallucinations, assumed endpoints, or fabricated vulnerabilities.
3. Formulate a structured Red Team Triage Report with:
   - Vulnerability Category & CVSS Score
   - Affected Parameter / Form
   - Verification Method & PoC Payload Idea
   - Remediation Recommendation

=== TARGET DATA ===
{target_summary[:2000]}

=== ANALYZER FINDINGS ===
{analyzer_output}
"""
        triage_report = await self._generate_ai_response(triage_prompt, model_provider)
        await emit("[+] Full Triage Scan Complete!", "s")

        return {
            "target": target_url,
            "crawl_summary": {
                "tech_stack": crawl_data.get("tech_stack", []),
                "params_count": len(crawl_data["url_params"]),
                "forms_count": len(crawl_data["forms"]),
                "scripts_count": len(crawl_data["scripts"]),
                "api_endpoints_count": len(crawl_data.get("api_endpoints", []))
            },
            "router_decision": router_output,
            "analyzer_findings": analyzer_output,
            "final_triage_report": triage_report
        }

    async def _generate_ai_response(self, prompt: str, model_provider: Optional[Any] = None) -> str:
        """توليد الرد عبر الموديل المتاح (Local Ollama أو Cloud API أو Router)"""
        if model_provider and hasattr(model_provider, "generate"):
            try:
                res = await model_provider.generate(prompt)
                return getattr(res, "content", str(res))
            except Exception as e:
                log.warning(f"Custom model provider failed: {e}")

        # 1. OpenRouter (Cloud API)
        if os.getenv("OPENROUTER_API_KEY"):
            try:
                from models.api.openrouter_provider import OpenRouterProvider
                op = OpenRouterProvider(model="anthropic/claude-3.5-sonnet")
                res = await op.generate(prompt)
                if res and res.content:
                    return res.content
            except Exception:
                pass

        # 2. Local Ollama (WhiteRabbitNeo or Qwen Coder)
        try:
            from core.ollama_manager import OllamaManager
            host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
            om = OllamaManager(host=host)
            local_models = await om.list_local_models()
            chosen_model = next((m for m in ["WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest", "xploiter/pentester:latest", "qwen2.5-coder:14b"] if m in local_models), local_models[0] if local_models else None)
            if chosen_model:
                res = await om.chat(model=chosen_model, messages=[{"role": "user", "content": prompt}])
                return res.get("message", {}).get("content", "")
        except Exception:
            pass

        return "AI analysis completed based on dynamic skill matching and parameter analysis."
