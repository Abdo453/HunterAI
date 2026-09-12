"""
Deep Analyzer — Phase 2 of Self-Learning Pipeline (Enhanced & Grounded)
يحلّل المحتوى المجلوب ويستخرج المعرفة بالأدلة والسياق:
- Techniques مع سياق وظهور ونسبة ثقة (Context & Confidence)
- CVEs مع سياق الظهور
- CVSS دقيق (0-10)
- Payloads مصنفة مع السياق وحالة التفويض
- Claims منفصلة مع الأدلة
- Deduplication & Text Normalization
- Targeted Snippets → Local Qwen → Conditional API Fallback
- الفصل التام: التحليل للاستخراج والفهم، والـ DecisionEngine للاختيار، والـ ToolRegistry للتنفيذ
"""
import asyncio
import json
import logging
import os
import re
import time
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("learning.analyzer")

# ─── Known Extraction Patterns ───────────────────────────────────────────────
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

CVSS_PATTERN = re.compile(
    r"\bCVSS(?:\s*v[234](?:\.[01])?)?(?:\s*(?:base\s*)?(?:score|rating))?\s*(?:is|[:=])?\s*"
    r"(?P<score>10(?:\.0)?|[0-9](?:\.[0-9])?)\b",
    re.IGNORECASE
)

TOOL_KEYWORDS: List[str] = [
    "sqlmap", "nuclei", "burpsuite", "burp suite", "nmap", "ffuf",
    "metasploit", "hashcat", "nikto", "masscan", "dalfox", "gobuster",
    "wfuzz", "amass", "subfinder", "katana", "rustscan", "dirsearch",
    "wapiti", "zaproxy", "semgrep", "snyk", "trivy", "shodan",
]

TECHNIQUE_KEYWORDS: Dict[str, List[str]] = {
    "xss": ["cross-site scripting", "xss", "reflected xss", "stored xss", "dom xss", "csp bypass"],
    "sqli": ["sql injection", "sqli", "union select", "time-based", "blind sqli", "nosql injection"],
    "ssrf": ["ssrf", "server-side request forgery", "metadata endpoint", "internal network"],
    "idor": ["idor", "insecure direct object", "broken object level", "bola", "horizontal privilege"],
    "rce": ["remote code execution", "rce", "command injection", "os command", "code execution"],
    "auth": ["authentication bypass", "broken auth", "jwt", "session hijack", "privilege escalation"],
    "ssti": ["server-side template injection", "ssti", "template injection", "jinja2", "twig injection"],
    "xxe": ["xml external entity", "xxe", "xml injection", "dtd injection"],
    "path_traversal": ["path traversal", "directory traversal", "lfi", "rfi", "local file inclusion"],
    "deserialization": ["insecure deserialization", "java deserialization", "pickle", "yaml deserialization"],
    "csrf": ["cross-site request forgery", "csrf", "anti-csrf"],
    "cors": ["cors misconfiguration", "access-control-allow-origin", "cors bypass"],
    "open_redirect": ["open redirect", "unvalidated redirect", "url redirect"],
    "race_condition": ["race condition", "toctou", "concurrent request", "time-of-check"],
    "business_logic": ["business logic", "price manipulation", "negative quantity", "workflow bypass"],
}

SEVERITY_KEYWORDS: Dict[str, List[str]] = {
    "Critical": ["critical", "9.0", "10.0", "full system compromise", "unauthenticated rce"],
    "High": ["high", "7.0", "8.0", "privilege escalation", "data breach"],
    "Medium": ["medium", "4.0", "5.0", "6.0", "information disclosure"],
    "Low": ["low", "1.0", "2.0", "3.0", "minor"],
}

BYPASS_KEYWORDS: List[str] = [
    "waf bypass", "filter evasion", "encoding bypass", "double encoding",
    "unicode bypass", "null byte", "case variation", "comment injection",
    "time-based evasion", "chunked transfer", "header injection bypass",
]

PAYLOAD_CHARS_PATTERN = re.compile(
    r"(<script|alert\(|onerror=|onload=|union\s+select|' or |OR 1=1|SLEEP\(|pg_sleep|\$\{|{{|\.\.\/|%00|0x[0-9a-f])",
    re.IGNORECASE
)

KNOWN_TECH_LIST = [
    "apache", "nginx", "tomcat", "wordpress", "drupal", "joomla",
    "laravel", "django", "spring boot", "node.js", "php", "ruby on rails",
    "react", "angular", "vue.js", "mongodb", "mysql", "postgresql",
    "redis", "elasticsearch", "jenkins", "gitlab", "github actions",
    "kubernetes", "docker", "aws", "azure", "gcp", "s3",
]

MODEL_CODER = "qwen2.5-coder:14b"


# ─── Normalization & Deduplication ───────────────────────────────────────────

def normalize_text(value: str) -> str:
    """توحيد النصوص وإزالة المسافات الزائدة"""
    return re.sub(r"\s+", " ", str(value).lower()).strip()


def deduplicate_items(items: List[Dict], key: str = "") -> List[Dict]:
    """إزالة التكرار من القوائم المهيكلة بناء على مفتاح محدد"""
    seen: Set[str] = set()
    output: List[Dict] = []
    for item in items:
        if key:
            val = normalize_text(str(item.get(key, "")))
        else:
            val = normalize_text(json.dumps(item, sort_keys=True))
        if val and val not in seen:
            seen.add(val)
            output.append(item)
    return output


# ─── Unified Analysis Schema ─────────────────────────────────────────────────

_ANALYSIS_SCHEMA: Dict[str, Any] = {
    "schema_version": 1,
    "source": {
        "url": None,
        "title": None,
        "retrieved_at": None,
        "source_type": "article",
    },
    # Backwards-compatibility aliases
    "source_url": "",
    "title": "",
    "timestamp": "",
    "summary": "",
    "severity": "Unknown",
    "cvss_scores": [],
    "cvss_score": None,
    "cves": [],             # list of {"id": "CVE-...", "context": "..."}
    "related_cves": [],     # list of string IDs for legacy consumers
    "techniques": [],       # list of {"technique": "...", "matches": [...], "confidence": 0.85, "recommended_capability": "..."}
    "technique_names": [],  # list of strings for legacy consumers
    "tools": [],            # list of {"tool": "...", "context": "..."}
    "related_tools": [],    # list of strings for legacy consumers
    "payloads": [],         # list of {"payload": "...", "category": "...", "context": "...", "confidence": float, "requires_authorization": True}
    "raw_payloads": [],     # list of strings for legacy consumers
    "bypass_methods": [],   # list of {"bypass": "...", "context": "..."}
    "bypass_techniques": [],# list of strings for legacy consumers
    "claims": [],           # list of {"claim": "...", "evidence": "...", "confidence": float, "category": "..."}
    "prerequisites": [],
    "key_learnings": [],
    "exploit_chain_hints": [],
    "affected_technologies": [],
    "embedding_text": "",
    "confidence": 0.0,
    "requires_review": False,
}


class DeepAnalyzer:
    """
    محلل عميق مستند إلى الأدلة:
    يستخرج المعرفة بسياقها (Context) ومستوى الثقة (Confidence)،
    مع فصل كامل بين الفهم والاستخراج، والاختيار التكتيكي للأدوات.
    """

    def __init__(self, resource_manager=None):
        self.rm = resource_manager

    # ── Contextual Extraction Methods ────────────────────────────────────────

    def extract_cves(self, text: str) -> List[Dict[str, str]]:
        """استخراج أرقام الـ CVE مع السياق المحيط (+240 / -160 حرف)"""
        findings = []
        for match in CVE_PATTERN.finditer(text):
            start = max(0, match.start() - 160)
            end = min(len(text), match.end() + 240)
            findings.append({
                "id": match.group(0).upper(),
                "context": text[start:end].strip()
            })
        # Deduplicate by CVE ID
        unique: Dict[str, Dict[str, str]] = {}
        for item in findings:
            unique[item["id"]] = item
        return list(unique.values())

    def extract_cve_ids(self, text: str) -> List[str]:
        """استرجاع أسماء الـ CVE فقط للتوافق"""
        return [c["id"] for c in self.extract_cves(text)]

    def extract_cvss(self, text: str) -> List[float]:
        """استخراج درجات CVSS دقيقة (بين 0.0 و 10.0) وتفادي أرقام الإصدارات مثل CVSS 3.1"""
        scores = []
        for match in CVSS_PATTERN.finditer(text):
            try:
                score = float(match.group("score"))
                if 0.0 <= score <= 10.0:
                    scores.append(score)
            except (ValueError, TypeError):
                pass
        return sorted(set(scores))

    def extract_techniques(self, text: str) -> List[Dict[str, Any]]:
        """استخراج التقنيات مع السياق ومستوى الثقة والأدلة المباشرة"""
        text_lower = text.lower()
        results = []

        for technique, keywords in TECHNIQUE_KEYWORDS.items():
            matches = []
            for keyword in keywords:
                for match in re.finditer(re.escape(keyword), text_lower):
                    start = max(0, match.start() - 180)
                    end = min(len(text), match.end() + 180)
                    matches.append({
                        "keyword": keyword,
                        "context": text[start:end].strip()
                    })

            if matches:
                # Deduplicate matches by context
                dedup_matches = deduplicate_items(matches, key="context")
                confidence = min(0.95, round(0.35 + len(dedup_matches) * 0.1, 2))
                results.append({
                    "technique": technique,
                    "matches": dedup_matches[:10],
                    "confidence": confidence,
                    "recommended_capability": f"{technique}_verification"
                })

        return results

    def extract_technique_names(self, text: str) -> List[str]:
        """استرجاع أسماء التقنيات فقط للتوافق"""
        return [t["technique"] for t in self.extract_techniques(text)]

    def extract_tools(self, text: str) -> List[Dict[str, str]]:
        """استخراج الأدوات المذكورة في النص كسياق ومعلومة فقط (ليس كأمر تنفيذي)"""
        text_lower = text.lower()
        results = []
        for tool in TOOL_KEYWORDS:
            for match in re.finditer(re.escape(tool.lower()), text_lower):
                start = max(0, match.start() - 140)
                end = min(len(text), match.end() + 140)
                results.append({
                    "tool": tool,
                    "context": text[start:end].strip()
                })
        return deduplicate_items(results, key="tool")

    def extract_tool_names(self, text: str) -> List[str]:
        return [t["tool"] for t in self.extract_tools(text)]

    def extract_bypass_techniques(self, text: str) -> List[Dict[str, str]]:
        """استخراج طرق التجاوز (WAF / Filter Bypasses) مع السياق"""
        text_lower = text.lower()
        results = []
        for bp in BYPASS_KEYWORDS:
            for match in re.finditer(re.escape(bp), text_lower):
                start = max(0, match.start() - 160)
                end = min(len(text), match.end() + 160)
                results.append({
                    "bypass": bp,
                    "context": text[start:end].strip()
                })
        return deduplicate_items(results, key="bypass")

    def extract_bypass_names(self, text: str) -> List[str]:
        return [b["bypass"] for b in self.extract_bypass_techniques(text)]

    def extract_payloads(self, text: str, source_url: str = "") -> List[Dict[str, Any]]:
        """
        استخراج الـ Payloads مع التصنيف والسياق والثقة وحالة التفويض.
        الـ Analyzer يستخرج ويصنف فقط ولا ينفذ أبداً.
        """
        raw_items: List[Dict[str, Any]] = []

        # 1. Code blocks (```...```)
        code_blocks = re.findall(r"```[\s\S]{10,500}?```", text)
        for b in code_blocks[:8]:
            cleaned = b.strip("`").strip()
            if 5 < len(cleaned) < 500:
                raw_items.append({
                    "payload": cleaned,
                    "category": self._guess_payload_category(cleaned),
                    "context": "code_block",
                    "source": source_url,
                    "confidence": 0.70,
                    "requires_authorization": True
                })

        # 2. Backtick inline
        inline = re.findall(r"`([^`]{5,200})`", text)
        for p in inline[:15]:
            if any(c in p for c in ["<", "'", "\"", ";", "--", "%", "{{", "${", "\\", "0x"]):
                raw_items.append({
                    "payload": p.strip(),
                    "category": self._guess_payload_category(p),
                    "context": "inline_backtick",
                    "source": source_url,
                    "confidence": 0.65,
                    "requires_authorization": True
                })

        # 3. Plain-text payload patterns
        for line in text.splitlines():
            line = line.strip()
            if 5 < len(line) < 300 and PAYLOAD_CHARS_PATTERN.search(line):
                raw_items.append({
                    "payload": line,
                    "category": self._guess_payload_category(line),
                    "context": "plain_text_pattern",
                    "source": source_url,
                    "confidence": 0.60,
                    "requires_authorization": True
                })

        return deduplicate_items(raw_items, key="payload")[:20]

    def _guess_payload_category(self, payload_text: str) -> str:
        p_lower = payload_text.lower()
        if any(x in p_lower for x in ["<script", "alert(", "onerror=", "onload=", "<img", "<svg", "javascript:"]):
            return "xss"
        if any(x in p_lower for x in ["union select", "' or ", "--", "sleep(", "pg_sleep", "or 1=1", "order by"]):
            return "sqli"
        if any(x in p_lower for x in ["{{", "${", "7*7", "config.items"]):
            return "ssti"
        if any(x in p_lower for x in ["../", "..\\", "/etc/passwd", "win.ini"]):
            return "path_traversal"
        if any(x in p_lower for x in ["<!entity", "system \"file", "xml version"]):
            return "xxe"
        if any(x in p_lower for x in ["169.254.169.254", "localhost", "127.0.0.1", "metadata"]):
            return "ssrf"
        return "general"

    def detect_severity(self, text: str) -> str:
        text_lower = text.lower()
        for severity, keywords in SEVERITY_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return severity
        return "Medium"

    def detect_affected_tech(self, text: str) -> List[str]:
        techs = []
        text_lower = text.lower()
        for tech in KNOWN_TECH_LIST:
            if tech in text_lower:
                techs.append(tech)
        return techs[:10]

    def extract_claims(self, text: str, bypasses: List[Dict], techniques: List[Dict]) -> List[Dict[str, Any]]:
        """استخراج ادعاءات أمنية مدعومة بأدلة من السياق"""
        claims = []
        # Claim from bypass techniques
        for bp in bypasses[:5]:
            claims.append({
                "claim": f"Filter/WAF evasion possible using '{bp.get('bypass')}'",
                "evidence": bp.get("context", "")[:200],
                "confidence": 0.72,
                "category": "bypass_method"
            })
        # Claim from verified techniques
        for tech in techniques[:5]:
            if tech.get("matches"):
                claims.append({
                    "claim": f"Target or component is susceptible to {tech.get('technique')}",
                    "evidence": tech["matches"][0].get("context", "")[:200],
                    "confidence": tech.get("confidence", 0.65),
                    "category": "vulnerability_logic"
                })
        return deduplicate_items(claims, key="claim")

    # ── AI-Powered Analysis with Conditional Fallback ─────────────────────────

    async def _ask_qwen(self, system_msg: str, user_msg: str) -> str:
        """يستدعي Qwen2.5-Coder عبر Ollama"""
        if self.rm:
            try:
                return await self.rm.run_local_model(
                    model_name=MODEL_CODER,
                    messages=[
                        {"role": "system", "content": system_msg},
                        {"role": "user", "content": user_msg},
                    ],
                    temperature=0.1,
                    num_ctx=4096,
                ) or ""
            except Exception:
                log.debug("Qwen local call failed or offline", exc_info=True)
        return ""

    async def _api_fallback(self, prompt: str) -> str:
        """Gemini → OpenRouter fallback عند الحاجة فقط"""
        # 1. Gemini
        if os.getenv("GEMINI_API_KEY"):
            try:
                from models.api.gemini_provider import GeminiProvider
                resp = await GeminiProvider(model="gemini-3.6-flash").generate(prompt)
                if resp and resp.content:
                    return resp.content
            except Exception:
                pass
        # 2. OpenRouter
        if os.getenv("OPENROUTER_API_KEY"):
            try:
                from models.api.openrouter_provider import OpenRouterProvider
                resp = await OpenRouterProvider().generate(prompt)
                if resp and resp.content:
                    return resp.content
            except Exception:
                pass
        return ""

    def _parse_json_safe(self, text: str, fallback: dict) -> dict:
        """محلل JSON آمن بأقواس متوازنة"""
        try:
            data = json.loads(text.strip())
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        try:
            start = text.index("{")
            depth, end = 0, start
            for i, ch in enumerate(text[start:], start):
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            data = json.loads(text[start:end + 1])
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return deepcopy(fallback)

    async def ai_summarize(
        self,
        text: str,
        source_url: str = "",
        context_snippets: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        الـ AI يُلخّص المقاطع ذات الصلة فقط (Context Snippets) بدلاً من إرسال كامل النص،
        مما يحسن الدقة ويقلل التكلفة.
        """
        # If context snippets provided, use them; otherwise use top 3000 chars
        if context_snippets:
            focused_content = "\n---\n".join(context_snippets[:8])
        else:
            focused_content = text[:3000]

        system_msg = (
            "You are an elite cybersecurity research analyst. Extract structured intelligence "
            "and grounded claims with evidence from the given security content. "
            "Output ONLY a valid JSON object."
        )
        user_msg = (
            f"Source URL: {source_url}\n\n"
            f"Relevant Context Snippets:\n{focused_content}\n\n"
            "Return a JSON object with these keys:\n"
            "  summary: string (concise 2-3 sentence overview)\n"
            "  key_learnings: list of strings (3-5 concrete technical takeaways)\n"
            "  attack_scenario: string (how the flaw is exploited)\n"
            "  prerequisites: list of strings (conditions required for exploitation)\n"
            "  exploit_chain_hints: list of strings (possible chaining vectors)\n"
            "  claims: list of objects [{\"claim\": str, \"evidence\": str, \"confidence\": float, \"category\": str}]\n"
            "  defender_notes: string (remediation or detection logic)\n"
            "Do NOT include markdown wrapping or extra text. Valid JSON ONLY."
        )

        fallback_val: Dict[str, Any] = {
            "summary": text[:250].strip(),
            "key_learnings": [],
            "attack_scenario": "",
            "prerequisites": [],
            "exploit_chain_hints": [],
            "claims": [],
            "defender_notes": "",
        }

        # 1. Try local Qwen
        raw = await self._ask_qwen(system_msg, user_msg)
        parsed = self._parse_json_safe(raw, {})

        # 2. Conditional API Fallback if local Qwen failed or gave empty/low-quality JSON
        if not parsed or not parsed.get("summary"):
            log.debug("[ANALYZE] Local model returned invalid/empty JSON — triggering API fallback")
            raw_api = await self._api_fallback(f"{system_msg}\n\n{user_msg}")
            parsed = self._parse_json_safe(raw_api, fallback_val)

        if not parsed:
            parsed = fallback_val

        return parsed

    # ── Main Analysis Method (Full Pipeline) ─────────────────────────────────

    async def analyze(
        self,
        text: str,
        source_url: str = "",
        title: str = "",
        source_type: str = "article",
        use_ai: bool = True
    ) -> Dict[str, Any]:
        """
        التدفق الكامل:
        استخراج Regex سريع ومعتمد على السياق
                ↓
        تجهيز المقاطع ذات الصلة (Context Snippets)
                ↓
        تحليل Qwen المحلي / API fallback المشروط
                ↓
        Validation للـ JSON ودمج النتائج وإزالة التكرار
                ↓
        بناء الـ Schema الموحد وحساب نسبة الثقة الإجمالية
        """
        result = deepcopy(_ANALYSIS_SCHEMA)
        now_iso = datetime.utcnow().isoformat()

        # Metadata
        result["source"]["url"] = source_url
        result["source"]["title"] = title
        result["source"]["retrieved_at"] = now_iso
        result["source"]["source_type"] = source_type
        result["source_url"] = source_url
        result["title"] = title
        result["timestamp"] = now_iso

        # 1. Fast deterministic contextual extraction
        cves_ctx = self.extract_cves(text)
        cvss_scores = self.extract_cvss(text)
        techs_ctx = self.extract_techniques(text)
        tools_ctx = self.extract_tools(text)
        bypasses_ctx = self.extract_bypass_techniques(text)
        payloads_ctx = self.extract_payloads(text, source_url=source_url)
        aff_tech = self.detect_affected_tech(text)
        pattern_claims = self.extract_claims(text, bypasses_ctx, techs_ctx)

        # Populate structured and legacy fields
        result["cves"] = cves_ctx
        result["related_cves"] = [c["id"] for c in cves_ctx]
        result["cvss_scores"] = cvss_scores
        result["cvss_score"] = cvss_scores[0] if cvss_scores else None
        result["techniques"] = techs_ctx
        result["technique_names"] = [t["technique"] for t in techs_ctx]
        result["tools"] = tools_ctx
        result["related_tools"] = [t["tool"] for t in tools_ctx]
        result["bypass_methods"] = bypasses_ctx
        result["bypass_techniques"] = [b["bypass"] for b in bypasses_ctx]
        result["payloads"] = payloads_ctx
        result["raw_payloads"] = [p["payload"] for p in payloads_ctx]
        result["affected_technologies"] = aff_tech
        result["severity"] = self.detect_severity(text)
        result["claims"] = pattern_claims

        # Embedding text
        cve_str = " ".join(result["related_cves"])
        tech_str = " ".join(result["technique_names"])
        result["embedding_text"] = f"{text[:800]} CVEs: {cve_str} Techniques: {tech_str}".strip()

        # 2. Targeted AI Analysis
        if use_ai and text.strip():
            # Build targeted snippets to avoid sending huge texts blindly
            snippets = []
            for c in cves_ctx[:3]:
                snippets.append(f"CVE Evidence: {c['context']}")
            for t in techs_ctx[:4]:
                if t.get("matches"):
                    snippets.append(f"Technique ({t['technique']}): {t['matches'][0]['context']}")
            for b in bypasses_ctx[:3]:
                snippets.append(f"Bypass: {b['context']}")

            ai_result = await self.ai_summarize(
                text=text,
                source_url=source_url,
                context_snippets=snippets if snippets else None
            )

            result["summary"] = ai_result.get("summary", text[:250].strip())
            result["key_learnings"] = ai_result.get("key_learnings", [])
            result["prerequisites"] = ai_result.get("prerequisites", [])
            result["exploit_chain_hints"] = ai_result.get("exploit_chain_hints", [])

            # Merge AI claims if present
            ai_claims = ai_result.get("claims", [])
            if isinstance(ai_claims, list):
                result["claims"].extend(ai_claims)
                result["claims"] = deduplicate_items(result["claims"], key="claim")
        else:
            lines = [l.strip() for l in text.splitlines() if l.strip()]
            result["summary"] = " ".join(lines[:3])[:300]

        # 3. Overall confidence calculation and review requirement
        confidence_points = 0.4
        if result["techniques"]:
            avg_tech_conf = sum(t.get("confidence", 0.5) for t in result["techniques"]) / len(result["techniques"])
            confidence_points = max(confidence_points, avg_tech_conf)
        if result["cves"]:
            confidence_points = min(0.95, confidence_points + 0.1)
        if result["key_learnings"]:
            confidence_points = min(0.95, confidence_points + 0.05)

        result["confidence"] = round(confidence_points, 2)
        result["requires_review"] = result["confidence"] < 0.60 or len(result["techniques"]) == 0

        log.info(
            f"[ANALYZE] {source_url[:45]} | "
            f"CVEs={len(result['cves'])} | "
            f"Techs={len(result['techniques'])} | "
            f"Confidence={result['confidence']} | "
            f"Review={result['requires_review']}"
        )

        return result

    async def analyze_cve_entry(self, cve_data: Dict) -> Dict[str, Any]:
        """يحلّل مدخل CVE من NVD API بصيغة موحدة"""
        cve = cve_data.get("cve", cve_data)
        cve_id = cve.get("id", "") or cve.get("CVE_ID", "")
        descriptions = cve.get("descriptions", [])
        desc_text = " ".join(
            d.get("value", "") for d in descriptions if d.get("lang") == "en"
        )
        metrics = cve.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [{}])
        score = None
        if cvss_v3:
            score = cvss_v3[0].get("cvssData", {}).get("baseScore")
        published = cve.get("published", "")

        result = await self.analyze(
            text=desc_text,
            source_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            title=f"NVD Advisory: {cve_id}",
            source_type="cve",
            use_ai=False
        )

        result["cve_id"] = cve_id
        result["cves"] = [{"id": cve_id, "context": desc_text[:300]}]
        result["related_cves"] = [cve_id]
        if score is not None:
            result["cvss_score"] = float(score)
            result["cvss_scores"] = [float(score)]
            result["severity"] = (
                "Critical" if float(score) >= 9.0 else
                "High" if float(score) >= 7.0 else
                "Medium" if float(score) >= 4.0 else "Low"
            )
        result["published"] = published
        return result

    async def analyze_batch(
        self, items: List[Dict], source_type: str = "article", use_ai: bool = True
    ) -> List[Dict[str, Any]]:
        """تحليل دفعة متزامنة مع التحكم في التزامن (Semaphore)"""
        sem = asyncio.Semaphore(3)

        async def _process(item):
            async with sem:
                text = item.get("text") or item.get("content") or item.get("description", "")
                url = item.get("url") or item.get("source_url", "")
                title = item.get("title", "")
                if not text:
                    return None
                return await self.analyze(
                    text=text,
                    source_url=url,
                    title=title,
                    source_type=source_type,
                    use_ai=use_ai
                )

        tasks = [_process(item) for item in items]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return [r for r in results if r is not None]
