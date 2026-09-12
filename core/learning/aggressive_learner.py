"""
Aggressive Learner — Knowledge Saturation Engine
"Aggressive Knowledge Absorption + Real-time Vulnerability Mastery"

يقوم بامتصاص كل البيانات والمعرفة الخاصة بتكنولوجيا الهدف قبل بدء الفحص:
1. كشف الـ Tech Stack (Framework, CMS, DB, Server, Frontend, Auth)
2. جلب كل الـ CVEs ذات الصلة من NVD و CISA KEV
3. استخراج الـ Payloads المصنفة والملائمة
4. استخراج طرق تجاوز الـ WAF والـ Filters
5. بناء سلاسل الاستغلال (Exploit Chains)
6. تخزين ومؤشرة المعرفة في قاعدة المعرفة (Knowledge Base)
"""
import asyncio
import json
import logging
import os
import re
import time
from copy import deepcopy
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

from core.learning.analyzer import DeepAnalyzer, deduplicate_items, normalize_text
from core.learning.fetcher import IntelligenceFetcher
from core.learning.knowledge_base import KnowledgeBase

log = logging.getLogger("learning.aggressive")

# ── Tech Stack Signatures ───────────────────────────────────────────────────
TECH_SIGNATURES: Dict[str, Dict[str, List[str]]] = {
    "framework": {
        "django": ["csrftoken", "django", "__admin__", "csrfmiddlewaretoken"],
        "laravel": ["laravel_session", "x-xsrf-token", "laravel", "xsrf-token"],
        "spring": ["jsessionid", "spring", "x-application-context", "whitelabel error page"],
        "express": ["connect.sid", "express", "x-powered-by: express"],
        "asp.net": ["asp.net_sessionid", "__viewstate", "x-aspnet-version", "x-powered-by: asp.net"],
        "rails": ["_rails_session", "x-csrf-token", "actionpack", "ruby on rails"],
        "flask": ["session=", "werkzeug", "flask"],
        "fastapi": ["fastapi", "openapi.json", "docs/oauth2"],
    },
    "cms": {
        "wordpress": ["wp-content", "wp-includes", "wp-json", "xmlrpc.php", "wordpress"],
        "drupal": ["drupal", "drupal.settings", "x-generator: drupal", "/sites/default/"],
        "joomla": ["joomla", "/administrator/", "/media/system/js/"],
        "magento": ["magento", "mage-messages", "/static/frontend/"],
        "ghost": ["ghost-root", "ghost-head", "x-ghost-cache"],
    },
    "database_hints": {
        "mysql": ["mysql", "mariadb", "mysql_fetch", "syntax error in query"],
        "postgresql": ["postgresql", "pg_query", "psycopg2", "pg_catalog"],
        "mongodb": ["mongodb", "bson", "mongoclient", "$oid"],
        "sqlite": ["sqlite", "sqlite3", "sqlite_master"],
        "mssql": ["microsoft sql server", "sqloledb", "ole db provider"],
        "redis": ["redis", "redis_version", "err unknown command"],
    },
    "server": {
        "nginx": ["nginx", "x-powered-by: nginx"],
        "apache": ["apache", "x-powered-by: apache", "htaccess"],
        "iis": ["microsoft-iis", "iis"],
        "caddy": ["caddy"],
        "cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
    },
    "frontend": {
        "react": ["react", "react-dom", "_reactRootContainer", "reactroot"],
        "vue": ["vue", "data-v-", "vue-router", "__vue__"],
        "angular": ["ng-version", "ng-app", "_ngcontent", "angular"],
        "jquery": ["jquery", "jquery.min.js"],
        "bootstrap": ["bootstrap", "bootstrap.min.css"],
        "tailwind": ["tailwind", "tailwind.css"],
    },
    "auth": {
        "jwt": ["bearer", "eyj", "jwt", "authorization: bearer"],
        "session_cookie": ["sessionid", "connect.sid", "phpsessid", "jsessionid"],
        "oauth": ["oauth", "authorize", "token_endpoint", "openid"],
        "basic": ["basic realm", "www-authenticate"],
    }
}


class AggressiveLearner:
    """
    محرك التعلم المكثف — Pre-Scan Saturation
    يمتص المعرفة الأمنية الخاصة بنوع وبيئة الهدف قبل الفحص.
    """

    def __init__(
        self,
        kb: Optional[KnowledgeBase] = None,
        resource_manager=None,
        fetcher: Optional[IntelligenceFetcher] = None,
        analyzer: Optional[DeepAnalyzer] = None,
    ):
        self.kb = kb or KnowledgeBase()
        self.rm = resource_manager
        self.fetcher = fetcher or IntelligenceFetcher()
        self.analyzer = analyzer or DeepAnalyzer(resource_manager=resource_manager)
        self.learning_stats: Dict[str, Any] = {
            "articles_learned": 0,
            "cves_indexed": 0,
            "payloads_discovered": 0,
            "exploit_chains_built": 0,
            "bypass_techniques_learned": 0,
            "last_saturation": None,
        }

    # ── Tech Stack Detection ─────────────────────────────────────────────────

    async def detect_tech_stack(
        self,
        target_url: str,
        html: str = "",
        headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        كشف متقدم للـ Tech Stack:
        1. فحص الهيدرز والكوكيز
        2. مطابقة الـ Signatures في الـ HTML والـ Scripts
        3. استنتاج بالـ AI لتأكيد التكنولوجيات
        """
        headers = headers or {}
        combined_text = (
            f"{target_url}\n"
            f"Headers: {json.dumps(headers)}\n"
            f"HTML: {html[:4000]}"
        ).lower()

        detected: Dict[str, List[str]] = {
            "framework": [],
            "cms": [],
            "database_hints": [],
            "server": [],
            "frontend": [],
            "auth": [],
        }

        # 1. Signature Matching
        for category, signature_dict in TECH_SIGNATURES.items():
            for tech_name, patterns in signature_dict.items():
                if any(p.lower() in combined_text for p in patterns):
                    detected[category].append(tech_name)

        # 2. Extract Server / X-Powered-By explicitly
        server_hdr = str(headers.get("Server", headers.get("server", ""))).lower()
        if server_hdr:
            for s in ["nginx", "apache", "iis", "caddy", "cloudflare", "gunicorn", "uvicorn"]:
                if s in server_hdr and s not in detected["server"]:
                    detected["server"].append(s)

        x_powered = str(headers.get("X-Powered-By", headers.get("x-powered-by", ""))).lower()
        if x_powered:
            for f in ["php", "express", "asp.net", "next.js", "nuxt", "laravel"]:
                if f in x_powered and f not in detected["framework"]:
                    detected["framework"].append(f)

        # Flatten list of all unique tech keywords
        all_techs: List[str] = []
        for cat, items in detected.items():
            for item in items:
                if item not in all_techs:
                    all_techs.append(item)

        # Fallback defaults if none detected
        if not all_techs:
            parsed = urlparse(target_url)
            all_techs = ["web_application", "http"]

        result = {
            "target": target_url,
            "classified": detected,
            "detected_technologies": all_techs,
            "primary_technology": all_techs[0] if all_techs else "web_application",
            "confidence": min(0.95, 0.40 + len(all_techs) * 0.1),
        }

        log.info(f"[AGGRESSIVE] Detected Tech Stack for {target_url}: {all_techs}")
        return result

    # ── Parallel Saturation Modules ──────────────────────────────────────────

    async def _learn_cves_for_tech(
        self,
        tech_list: List[str],
        emit_fn: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """
        جلب وتخزين كل الـ CVEs الحديثة من NVD و CISA KEV للتكنولوجيات المكتشفة
        """
        all_cves: List[Dict[str, Any]] = []

        # 1. CISA KEV (Most Critical)
        try:
            if emit_fn:
                await emit_fn("[SATURATION] Querying CISA KEV for target technologies...")
            kev_list = await self.fetcher.fetch_cisa_kev()
            for entry in kev_list:
                desc = f"{entry.get('shortDescription', '')} {entry.get('notes', '')}".lower()
                cve_id = entry.get("cveID", "")
                if any(tech.lower() in desc for tech in tech_list):
                    cve_obj = {
                        "cve_id": cve_id,
                        "description": desc[:500],
                        "cvss_score": 8.5,
                        "severity": "High",
                        "published": entry.get("dateAdded", ""),
                        "affected_technologies": [t for t in tech_list if t.lower() in desc],
                        "source": "cisa_kev",
                    }
                    self.kb.save_cve(cve_obj)
                    all_cves.append(cve_obj)
                    self.learning_stats["cves_indexed"] += 1
        except Exception as e:
            log.warning(f"CISA KEV tech learning failed: {e}")

        # 2. NVD CVEs for top 3 detected technologies
        for tech in tech_list[:3]:
            if tech in ["http", "web_application"]:
                continue
            try:
                if emit_fn:
                    await emit_fn(f"[SATURATION] Querying NVD for CVEs: {tech}")
                nvd_entries = await self.fetcher.fetch_nvd_cves(keyword=tech)
                for entry in nvd_entries[:15]:
                    analysis = await self.analyzer.analyze_cve_entry(entry)
                    if analysis.get("cve_id"):
                        self.kb.save_cve(analysis)
                        all_cves.append(analysis)
                        self.learning_stats["cves_indexed"] += 1
            except Exception as e:
                log.warning(f"NVD CVE learning for {tech} failed: {e}")

        return deduplicate_items(all_cves, key="cve_id")

    async def _learn_payloads_for_tech(
        self,
        tech_list: List[str],
        emit_fn: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """
        جلب الـ Payloads المصنفة من GitHub و PayloadsAllTheThings المطابقة للـ Tech Stack
        """
        categories_map: Dict[str, List[str]] = {
            "sql": ["SQL Injection"],
            "mysql": ["SQL Injection"],
            "postgresql": ["SQL Injection"],
            "django": ["Server Side Template Injection", "SQL Injection"],
            "flask": ["Server Side Template Injection"],
            "spring": ["Server Side Template Injection", "Java Deserialization"],
            "express": ["NodeJS", "XSS Injection"],
            "wordpress": ["XSS Injection", "SQL Injection", "File Inclusion"],
            "jwt": ["JSON Web Token"],
            "php": ["File Inclusion", "PHP Code Injection"],
        }

        needed_categories: Set[str] = {"XSS Injection", "SQL Injection"}
        for tech in tech_list:
            t_low = tech.lower()
            for key, cats in categories_map.items():
                if key in t_low:
                    needed_categories.update(cats)

        payload_results: List[Dict[str, Any]] = []

        for cat in list(needed_categories)[:4]:
            try:
                if emit_fn:
                    await emit_fn(f"[SATURATION] Learning Payloads for: {cat}")
                content = await self.fetcher.fetch_payloads_all_things(cat)
                if not content:
                    continue
                extracted = self.analyzer.extract_payloads(content, source_url=f"PayloadsAllTheThings/{cat}")
                for p in extracted[:12]:
                    p_text = p.get("payload", "")
                    p_cat = p.get("category", cat.lower().split()[0])
                    if len(p_text) > 4:
                        self.kb.save_payload(
                            payload_text=p_text,
                            payload_type=p_cat,
                            technologies=tech_list,
                            source_url=f"PayloadsAllTheThings/{cat}",
                            severity="High"
                        )
                        payload_results.append(p)
                        self.learning_stats["payloads_discovered"] += 1
            except Exception as e:
                log.warning(f"Payload learning for {cat} failed: {e}")

        return deduplicate_items(payload_results, key="payload")

    async def _learn_bypass_techniques_for_tech(
        self,
        tech_list: List[str],
        emit_fn: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """
        استخراج طرق تجاوز الـ WAF والـ Filters ذات الصلة
        """
        if emit_fn:
            await emit_fn("[SATURATION] Indexing WAF & Filter Bypass techniques...")

        sample_bypass_data = [
            {"name": "WAF Charset/Encoding Bypass", "category": "waf_bypass", "description": "Use UTF-8 overlong / double URL encoding to bypass signature inspection", "bypasses": ["double encoding", "unicode bypass"]},
            {"name": "SQLi Comment Injection", "category": "sqli_bypass", "description": "Use inline comments /**/ or NULL bytes %00 to break SQL keywords filters", "bypasses": ["comment injection", "null byte"]},
            {"name": "XSS Mixed-Case / Event Obfuscation", "category": "xss_bypass", "description": "Obfuscate script tags using svg/onload and mixed casing", "bypasses": ["case variation", "filter evasion"]},
            {"name": "Chunked Transfer Encoding Evasion", "category": "waf_bypass", "description": "Split request body using Transfer-Encoding: chunked to evade inspection engines", "bypasses": ["chunked transfer", "header injection bypass"]}
        ]

        bypasses: List[Dict[str, Any]] = []
        for b in sample_bypass_data:
            tid = self.kb.save_technique(
                technique_name=b["name"],
                category=b["category"],
                description=b["description"],
                bypass_methods=b.get("bypasses", []),
                affected_tech=tech_list
            )
            bypasses.append({"id": tid, **b})
            self.learning_stats["bypass_techniques_learned"] += 1

        return bypasses

    async def _learn_writeups_for_tech(
        self,
        tech_list: List[str],
        emit_fn: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """
        جلب وتحليل المقالات والشروحات ذات الصلة من Medium
        """
        if emit_fn:
            await emit_fn("[SATURATION] Fetching security writeups & intelligence...")

        articles_learned: List[Dict[str, Any]] = []
        for tag in ["bug-bounty", "web-security"]:
            try:
                articles = await self.fetcher.fetch_medium_rss(tag=tag, limit=8)
                for art in articles:
                    text = art.get("text", "")
                    if len(text) < 150:
                        continue
                    analysis = await self.analyzer.analyze(
                        text=text,
                        source_url=art.get("url", ""),
                        title=art.get("title", ""),
                        source_type="article",
                        use_ai=False
                    )
                    # Enrich with detected target techs
                    analysis["affected_technologies"].extend(tech_list)
                    analysis["affected_technologies"] = list(set(analysis["affected_technologies"]))

                    self.kb.save_article(analysis)
                    articles_learned.append(analysis)
                    self.learning_stats["articles_learned"] += 1
            except Exception as e:
                log.warning(f"Writeup learning failed: {e}")

        return articles_learned

    async def _build_exploit_chains_for_tech(
        self,
        tech_list: List[str],
        cves: List[Dict],
        emit_fn: Optional[Callable] = None
    ) -> List[Dict[str, Any]]:
        """
        توليد وتخزين سلاسل استغلال مقترحة (Exploit Chains)
        مثل: Recon -> Param Discovery -> Reflected XSS -> Auth Steal -> Account Takeover
        """
        if emit_fn:
            await emit_fn("[SATURATION] Synthesizing Multi-step Exploit Chains...")

        chains: List[Dict[str, Any]] = []

        # 1. Chain: Web Injection to Account Takeover
        chains.append({
            "id": "chain_web_to_ato",
            "name": "Web Injection -> Session Hijacking -> Account Takeover",
            "description": "Exploit reflected/stored XSS to exfiltrate session tokens and bypass auth controls",
            "steps": [
                "1. Observe input reflection in parameters",
                "2. Apply context-appropriate XSS bypass payload",
                "3. Harvest authenticated session cookie / JWT token",
                "4. Access privileged endpoints using hijacked credentials"
            ],
            "techniques": ["xss", "auth"],
            "severity": "High",
            "target_techs": tech_list,
        })

        # 2. Chain: SQLi to Database Dump
        if any(t in ["mysql", "postgresql", "sql", "django", "laravel", "php"] for t in tech_list):
            chains.append({
                "id": "chain_sqli_dump",
                "name": "Parameter Fuzzing -> SQL Injection -> Data Extraction",
                "description": "Detect vulnerable parameter via time-based/error blind SQLi and extract schema and users table",
                "steps": [
                    "1. Test parameter with arithmetic/boolean probes",
                    "2. Confirm DBMS fingerprint and syntax",
                    "3. Extract database banner and current user",
                    "4. Enumerate schema and sensitive data"
                ],
                "techniques": ["sqli"],
                "severity": "Critical",
                "target_techs": tech_list,
            })

        # 3. Chain: SSRF to Cloud Metadata
        if any(t in ["aws", "azure", "gcp", "docker", "kubernetes"] for t in tech_list):
            chains.append({
                "id": "chain_ssrf_cloud",
                "name": "URL Redirection / SSRF -> Cloud Metadata Token Access",
                "description": "Leverage internal request forgery to reach IMDS / 169.254.169.254 and obtain IAM credentials",
                "steps": [
                    "1. Identify parameter accepting external URLs/webhooks",
                    "2. Probe loopback and metadata address (169.254.169.254)",
                    "3. Retrieve temporary IAM role security credentials",
                    "4. Pivot into cloud control plane"
                ],
                "techniques": ["ssrf", "auth"],
                "severity": "Critical",
                "target_techs": tech_list,
            })

        for ch in chains:
            with self.kb._conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO exploit_chains
                    (id, name, description, steps, techniques, cve_ids, severity, source_url, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                    ch["id"],
                    ch["name"],
                    ch["description"],
                    json.dumps(ch["steps"]),
                    json.dumps(ch["techniques"]),
                    json.dumps([c.get("cve_id", c.get("id", "")) for c in cves[:3]]),
                    ch["severity"],
                    "synthesized_brain_chain",
                    time.time()
                ))
            self.learning_stats["exploit_chains_built"] += 1

        return chains

    # ── Main Pre-Scan Saturation Entry Point ─────────────────────────────────

    async def aggressive_prescan_saturation(
        self,
        target_url: str,
        html: str = "",
        headers: Optional[Dict[str, str]] = None,
        emit_fn: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        دورة الإشباع المعرفي الكاملة قبل الفحص (Pre-Scan Saturation):
        1. كشف الـ Tech Stack
        2. جلب الـ CVEs ذات الصلة بالتوازي
        3. جلب الـ Payloads المصنفة
        4. استخراج طرق تجاوز الـ WAF
        5. تحليل الـ Writeups
        6. بناء سلاسل الاستغلال (Exploit Chains)
        7. حفظ وتحديث مؤشرات الـ Knowledge Base
        """
        t0 = time.time()
        if emit_fn:
            await emit_fn(f"[SATURATION] === Aggressive Knowledge Saturation Starting for: {target_url} ===")

        # Step 1: Detect Tech Stack
        tech_info = await self.detect_tech_stack(target_url, html=html, headers=headers)
        tech_list = tech_info.get("detected_technologies", [])
        if emit_fn:
            await emit_fn(f"[SATURATION] Target Technologies: {', '.join(tech_list)}")

        # Step 2: Parallel Ingestion Tasks
        cves_task = self._learn_cves_for_tech(tech_list, emit_fn=emit_fn)
        payloads_task = self._learn_payloads_for_tech(tech_list, emit_fn=emit_fn)
        bypasses_task = self._learn_bypass_techniques_for_tech(tech_list, emit_fn=emit_fn)
        writeups_task = self._learn_writeups_for_tech(tech_list, emit_fn=emit_fn)

        results = await asyncio.gather(
            cves_task, payloads_task, bypasses_task, writeups_task,
            return_exceptions=True
        )

        cves = results[0] if isinstance(results[0], list) else []
        payloads = results[1] if isinstance(results[1], list) else []
        bypasses = results[2] if isinstance(results[2], list) else []
        writeups = results[3] if isinstance(results[3], list) else []

        # Step 3: Build Exploit Chains
        chains = await self._build_exploit_chains_for_tech(tech_list, cves, emit_fn=emit_fn)

        # Step 4: Flush vectors to disk
        self.kb.flush_vectors()
        duration = round(time.time() - t0, 2)
        self.learning_stats["last_saturation"] = datetime.utcnow().isoformat()

        stats = self.kb.stats()
        if emit_fn:
            await emit_fn(
                f"[SATURATION] Complete in {duration}s | "
                f"CVEs: {len(cves)}, Payloads: {len(payloads)}, "
                f"Chains: {len(chains)}, Articles: {len(writeups)}"
            )

        report = {
            "target": target_url,
            "duration_seconds": duration,
            "tech_stack": tech_info,
            "cves_indexed": len(cves),
            "payloads_discovered": len(payloads),
            "bypass_techniques": len(bypasses),
            "exploit_chains": chains,
            "cve_samples": cves[:5],
            "top_payloads": payloads[:8],
            "kb_stats": stats,
            "ready_to_exploit": True,
        }

        return report
