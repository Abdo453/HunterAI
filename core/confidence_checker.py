"""
Confidence Checker — نظام التحقق من اليقين في الثغرات
═══════════════════════════════════════════════════════
الفكرة:
  لو موديل شاكك في وجود ثغرة → يفعّل "Confidence Check Protocol"
  
  الـ Protocol:
  1. كل موديلات الـ API تشتغل بالتوازي (بدون GPU محلي)
  2. موديلين Security يفتحوا المتصفح + BurpSuite للتحقق الفعلي
  3. النتائج تتجمع → Confidence Score نهائي
  4. لو > 70% → تأكيد الثغرة
  5. لو < 70% → False Positive

الـ Trigger keywords:
  "not sure", "might be", "possibly", "شاكك", "ممكن", "يبدو"
"""
import asyncio
import httpx
import os
import json
import time
import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Any

log = logging.getLogger("confidence_checker")

# OpenRouter models for parallel verification
OPENROUTER_MODELS = [
    {"id": "openai/gpt-4o",                          "role": "web_security_expert",    "name": "GPT-4o"},
    {"id": "anthropic/claude-sonnet-4",               "role": "vulnerability_analyst",  "name": "Claude Sonnet"},
    {"id": "google/gemini-2.5-flash",                 "role": "recon_specialist",       "name": "Gemini Flash"},
    {"id": "meta-llama/llama-3.1-70b-instruct",       "role": "exploit_researcher",     "name": "Llama 70B"},
    {"id": "mistralai/mistral-large",                 "role": "security_verifier",      "name": "Mistral Large"},
]

DOUBT_PATTERNS = [
    r"not sure", r"might be", r"possibly", r"could be", r"appears to",
    r"seems like", r"potential(ly)?", r"suspected?", r"unconfirmed",
    r"شاكك", r"ممكن", r"يبدو", r"محتمل", r"غير متأكد",
    r"may indicate", r"worth investigating", r"needs verification",
    r"false positive", r"cannot confirm", r"unclear if",
]


@dataclass
class ModelVerdict:
    model_name: str
    role: str
    verdict: str          # "CONFIRMED" | "FALSE_POSITIVE" | "UNCERTAIN"
    confidence: float     # 0.0 - 1.0
    evidence: str
    reasoning: str
    response_time: float


@dataclass
class ConfidenceResult:
    original_claim: str
    target: str
    final_verdict: str    # "CONFIRMED" | "FALSE_POSITIVE" | "UNCERTAIN"
    confidence_score: float
    verdicts: List[ModelVerdict] = field(default_factory=list)
    browser_evidence: str = ""
    burpsuite_findings: str = ""
    consensus_reasoning: str = ""
    duration: float = 0.0
    models_agreed: int = 0
    models_disagreed: int = 0


class ConfidenceChecker:
    """
    نظام التحقق من الثغرات عند الشك
    يشغّل كل موديلات الـ API بالتوازي + browser verification
    """

    def __init__(self, progress_cb: Optional[Callable] = None):
        self.cb = progress_cb
        self.openrouter_key = os.getenv("OPENROUTER_API_KEY", "")
        self.openrouter_base = "https://openrouter.ai/api/v1"

    async def _emit(self, event: str, data: dict):
        if self.cb:
            try:
                await self.cb({"event": event, **data})
            except Exception:
                pass

    # ── تحقق هل الموديل شاكك ────────────────────────────────
    def is_uncertain(self, model_response: str) -> tuple[bool, str]:
        """
        يكتشف هل الموديل شاكك في نتيجته
        Returns: (is_uncertain, matched_pattern)
        """
        text = model_response.lower()
        for pattern in DOUBT_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True, pattern
        return False, ""

    # ── Confidence Check Protocol ─────────────────────────────
    async def verify(
        self,
        claim: str,           # الادعاء اللي الموديل شاكك فيه
        target: str,          # الهدف (URL/IP)
        context: str = "",    # context إضافي
        use_browser: bool = True,
    ) -> ConfidenceResult:
        """
        البروتوكول الكامل للتحقق:
        1. كل API models بالتوازي
        2. Browser verification (اختياري)
        3. جمع النتائج + تصويت
        """
        t0 = time.time()

        await self._emit("confidence_check_start", {
            "claim": claim[:100],
            "target": target,
            "models": len(OPENROUTER_MODELS),
            "browser": use_browser,
        })

        # ── Phase 1: API Models بالتوازي ──────────────────────
        await self._emit("confidence_phase", {
            "phase": 1,
            "message": f"Launching {len(OPENROUTER_MODELS)} AI models in parallel..."
        })

        # كل موديلات OpenRouter بالتوازي
        api_tasks = [
            self._query_model(model, claim, target, context)
            for model in OPENROUTER_MODELS
        ]

        # Browser + BurpSuite بالتوازي مع الـ API calls
        if use_browser:
            browser_task = asyncio.create_task(
                self._browser_verify(target, claim)
            )
        else:
            browser_task = None

        # انتظر كل الـ API calls
        verdicts_raw = await asyncio.gather(*api_tasks, return_exceptions=True)
        verdicts = [v for v in verdicts_raw if isinstance(v, ModelVerdict)]

        # انتظر الـ browser
        browser_evidence = ""
        burpsuite_findings = ""
        if browser_task:
            browser_result = await browser_task
            browser_evidence = browser_result.get("evidence", "")
            burpsuite_findings = browser_result.get("burpsuite", "")

        # ── Phase 2: تجميع النتائج ────────────────────────────
        await self._emit("confidence_phase", {
            "phase": 2,
            "message": "Calculating consensus..."
        })

        result = self._calculate_consensus(
            claim=claim,
            target=target,
            verdicts=verdicts,
            browser_evidence=browser_evidence,
            burpsuite_findings=burpsuite_findings,
            duration=time.time() - t0,
        )

        await self._emit("confidence_result", {
            "verdict": result.final_verdict,
            "score": result.confidence_score,
            "agreed": result.models_agreed,
            "disagreed": result.models_disagreed,
            "browser_evidence": bool(browser_evidence),
        })

        return result

    async def _query_model(
        self, model: dict, claim: str, target: str, context: str
    ) -> ModelVerdict:
        """استدعاء موديل OpenRouter واحد"""
        t0 = time.time()

        system_prompt = f"""You are a {model['role']} performing vulnerability verification.
Your job: determine if the following security claim is CONFIRMED, FALSE_POSITIVE, or UNCERTAIN.

Analyze carefully:
- Technical plausibility
- Common false positive patterns
- Evidence quality

Respond in JSON format:
{{
  "verdict": "CONFIRMED|FALSE_POSITIVE|UNCERTAIN",
  "confidence": 0.0-1.0,
  "evidence": "technical evidence",
  "reasoning": "brief explanation"
}}"""

        user_msg = f"""Target: {target}
Context: {context[:300] if context else 'No additional context'}

Security Claim to verify:
{claim}

Provide your verdict as JSON."""

        if not self.openrouter_key:
            return ModelVerdict(
                model_name=model["name"], role=model["role"],
                verdict="UNCERTAIN", confidence=0.5,
                evidence="No API key", reasoning="OpenRouter not configured",
                response_time=0.0
            )

        try:
            async with httpx.AsyncClient(timeout=30, trust_env=False, verify=False) as c:
                r = await c.post(

                    f"{self.openrouter_base}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.openrouter_key}",
                        "HTTP-Referer": "https://pentestai.local",
                        "X-Title": "PentestAI Unified",
                    },
                    json={
                        "model": model["id"],
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_msg},
                        ],
                        "max_tokens": 400,
                        "temperature": 0.1,
                        "response_format": {"type": "json_object"},
                    }
                )
                r.raise_for_status()
                content = r.json()["choices"][0]["message"]["content"]

                # Parse JSON response
                try:
                    parsed = json.loads(content)
                    verdict_str = parsed.get("verdict", "UNCERTAIN").upper()
                    if verdict_str not in ("CONFIRMED", "FALSE_POSITIVE", "UNCERTAIN"):
                        verdict_str = "UNCERTAIN"
                    confidence = float(parsed.get("confidence", 0.5))
                    evidence = parsed.get("evidence", "")
                    reasoning = parsed.get("reasoning", "")
                except json.JSONDecodeError:
                    # Extract from text if JSON fails
                    verdict_str = "CONFIRMED" if "confirmed" in content.lower() else \
                                  "FALSE_POSITIVE" if "false positive" in content.lower() else "UNCERTAIN"
                    confidence = 0.6
                    evidence = content[:200]
                    reasoning = content[:200]

                rt = time.time() - t0
                await self._emit("model_verdict", {
                    "model": model["name"],
                    "verdict": verdict_str,
                    "confidence": confidence,
                    "time": round(rt, 1),
                })

                return ModelVerdict(
                    model_name=model["name"], role=model["role"],
                    verdict=verdict_str, confidence=confidence,
                    evidence=evidence, reasoning=reasoning,
                    response_time=rt,
                )

        except Exception as e:
            log.warning(f"[{model['name']}] Error: {e}")
            return ModelVerdict(
                model_name=model["name"], role=model["role"],
                verdict="UNCERTAIN", confidence=0.5,
                evidence=f"Error: {str(e)[:100]}", reasoning="API call failed",
                response_time=time.time() - t0,
            )

    async def _browser_verify(self, target: str, claim: str) -> dict:
        """
        Browser verification:
        1. Selenium يفتح المتصفح
        2. يحاول يتحقق من الثغرة
        3. BurpSuite/ZAP يسجل الـ traffic
        """
        result = {"evidence": "", "burpsuite": "", "screenshots": []}

        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.common.exceptions import WebDriverException

            await self._emit("browser_start", {
                "target": target,
                "action": "Opening browser for verification..."
            })

            opts = Options()
            opts.add_argument("--no-sandbox")
            opts.add_argument("--disable-dev-shm-usage")
            opts.add_argument("--disable-gpu")
            opts.add_argument("--ignore-certificate-errors")
            opts.add_argument("--ignore-ssl-errors=yes")
            opts.add_argument("--allow-insecure-localhost")

            import shutil
            for bin_name in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"]:
                loc = shutil.which(bin_name)
                if loc:
                    opts.binary_location = loc
                    break

            # BurpSuite proxy (لو شغال)
            burp_host = os.getenv("BURPSUITE_PROXY", "127.0.0.1:8080")
            zap_host = os.getenv("ZAP_PROXY", "127.0.0.1:8090")

            proxy_set = False
            if os.getenv("USE_PROXY", "false").lower() == "true":
                # جرب BurpSuite أولاً
                if await self._check_proxy(burp_host):
                    opts.add_argument(f"--proxy-server=http://{burp_host}")
                    proxy_set = True
                    result["burpsuite"] = f"Traffic routed through BurpSuite at {burp_host}"
                    await self._emit("proxy_active", {"proxy": "BurpSuite", "addr": burp_host})
                # ثم ZAP
                elif await self._check_proxy(zap_host):
                    opts.add_argument(f"--proxy-server=http://{zap_host}")
                    proxy_set = True
                    result["burpsuite"] = f"Traffic routed through ZAP at {zap_host}"
                    await self._emit("proxy_active", {"proxy": "ZAP", "addr": zap_host})

            # headless لو مش محتاج ترى المتصفح
            if os.getenv("HEADLESS_BROWSER", "true").lower() == "true":
                opts.add_argument("--headless=new")

            driver = None
            driver_path = shutil.which("chromedriver") or shutil.which("chromium-driver") or "/usr/bin/chromedriver"
            try:
                if driver_path and os.path.exists(driver_path):
                    from selenium.webdriver.chrome.service import Service as ChromeService
                    driver = webdriver.Chrome(service=ChromeService(executable_path=driver_path), options=opts)
                else:
                    driver = webdriver.Chrome(options=opts)
            except Exception:
                # Fallback to Firefox / Firefox-ESR (Standard on Kali Linux)
                try:
                    from selenium.webdriver.firefox.options import Options as FirefoxOptions
                    fopts = FirefoxOptions()
                    if os.getenv("HEADLESS_BROWSER", "true").lower() == "true":
                        fopts.add_argument("-headless")
                    fopts.set_preference("acceptInsecureCerts", True)
                    fopts.set_preference("webdriver_accept_untrusted_certs", True)
                    if proxy_set and burp_host and ":" in burp_host:
                        h_ip, h_port = burp_host.split(":")
                        fopts.set_preference("network.proxy.type", 1)
                        fopts.set_preference("network.proxy.http", h_ip)
                        fopts.set_preference("network.proxy.http_port", int(h_port))
                        fopts.set_preference("network.proxy.ssl", h_ip)
                        fopts.set_preference("network.proxy.ssl_port", int(h_port))
                    for fbin in ["firefox-esr", "firefox"]:
                        floc = shutil.which(fbin)
                        if floc:
                            fopts.binary_location = floc
                            break
                    driver = webdriver.Firefox(options=fopts)
                except Exception as fe:
                    raise RuntimeError(f"Could not initialize Chrome/Chromium or Firefox: {fe}")


            try:
                # افتح الـ target
                if not target.startswith("http"):
                    target_url = f"http://{target}"
                else:
                    target_url = target

                driver.set_page_load_timeout(15)
                driver.get(target_url)

                await asyncio.sleep(2)

                # جمع معلومات
                page_source = driver.page_source[:3000]
                page_title = driver.title
                current_url = driver.current_url

                # فحص علامات الثغرة في الصفحة
                vuln_indicators = self._analyze_page_for_vuln(page_source, claim)

                result["evidence"] = (
                    f"Browser Visit: {current_url}\n"
                    f"Title: {page_title}\n"
                    f"Vulnerability indicators found: {vuln_indicators}\n"
                    f"Proxy: {'Active (' + burp_host + ')' if proxy_set else 'Not used'}"
                )

                # Screenshot
                screenshot_path = f"data/screenshots/verify_{int(time.time())}.png"
                import os as _os
                _os.makedirs("data/screenshots", exist_ok=True)
                driver.save_screenshot(screenshot_path)
                result["screenshots"].append(screenshot_path)

                await self._emit("browser_done", {
                    "url": current_url,
                    "indicators": len(vuln_indicators),
                    "screenshot": screenshot_path,
                    "proxy": proxy_set,
                })

            finally:
                driver.quit()

        except ImportError:
            result["evidence"] = "Selenium not installed (pip install selenium)"
        except Exception as e:
            result["evidence"] = f"Browser error: {str(e)[:200]}"
            log.warning(f"Browser verify failed: {e}")

        return result

    async def _check_proxy(self, addr: str) -> bool:
        """تحقق هل الـ proxy شغال"""
        try:
            host, port = addr.rsplit(":", 1)
            async with httpx.AsyncClient(timeout=2) as c:
                await c.get(f"http://{host}:{port}/")
            return True
        except Exception:
            return False

    def _analyze_page_for_vuln(self, html: str, claim: str) -> list:
        """تحليل HTML للبحث عن علامات الثغرة"""
        indicators = []
        html_lower = html.lower()
        claim_lower = claim.lower()

        # SQL Injection indicators
        if "sql" in claim_lower or "injection" in claim_lower:
            patterns = ["error in your sql", "mysql_fetch", "ora-01", "sqlite", "syntax error"]
            for p in patterns:
                if p in html_lower:
                    indicators.append(f"SQL error: '{p}'")

        # XSS indicators
        if "xss" in claim_lower or "script" in claim_lower:
            if "<script>" in html or "alert(" in html or "onerror=" in html:
                indicators.append("JavaScript execution detected")

        # Directory traversal
        if "traversal" in claim_lower or "lfi" in claim_lower:
            if "root:x:" in html or "[boot loader]" in html:
                indicators.append("File content exposed")

        # Generic error exposure
        if "traceback" in html_lower or "stack trace" in html_lower:
            indicators.append("Error/stacktrace exposed")

        # Version disclosure
        import re
        versions = re.findall(r'(?:apache|nginx|php|python|version)[/\s]+[\d.]+', html_lower)
        if versions:
            indicators.append(f"Version disclosure: {versions[:2]}")

        return indicators

    def _calculate_consensus(
        self,
        claim: str,
        target: str,
        verdicts: List[ModelVerdict],
        browser_evidence: str,
        burpsuite_findings: str,
        duration: float,
    ) -> ConfidenceResult:
        """
        حساب الـ consensus النهائي من كل الأدلة
        """
        if not verdicts:
            return ConfidenceResult(
                original_claim=claim, target=target,
                final_verdict="UNCERTAIN", confidence_score=0.5,
                duration=duration,
            )

        # تصويت الموديلات
        votes = {"CONFIRMED": [], "FALSE_POSITIVE": [], "UNCERTAIN": []}
        for v in verdicts:
            votes[v.verdict].append(v.confidence)

        confirmed_score = sum(votes["CONFIRMED"]) / max(len(verdicts), 1)
        fp_score = sum(votes["FALSE_POSITIVE"]) / max(len(verdicts), 1)
        uncertain_ratio = len(votes["UNCERTAIN"]) / max(len(verdicts), 1)

        # Browser boost
        browser_boost = 0.0
        if browser_evidence and ("indicators found" in browser_evidence):
            import re
            m = re.search(r"indicators found: (\d+)", browser_evidence)
            if m and int(m.group(1)) > 0:
                browser_boost = 0.15

        # BurpSuite boost
        burp_boost = 0.05 if burpsuite_findings else 0.0

        # Final score
        raw_score = confirmed_score + browser_boost + burp_boost

        # Verdict
        if raw_score >= 0.65:
            verdict = "CONFIRMED"
        elif fp_score >= 0.5 or raw_score < 0.3:
            verdict = "FALSE_POSITIVE"
        else:
            verdict = "UNCERTAIN"

        # Reasoning
        reasoning_parts = []
        if votes["CONFIRMED"]:
            reasoning_parts.append(
                f"{len(votes['CONFIRMED'])}/{len(verdicts)} models confirmed"
            )
        if votes["FALSE_POSITIVE"]:
            reasoning_parts.append(
                f"{len(votes['FALSE_POSITIVE'])}/{len(verdicts)} flagged as false positive"
            )
        if browser_boost > 0:
            reasoning_parts.append("Browser verification found indicators")
        if burpsuite_findings:
            reasoning_parts.append("BurpSuite/ZAP traffic captured")

        return ConfidenceResult(
            original_claim=claim,
            target=target,
            final_verdict=verdict,
            confidence_score=min(1.0, raw_score),
            verdicts=verdicts,
            browser_evidence=browser_evidence,
            burpsuite_findings=burpsuite_findings,
            consensus_reasoning=" | ".join(reasoning_parts),
            duration=duration,
            models_agreed=len(votes["CONFIRMED"]),
            models_disagreed=len(votes["FALSE_POSITIVE"]),
        )

    def format_report(self, result: ConfidenceResult) -> str:
        """تقرير منسق للـ confidence check"""
        bars = "#" * int(result.confidence_score * 10) + "." * (10 - int(result.confidence_score * 10))
        verdict_icon = {
            "CONFIRMED": "[CONFIRMED]",
            "FALSE_POSITIVE": "[FALSE_POSITIVE]",
            "UNCERTAIN": "[UNCERTAIN]"
        }.get(result.final_verdict, "[?]")

        lines = [
            "=" * 55,
            "  CONFIDENCE CHECK REPORT",
            "=" * 55,
            f"  Verdict:    {verdict_icon}",
            f"  Score:      [{bars}] {result.confidence_score:.0%}",
            f"  Agreed:     {result.models_agreed} models confirmed",
            f"  Disagreed:  {result.models_disagreed} flagged as FP",
            f"  Duration:   {result.duration:.1f}s",
            "",
            f"  Claim: {result.original_claim[:80]}",
            f"  Target: {result.target}",
            "",
            f"  Reasoning: {result.consensus_reasoning}",
        ]

        if result.browser_evidence:
            lines += ["", "  BROWSER EVIDENCE:", f"  {result.browser_evidence[:200]}"]

        lines += ["", "  MODEL VERDICTS:"]
        for v in result.verdicts:
            icon = {"CONFIRMED": "+", "FALSE_POSITIVE": "-", "UNCERTAIN": "?"}.get(v.verdict, "?")
            lines.append(
                f"    [{icon}] {v.model_name:20} {v.verdict:15} ({v.confidence:.0%}) {v.response_time:.1f}s"
            )

        lines.append("=" * 55)
        return "\n".join(lines)
