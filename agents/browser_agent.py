"""Browser Agent — Selenium + BurpSuite/ZAP proxy"""
import os
from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.browser_tools import BrowserController


from typing import Optional, Dict, Any

class BrowserAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None, proxy: Optional[str] = None, visible: bool = True, auth: Optional[Dict[str, Any]] = None):
        super().__init__("browser_agent", "Browser automation with proxy & visual verification", mgr, cb)
        self.proxy = proxy or (os.getenv("BURPSUITE_PROXY", "127.0.0.1:8080") if os.getenv("USE_PROXY", "false").lower() == "true" else None)
        self.visible = visible
        self.auth = auth or {}
        self.browser = BrowserController(headless=not visible, proxy=self.proxy)

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        url = target if target.startswith("http") else f"https://{target}"
        r = AgentResult(agent_name=self.name, target=target)
        auth = self.auth or task.extra.get("auth", {})
        auth_note = " | 🔐 مصادقة مفعلة" if auth.get("username") or auth.get("cookie") else ""
        await self.emit("start", {"message": f"🌐 تشغيل المتصفح الحي لفحص الهدف: {url} | البروكسي: {self.proxy or 'Direct'}{auth_note}"})

        if not self.browser.start(visible=self.visible, preferred_browser="firefox"):
            r.success = False
            r.errors.append("Browser/Driver not available")
            await self.emit("error", {"message": "لم يتم العثور على مشغل المتصفح (Chromium/Firefox/Chrome)"})
            return r

        try:
            # 1. Automatic Login if credentials provided
            if auth.get("username") and auth.get("password"):
                await self.emit("tool_start", {"tool": "Auto-Login Authentication"})
                login_ok = self.browser.auto_login(
                    username=auth["username"],
                    password=auth["password"],
                    login_url=auth.get("login_url") or url
                )
                await self.emit("tool_done", {"tool": "Auto-Login Authentication", "logged_in": login_ok})

            self.browser.navigate(url)
            title = self.browser.get_title()
            screenshot = self.browser.screenshot("initial.png")
            r.raw_output["title"] = title
            if screenshot: r.raw_output["screenshot"] = screenshot
            await self.emit("tool_done", {"tool": "browser", "title": title})

            # Forms and Interactive Elements
            elements = self.browser.find_interactive_elements()
            forms = elements.get("forms", [])
            r.raw_output["forms"] = str(forms)
            if forms:
                r.findings.append({"type": "forms", "severity": "Info",
                                   "title": f"Found {len(forms)} HTML Forms",
                                   "evidence": str(forms)[:400], "tool": "browser",
                                   "recommendation": "Test all forms for injection vulnerabilities."})

            # Cookies
            cookies = self.browser.get_cookies()
            insecure = [c for c in cookies if not c.get("secure") or not c.get("httpOnly")]
            if insecure:
                r.findings.append({"type": "cookie", "severity": "Medium",
                                   "title": f"Insecure Cookies ({len(insecure)})",
                                   "evidence": str(insecure)[:300], "tool": "browser",
                                   "recommendation": "Set Secure and HttpOnly flags on all sensitive cookies."})

            # JS cookie access
            js_cookies = self.browser.execute_js("return document.cookie;")
            if js_cookies:
                r.findings.append({"type": "cookie_js", "severity": "Low",
                                   "title": "Cookies Accessible via JavaScript",
                                   "evidence": str(js_cookies)[:200], "tool": "browser",
                                   "recommendation": "Add HttpOnly flag to sensitive cookies."})
        finally:
            self.browser.stop()

        await self.emit("complete", {"findings": len(r.findings)})
        return r
