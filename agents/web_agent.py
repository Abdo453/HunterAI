"""Web Agent — directory fuzzing + nuclei + SQLi + XSS"""
from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.web_tools import WebTools


class WebAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__("web_agent", "Web testing — fuzzing, vulns, SQLi, XSS", mgr, cb)
        self.web = WebTools(mgr)

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        url = target if target.startswith("http") else f"http://{target}"
        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Web testing on {url}"})

        # Directory fuzzing (Only for general full scans, not targeted SQLi/Vuln scans)
        if task.mode in ("full", "fuzz", "dirs") and self.mgr.is_available("gobuster"):
            from core.wordlist_manager import WordlistManager
            prof = "deep" if task.mode == "full" else "safe"
            wl = WordlistManager().get_wordlist("directories", profile=prof)
            cmd_str = f"gobuster dir -u {url} -w {wl} -q"
            await self.emit("log", {"message": f"💻 [EXEC] {cmd_str}"})
            await self.emit("tool_start", {"tool": "gobuster"})
            gb = await self.web.gobuster_dir(url, wordlist=wl)
            r.raw_output["gobuster"] = gb.output
            found = [l for l in gb.stdout.splitlines() if "(Status:" in l]
            if found:
                for f_line in found[:5]:
                    await self.emit("log", {"message": f"   -> [FOUND] {f_line}"})
                r.findings.append({"type": "directories", "severity": "Info",
                                   "title": f"Dirs/Files Found ({len(found)})",
                                   "evidence": "\n".join(found[:30]), "tool": "gobuster",
                                   "recommendation": "Review exposed paths for sensitive data."})
            await self.emit("tool_done", {"tool": "gobuster", "found": len(found)})

        # Nuclei
        if self.mgr.is_available("nuclei"):
            cmd_str = f"nuclei -u {url} -severity critical,high,medium -silent"
            await self.emit("log", {"message": f"💻 [EXEC] {cmd_str}"})
            await self.emit("tool_start", {"tool": "nuclei"})
            nc = await self.web.nuclei_scan(url)
            r.raw_output["nuclei"] = nc.output
            for line in nc.stdout.splitlines():
                if not line.strip() or "[" not in line: continue
                lw = line.lower()
                if any(noise in lw for noise in ["missing-security-headers", "missing-cookie-samesite", "wildcard-dns"]):
                    continue  # Filter out low-value scanner noise
                await self.emit("log", {"message": f"   -> [NUCLEI HIT] {line}"})
                if "[critical]" in lw: sev = "Critical"
                elif "[high]" in lw: sev = "High"
                elif "[medium]" in lw: sev = "Medium"
                elif "[low]" in lw: sev = "Low"
                else: sev = "Info"
                r.findings.append({"type": "nuclei", "severity": sev,
                                   "title": line[:100], "evidence": line, "tool": "nuclei",
                                   "recommendation": "Apply vendor patches or mitigations."})
            await self.emit("tool_done", {"tool": "nuclei", "vulns": len(r.findings)})

        # SQLi
        if self.mgr.is_available("sqlmap"):
            cmd_str = f"sqlmap -u \"{url}\" --batch --level=3 --risk=2 --silent"
            await self.emit("log", {"message": f"💻 [EXEC] {cmd_str}"})
            await self.emit("tool_start", {"tool": "sqlmap"})
            sq = await self.web.sqlmap(url)
            r.raw_output["sqlmap"] = sq.output
            if sq.stdout.strip():
                sample_out = "\n".join(sq.stdout.splitlines()[:4])
                await self.emit("log", {"message": f"   -> [SQLMAP LOG]\n{sample_out}"})
            if "is vulnerable" in sq.stdout.lower() or "injection" in sq.stdout.lower():
                try:
                    from core.ai_reasoning_core import AIReasoningCore
                    ai_dec = await AIReasoningCore.analyze_web_tool_output(url, "sqlmap", sq.stdout)
                    r.findings.append({
                        "type": "sqli",
                        "severity": ai_dec.get("severity", "Critical"),
                        "title": ai_dec.get("title", "SQL Injection Confirmed"),
                        "evidence": f"Tool output:\n{sq.stdout[:400]}\n\nReasoning:\n{ai_dec.get('reasoning')}",
                        "tool": "AI-WebAgent (sqlmap)",
                        "recommendation": ai_dec.get("remediation", "Use parameterized queries / prepared statements.")
                    })
                except Exception:
                    r.findings.append({"type": "sqli", "severity": "Critical",
                                       "title": "SQL Injection Found",
                                       "evidence": sq.stdout[:500], "tool": "sqlmap",
                                       "recommendation": "Use parameterized queries / prepared statements."})
            await self.emit("tool_done", {"tool": "sqlmap"})

        # XSS
        if self.mgr.is_available("dalfox"):
            cmd_str = f"dalfox url \"{url}\" -S"
            await self.emit("log", {"message": f"💻 [EXEC] {cmd_str}"})
            await self.emit("tool_start", {"tool": "dalfox"})
            df = await self.web.dalfox(url)
            r.raw_output["dalfox"] = df.output
            xss = [l for l in df.stdout.splitlines() if "[V]" in l or "POC" in l]
            for x in xss:
                await self.emit("log", {"message": f"   -> [DALFOX HIT] {x}"})
                try:
                    from core.ai_reasoning_core import AIReasoningCore
                    ai_dec = await AIReasoningCore.analyze_web_tool_output(url, "dalfox", x)
                    r.findings.append({
                        "type": "xss",
                        "severity": ai_dec.get("severity", "High"),
                        "title": ai_dec.get("title", "XSS Vulnerability Confirmed"),
                        "evidence": f"Payload Evidence:\n{x}\n\nReasoning:\n{ai_dec.get('reasoning')}",
                        "tool": "AI-WebAgent (dalfox)",
                        "recommendation": ai_dec.get("remediation", "Encode all user-supplied output contextually.")
                    })
                except Exception:
                    r.findings.append({"type": "xss", "severity": "High",
                                       "title": "XSS Found",
                                       "evidence": x, "tool": "dalfox",
                                       "recommendation": "Encode all user-supplied output contextually."})
            await self.emit("tool_done", {"tool": "dalfox", "xss": len(xss)})

        await self.emit("complete", {"findings": len(r.findings)})
        return r
