"""Recon Agent — Port scan + subdomain + tech detection"""
import re
from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.network_tools import NetworkTools
from tools.web_tools import WebTools
from tools.osint_tools import OSINTTools


class ReconAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__("recon_agent", "Recon — ports, subdomains, tech", mgr, cb)
        self.net = NetworkTools(mgr)
        self.web = WebTools(mgr)
        self.osint = OSINTTools(mgr)

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Recon on {target}"})

        # Port scanning
        if self.mgr.is_available("rustscan"):
            await self.emit("tool_start", {"tool": "rustscan", "target": target})
            rs = await self.net.rustscan(target)
            r.raw_output["rustscan"] = rs.output
            await self.emit("tool_done", {"tool": "rustscan", "output": rs.output[:300]})

        if self.mgr.is_available("nmap"):
            await self.emit("tool_start", {"tool": "nmap", "target": target})
            nm = await self.net.nmap_scan(target)
            r.raw_output["nmap"] = nm.output
            open_ports = [l for l in nm.stdout.splitlines() if "/tcp" in l and "open" in l]
            if open_ports:
                ev_str = "\n".join(open_ports)
                if nm.output_file:
                    ev_str = f"[Raw Log: {nm.output_file}]\n" + ev_str
                r.findings.append({"type": "ports", "severity": "Info",
                                   "title": f"Open Ports ({len(open_ports)})",
                                   "evidence": ev_str, "tool": "nmap",
                                   "log_file": nm.output_file,
                                   "recommendation": "Review all open services."})
            await self.emit("tool_done", {"tool": "nmap", "found": len(open_ports), "output_file": nm.output_file})

        # Subdomain enum (Multi-source: crt.sh + Subfinder + Assetfinder + Findomain)
        clean = target.replace("https://","").replace("http://","").split("/")[0]
        is_domain = bool(re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', clean))
        all_subs: set = set()

        if is_domain:
            # 1. crt.sh Certificate Transparency
            try:
                from core.playbooks.bug_bounty_methodology import BugBountyMethodology
                bb_method = BugBountyMethodology(self.mgr)
                crt_subs = await bb_method.fetch_crtsh_subdomains(clean)
                all_subs.update(crt_subs)
            except Exception:
                pass

            # 2. subfinder
            if self.mgr.is_available("subfinder"):
                await self.emit("tool_start", {"tool": "subfinder", "target": clean})
                sf = await self.osint.subfinder(clean)
                subs = [l.strip() for l in sf.stdout.splitlines() if l.strip()]
                all_subs.update(subs)
                r.raw_output["subfinder"] = sf.output
                await self.emit("tool_done", {"tool": "subfinder", "found": len(subs), "output_file": sf.output_file})

            # 3. assetfinder
            if self.mgr.is_available("assetfinder"):
                af = await self.osint.assetfinder(clean)
                subs = [l.strip() for l in af.stdout.splitlines() if l.strip() and clean in l]
                all_subs.update(subs)

            # 4. findomain
            if self.mgr.is_available("findomain"):
                fd = await self.osint.findomain(clean)
                subs = [l.strip() for l in fd.stdout.splitlines() if l.strip() and clean in l]
                all_subs.update(subs)

            # 5. Active DNS wordlist brute-forcing (SecLists)
            try:
                from core.wordlist_manager import WordlistManager
                prof = "deep" if getattr(task, "mode", "safe") in ("full", "deep", "hunter") else "safe"
                dns_wl = WordlistManager().get_wordlist("dns", profile=prof)
                if self.mgr.is_available("gobuster"):
                    await self.emit("tool_start", {"tool": "gobuster-dns", "target": clean})
                    gb_res = await self.osint.gobuster_dns(clean, wordlist=dns_wl)
                    found_dns = [l.split()[1].strip().lower() for l in gb_res.stdout.splitlines() if "Found:" in l]
                    if found_dns:
                        all_subs.update(found_dns)
                    await self.emit("tool_done", {"tool": "gobuster-dns", "found": len(found_dns)})
                elif self.mgr.is_available("dnsx"):
                    await self.emit("tool_start", {"tool": "dnsx-brute", "target": clean})
                    dnsx_res = await self.osint.dnsx_brute(clean, wordlist=dns_wl)
                    found_dns = [l.strip().lower() for l in dnsx_res.stdout.splitlines() if l.strip() and clean in l]
                    if found_dns:
                        all_subs.update(found_dns)
                    await self.emit("tool_done", {"tool": "dnsx-brute", "found": len(found_dns)})
            except Exception:
                pass

            if all_subs:
                sorted_subs = sorted(list(all_subs))
                sub_file = self.mgr._save_tool_output(
                    "recon_subdomains", f"recon subdomains for {clean}",
                    "\n".join(sorted_subs), "", 0, 0.0
                )
                sub_ev = "\n".join(sorted_subs[:30])
                if sub_file:
                    sub_ev = f"[Saved Subdomains: {sub_file}]\n" + sub_ev
                r.findings.append({"type": "subdomains", "severity": "Info",
                                   "title": f"Subdomains Discovered ({len(sorted_subs)})",
                                   "evidence": sub_ev, "tool": "Multi-Source Recon (crt.sh/subfinder/assetfinder)",
                                   "log_file": sub_file,
                                   "recommendation": "Review all subdomains for attack surface and takeover vulnerabilities."})

                # 5. Subdomain Takeover check via subzy
                if self.mgr.is_available("subzy"):
                    try:
                        import tempfile
                        with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
                            tf.write("\n".join(sorted_subs))
                            tf_path = tf.name
                        subz_res = await self.web.subzy_takeover(tf_path)
                        os.unlink(tf_path)
                        if "VULNERABLE" in subz_res.stdout.upper():
                            r.findings.append({
                                "type": "subdomain_takeover",
                                "severity": "Critical",
                                "title": "🚨 Potential Subdomain Takeover Detected (subzy)",
                                "evidence": subz_res.stdout[:500],
                                "tool": "subzy",
                                "recommendation": "Claim dangling DNS CNAME records or decommission obsolete DNS pointers."
                            })
                    except Exception:
                        pass

            # 6. Dork generation
            try:
                dorks = bb_method.generate_dorks(clean)
                r.findings.append({
                    "type": "osint_dorks",
                    "severity": "Info",
                    "title": f"Generated Google Dorks for {clean}",
                    "evidence": "\n".join(dorks),
                    "tool": "DorkEngine",
                    "recommendation": "Search these dorks to discover leaked spreadsheets, credentials, and backups."
                })
            except Exception:
                pass

        # Tech detection
        url = target if target.startswith("http") else f"http://{target}"
        if self.mgr.is_available("httpx"):
            await self.emit("tool_start", {"tool": "httpx"})
            hx = await self.web.httpx_probe(url)
            r.raw_output["httpx"] = hx.output
            await self.emit("tool_done", {"tool": "httpx", "output": hx.output[:200]})

        if self.mgr.is_available("wafw00f"):
            await self.emit("tool_start", {"tool": "wafw00f"})
            waf = await self.web.wafw00f(url)
            r.raw_output["wafw00f"] = waf.output
            if "is behind" in waf.stdout.lower():
                r.findings.append({"type": "waf", "severity": "Info", "title": "WAF Detected",
                                   "evidence": waf.stdout[:200], "tool": "wafw00f",
                                   "recommendation": "WAF present — adjust payloads accordingly."})
            await self.emit("tool_done", {"tool": "wafw00f"})

        # ── 4. التفكير والاستنتاج الذكي لسطح الهجوم (AI Surface Reasoning) ──
        try:
            from core.ai_reasoning_core import AIReasoningCore
            await self.emit("tool_start", {"tool": "AI Surface Reasoning"})
            open_p = [f.get("evidence", "") for f in r.findings if f.get("type") == "ports"]
            subs_list = [f.get("evidence", "") for f in r.findings if f.get("type") == "subdomains"]
            tech_s = r.raw_output.get("httpx", "")
            
            ai_eval = await AIReasoningCore.analyze_recon_surface(target, open_p, subs_list, tech_s)
            if ai_eval:
                r.findings.append({
                    "type": "ai_surface_assessment",
                    "severity": ai_eval.get("risk_level", "Medium"),
                    "title": f"🧠 تقييم واستنتاج الذكاء الاصطناعي لسطح الهجوم ({ai_eval.get('risk_level', 'Medium')})",
                    "evidence": f"Analysis:\n{ai_eval.get('analysis')}\n\nPriority Vectors:\n" + "\n".join(f"- {v}" for v in ai_eval.get("priority_vectors", [])),
                    "tool": "AI-ReasoningCore",
                    "recommendation": ai_eval.get("remediation", "Harden exposed assets.")
                })
            await self.emit("tool_done", {"tool": "AI Surface Reasoning"})
        except Exception:
            pass

        await self.emit("complete", {"findings": len(r.findings)})
        return r
