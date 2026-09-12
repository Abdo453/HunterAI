"""
Autonomous Recon Pipeline Engine
محرك تنفيذ سلسلة الاستطلاع والـ Recon التلقائي متعدد المراحل
يقوم بربط: Subdomain Enumeration -> Anew -> HTTPX -> WAF Radar -> Crawling -> Visual Graph
"""
import asyncio
import json
import time
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable

from core.scope_guard import ScopeGuard
from tools.waf_evasion import WAFEvasionEngine
from tools.tool_manager import ToolManager


class ReconPipelineRunner:
    """
    محرك تنفيذ المنهجية التلقائية وحساب مساحة الهجوم
    """

    def __init__(self, target: str, scope_guard: Optional[ScopeGuard] = None,
                 progress_cb: Optional[Callable] = None, session_id: Optional[str] = None):
        self.target = target.strip()
        self.scope_guard = scope_guard or ScopeGuard(in_scope=[self.target])
        self.cb = progress_cb
        self.session_id = session_id or f"recon_{int(time.time())}"
        self.tm = ToolManager()
        self.waf_engine = WAFEvasionEngine()
        
        self.discovered_subdomains: List[str] = []
        self.alive_hosts: List[Dict[str, Any]] = []
        self.discovered_endpoints: List[str] = []
        self.graph_nodes: List[Dict[str, Any]] = []
        self.graph_edges: List[Dict[str, Any]] = []
        self.is_running = False

    async def _emit(self, event_type: str, data: Dict[str, Any]):
        if self.cb:
            try:
                msg = {"event": event_type, "session_id": self.session_id, **data}
                if asyncio.iscoroutinefunction(self.cb):
                    await self.cb(msg)
                else:
                    self.cb(msg)
            except Exception:
                pass

    def _add_graph_node(self, node_id: str, label: str, group: str, details: Dict[str, Any] = None):
        """إضافة عقدة إلى الخريطة البصرية"""
        # تجنب التكرار
        if any(n["id"] == node_id for n in self.graph_nodes):
            return
        node = {
            "id": node_id,
            "label": label,
            "group": group,  # target | subdomain | web | waf | vuln | endpoint
            "details": details or {}
        }
        self.graph_nodes.append(node)

    def _add_graph_edge(self, from_id: str, to_id: str, label: str = ""):
        """ربط عقدتين في الخريطة البصرية"""
        edge = {"from": from_id, "to": to_id, "label": label}
        if edge not in self.graph_edges:
            self.graph_edges.append(edge)

    async def run(self) -> Dict[str, Any]:
        """تشغيل المنهجية بالكامل عبر الـ 4 مراحل"""
        self.is_running = True
        t0 = time.time()

        # التحقق من الـ Scope قبل البدء
        allowed, reason = self.scope_guard.is_in_scope(self.target)
        if not allowed:
            await self._emit("pipeline_error", {"error": f"Target blocked by Scope Guard: {reason}"})
            return {"error": reason, "success": False}

        await self._emit("pipeline_start", {
            "target": self.target,
            "session_id": self.session_id,
            "timestamp": time.time()
        })

        # إنشاء Node الهدف الرئيسي في الـ Graph
        root_id = f"target_{self.target}"
        self._add_graph_node(root_id, self.target, "target", {"type": "Root Target"})
        await self._emit("graph_update", {"nodes": self.graph_nodes, "edges": self.graph_edges})

        # ── المرحلة 1: Subdomain Discovery ──
        await self._step1_subdomain_discovery(root_id)

        # ── المرحلة 2: Merge & Scope Filter ──
        await self._step2_scope_filter(root_id)

        # ── المرحلة 3: Alive Host & WAF Detection ──
        await self._step3_alive_and_waf(root_id)

        # ── المرحلة 4: Endpoint Discovery & Vulnerability Sweep ──
        await self._step4_endpoints_and_vulns(root_id)

        duration = round(time.time() - t0, 2)
        summary = {
            "target": self.target,
            "session_id": self.session_id,
            "duration": duration,
            "subdomains_count": len(self.discovered_subdomains),
            "alive_hosts_count": len(self.alive_hosts),
            "endpoints_count": len(self.discovered_endpoints),
            "graph_nodes_count": len(self.graph_nodes),
            "graph_edges_count": len(self.graph_edges),
            "alive_hosts": self.alive_hosts
        }

        await self._emit("pipeline_done", summary)
        self.is_running = False
        return summary

    async def _step1_subdomain_discovery(self, root_id: str):
        """المرحلة الأولى: البحث عن الدومينات الفرعية"""
        await self._emit("pipeline_step", {
            "step": 1,
            "name": "Subdomain Discovery",
            "status": "Running subfinder & crt.sh..."
        })

        subs = set()
        subs.add(self.target)

        # 1. محاولة استخدام subfinder إذا كان متاحاً
        if self.tm.is_tool_available("subfinder"):
            res = await self.tm.execute_tool("subfinder", f"-d {self.target} -silent")
            if res.stdout:
                for line in res.stdout.splitlines():
                    clean = line.strip().lower()
                    if clean and self.target in clean:
                        subs.add(clean)

        # 2. استخراج من crt.sh (SSL Transparency) عبر HTTP مباشرة
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"https://crt.sh/?q=%25.{self.target}&output=json")
                if r.status_code == 200:
                    entries = r.json()
                    for entry in entries:
                        names = entry.get("name_value", "").split("\n")
                        for n in names:
                            n = n.strip().lower().replace("*.", "")
                            if n and self.target in n:
                                subs.add(n)
        except Exception:
            pass

        self.discovered_subdomains = list(subs)
        await self._emit("pipeline_step", {
            "step": 1,
            "name": "Subdomain Discovery",
            "status": f"Discovered {len(self.discovered_subdomains)} subdomains",
            "count": len(self.discovered_subdomains)
        })

    async def _step2_scope_filter(self, root_id: str):
        """المرحلة الثانية: تصفية النطاقات وفق قواعد الـ Scope"""
        await self._emit("pipeline_step", {
            "step": 2,
            "name": "Merge & Scope Enforcement",
            "status": "Filtering out-of-scope assets..."
        })

        filtered = []
        for sub in self.discovered_subdomains:
            allowed, _ = self.scope_guard.is_in_scope(sub)
            if allowed:
                filtered.append(sub)
                sub_id = f"sub_{sub}"
                self._add_graph_node(sub_id, sub, "subdomain", {"hostname": sub})
                self._add_graph_edge(root_id, sub_id, "has_subdomain")

        self.discovered_subdomains = filtered
        await self._emit("graph_update", {"nodes": self.graph_nodes, "edges": self.graph_edges})
        await self._emit("pipeline_step", {
            "step": 2,
            "name": "Merge & Scope Enforcement",
            "status": f"Retained {len(filtered)} in-scope targets",
            "count": len(filtered)
        })

    async def _step3_alive_and_waf(self, root_id: str):
        """المرحلة الثالثة: فحص السيرفرات النشطة واكتشاف الـ WAF"""
        await self._emit("pipeline_step", {
            "step": 3,
            "name": "Alive Probing & WAF Radar",
            "status": "Probing HTTP/HTTPS services and checking WAFs..."
        })

        import httpx
        self.alive_hosts = []

        async with httpx.AsyncClient(timeout=8, verify=False) as client:
            for sub in self.discovered_subdomains[:15]:  # أول 15 دومين للسرعة
                for proto in ["https", "http"]:
                    url = f"{proto}://{sub}"
                    try:
                        resp = await client.get(url)
                        if resp.status_code < 500:
                            # فحص الـ WAF
                            waf_profile = await self.waf_engine.detect_waf(url)

                            # استخراج العنوان
                            title = ""
                            m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE)
                            if m:
                                title = m.group(1).strip()[:40]

                            server = resp.headers.get("server", "")
                            host_entry = {
                                "url": url,
                                "hostname": sub,
                                "status_code": resp.status_code,
                                "title": title,
                                "server": server,
                                "waf_detected": waf_profile.waf_detected,
                                "waf_names": waf_profile.waf_names
                            }
                            self.alive_hosts.append(host_entry)

                            # إضافة Node الويب النشط
                            web_id = f"web_{sub}_{proto}"
                            self._add_graph_node(web_id, f"{proto.upper()}:{resp.status_code}\n{title or server}", "web", host_entry)
                            self._add_graph_edge(f"sub_{sub}", web_id, f"{resp.status_code}")

                            # إذا تم اكتشاف WAF أضف عقدة WAF
                            if waf_profile.waf_detected:
                                waf_id = f"waf_{sub}"
                                self._add_graph_node(waf_id, f"🛡️ WAF: {', '.join(waf_profile.waf_names)}", "waf", {"wafs": waf_profile.waf_names})
                                self._add_graph_edge(web_id, waf_id, "protected_by")

                            break  # لو https اشتغل لا داعي لـ http
                    except Exception:
                        pass

        await self._emit("graph_update", {"nodes": self.graph_nodes, "edges": self.graph_edges})
        await self._emit("pipeline_step", {
            "step": 3,
            "name": "Alive Probing & WAF Radar",
            "status": f"Found {len(self.alive_hosts)} active web services",
            "count": len(self.alive_hosts)
        })

    async def _step4_endpoints_and_vulns(self, root_id: str):
        """المرحلة الرابعة: استخراج المسارات والـ Endpoints وفحص الثغرات"""
        await self._emit("pipeline_step", {
            "step": 4,
            "name": "Endpoint Crawling & Exposure Sweep",
            "status": "Discovering URLs, APIs, and exposed endpoints..."
        })

        import httpx
        endpoints = []

        # محاولة استخراج أرشيف الـ URLs من Wayback
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(f"https://web.archive.org/cdx/search/cdx?url={self.target}/*&output=json&collapse=urlkey&limit=30")
                if r.status_code == 200:
                    data = r.json()
                    if len(data) > 1:
                        for row in data[1:]:
                            orig_url = row[2]
                            endpoints.append(orig_url)
                            # إضافة عينات للـ Graph
                            if len(self.discovered_endpoints) < 10:
                                parsed = urlparse(orig_url)
                                path_label = parsed.path[:25]
                                if path_label and path_label != "/":
                                    ep_id = f"ep_{hash(orig_url)}"
                                    self._add_graph_node(ep_id, path_label, "endpoint", {"url": orig_url})
                                    self._add_graph_edge(root_id, ep_id, "endpoint")
        except Exception:
            pass

        self.discovered_endpoints = endpoints
        await self._emit("graph_update", {"nodes": self.graph_nodes, "edges": self.graph_edges})
        await self._emit("pipeline_step", {
            "step": 4,
            "name": "Endpoint Crawling & Exposure Sweep",
            "status": f"Discovered {len(endpoints)} endpoints & historical URLs",
            "count": len(endpoints)
        })
