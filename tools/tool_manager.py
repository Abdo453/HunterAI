"""Tool Manager — مدير الأدوات الذكي مع caching"""
import asyncio, shutil, hashlib, time
from dataclasses import dataclass
from typing import Dict, List, Optional, Any


@dataclass
class ToolResult:
    tool: str
    command: str
    stdout: str
    stderr: str
    returncode: int
    duration: float
    cached: bool = False
    error: Optional[str] = None
    output_file: Optional[str] = None

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.error

    @property
    def output(self) -> str:
        return self.stdout or self.stderr


class ToolManager:
    INSTALL_MAP = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "katana": "go install -v github.com/projectdiscovery/katana/cmd/katana@latest",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "anew": "go install -v github.com/tomnomnom/anew@latest",
        "gau": "go install -v github.com/lc/gau/v2/cmd/gau@latest",
        "qsreplace": "go install -v github.com/tomnomnom/qsreplace@latest",
        "ffuf": "go install -v github.com/ffuf/ffuf/v2@latest",
        "arjun": "pip install arjun",
        "dirsearch": "pip install dirsearch",
        "wafw00f": "pip install wafw00f",
        "nmap": "sudo apt update && sudo apt install -y nmap",
        "sqlmap": "sudo apt update && sudo apt install -y sqlmap",
        "masscan": "sudo apt update && sudo apt install -y masscan",
        "gobuster": "sudo apt update && sudo apt install -y gobuster",
        "nikto": "sudo apt update && sudo apt install -y nikto",
        "hydra": "sudo apt update && sudo apt install -y hydra",
    }

    def __init__(self, output_dir: Optional[str] = None):
        import os
        self._cache: Dict[str, ToolResult] = {}
        self._avail: Dict[str, bool] = {}
        self.output_dir = output_dir or os.getenv("TOOL_OUTPUTS_DIR", os.path.join(os.getcwd(), "data", "tool_outputs"))
        os.makedirs(self.output_dir, exist_ok=True)

    def resolve_binary(self, cmd: str) -> str:
        """حل مسار الأداة بدقة لمنع التعارض بين أدوات بايثون وأدوات كالي Go"""
        import os
        c = cmd.lower().strip()
        if c in ("httpx", "httpx-toolkit"):
            if shutil.which("httpx-toolkit"):
                return "httpx-toolkit"
            go_httpx = os.path.expanduser("~/go/bin/httpx")
            if os.path.isfile(go_httpx) and os.access(go_httpx, os.X_OK):
                return go_httpx

        # فحص مجلد Go الافتراضي لجميع أدوات Go في كالي
        go_bin = os.path.expanduser(f"~/go/bin/{cmd}")
        if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
            return go_bin

        return cmd

    def is_available(self, cmd: str) -> bool:
        if cmd not in self._avail:
            import os
            resolved = self.resolve_binary(cmd)
            self._avail[cmd] = shutil.which(resolved) is not None or os.path.exists(resolved)
        return self._avail[cmd]

    async def auto_install_if_missing(self, tool: str) -> bool:
        """محاولة تثبيت الأداة تلقائياً إذا كانت مفقودة على Kali/Linux"""
        if self.is_available(tool):
            return True
        
        install_cmd = self.INSTALL_MAP.get(tool.lower())
        if not install_cmd:
            return False

        try:
            proc = await asyncio.create_subprocess_shell(
                install_cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(proc.communicate(), timeout=180)
            # Recheck availability
            self._avail.pop(tool, None)
            return self.is_available(tool)
        except Exception:
            return False

    def get_available(self, category: str = None) -> List[str]:
        all_tools = {
            "network": ["nmap", "masscan", "rustscan", "netexec", "enum4linux-ng"],
            "web": ["gobuster", "ffuf", "nuclei", "sqlmap", "nikto", "dalfox", "httpx", "wafw00f", "wpscan", "katana"],
            "recon": ["subfinder", "amass", "theHarvester", "assetfinder", "shodan"],
            "password": ["hydra", "john", "hashcat"],
            "binary": ["gdb", "r2", "binwalk", "checksec", "strings", "file"],
            "osint": ["sherlock"],
            "ctf": ["exiftool", "binwalk", "steghide", "zsteg", "foremost"],
        }
        pool = all_tools.get(category, [t for tl in all_tools.values() for t in tl]) if category else [t for tl in all_tools.values() for t in tl]
        return [t for t in pool if self.is_available(t)]

    def get_available_tools(self, category: str = None) -> List[str]:
        """Alias for get_available()"""
        return self.get_available(category)

    def _save_tool_output(self, tool: str, command: str, stdout: str, stderr: str,
                           returncode: int, duration: float, error: Optional[str] = None) -> Optional[str]:
        """حفظ مخرجات الأداة بصيغة نصية واضحة في data/tool_outputs/ ليراها المستخدم"""
        try:
            import re, os
            from datetime import datetime
            
            # Extract target/host from command if possible
            target_match = re.search(r'https?://[^\s\'"]+', command)
            if not target_match:
                target_match = re.search(r'(?:-u|-h|-d|-target|--url)?\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|(?:\d{1,3}\.){3}\d{1,3})', command)
            raw_target = target_match.group(0) if target_match else "scan"
            clean_target = re.sub(r'[^a-zA-Z0-9_\-.]', '_', raw_target).strip('_')[:40] or "target"
            
            clean_tool = re.sub(r'[^a-zA-Z0-9_\-]', '_', tool.lower())[:20]
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{clean_tool}_{clean_target}_{timestamp}.txt"
            filepath = os.path.join(self.output_dir, filename)
            
            status_str = "SUCCESS" if (returncode == 0 and not error) else "FAILED"
            content = (
                f"================================================================================\n"
                f"PentestAI Tool Execution Log\n"
                f"Tool:       {tool}\n"
                f"Target:     {raw_target}\n"
                f"Command:    {command}\n"
                f"Timestamp:  {datetime.now().isoformat()}\n"
                f"Duration:   {duration:.2f}s\n"
                f"Exit Code:  {returncode}\n"
                f"Status:     {status_str}\n"
                f"================================================================================\n\n"
                f"[--- STDOUT ---]\n{stdout}\n\n"
                f"[--- STDERR ---]\n{stderr}\n\n"
                f"[--- ERROR ---]\n{error or 'None'}\n"
            )
            with open(filepath, "w", encoding="utf-8", errors="replace") as f:
                f.write(content)
            return filepath
        except Exception:
            return None

    def list_output_files(self) -> List[Dict[str, Any]]:
        """قائمة ملفات المخرجات النصية المحفوظة"""
        import os
        results = []
        if not os.path.isdir(self.output_dir):
            return results
        for f in os.listdir(self.output_dir):
            if f.endswith(".txt"):
                p = os.path.join(self.output_dir, f)
                try:
                    stat = os.stat(p)
                    results.append({
                        "filename": f,
                        "path": p,
                        "size": stat.st_size,
                        "modified": stat.st_mtime
                    })
                except Exception:
                    pass
        results.sort(key=lambda x: x["modified"], reverse=True)
        return results

    def get_output_content(self, filename: str) -> Optional[str]:
        """قراءة محتوى ملف نصي محفوظ"""
        import os
        safe_name = os.path.basename(filename)
        p = os.path.join(self.output_dir, safe_name)
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception:
                return None
        return None

    async def execute(self, command: Any, *args, timeout: int = 300, use_cache: bool = True, **kwargs) -> ToolResult:
        if isinstance(command, list):
            command_str = " ".join(str(c) for c in command)
            tool = command[0] if command else "unknown"
        else:
            command_str = str(command)
            tool = command_str.split()[0] if command_str else "unknown"

        # Handle flexible args (e.g. execute("wafw00f", [url]) or execute("arjun", ["-u", url]))
        if args:
            first = args[0]
            if isinstance(first, (list, tuple)):
                extra = " ".join(str(x) for x in first)
                command_str = f"{command_str} {extra}".strip()
                if len(args) > 1 and isinstance(args[1], (int, float)):
                    timeout = int(args[1])
            elif isinstance(first, (int, float)):
                timeout = int(first)
            elif isinstance(first, str):
                command_str = f"{command_str} {first}".strip()
                if len(args) > 1 and isinstance(args[1], (int, float)):
                    timeout = int(args[1])

        key = hashlib.md5(command_str.encode()).hexdigest()
        if use_cache and key in self._cache:
            r = self._cache[key]
            r.cached = True
            return r
        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_shell(
                command_str, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                dur = time.time() - t0
                err_msg = f"Timeout after {timeout}s"
                out_f = self._save_tool_output(tool, command_str, "", "", -1, dur, error=err_msg)
                return ToolResult(tool=tool, command=command_str, stdout="", stderr="",
                                  returncode=-1, duration=dur, error=err_msg, output_file=out_f)
            
            dur = time.time() - t0
            stdout_str = out.decode("utf-8", errors="replace")
            stderr_str = err.decode("utf-8", errors="replace")
            ret_code = proc.returncode or 0
            out_f = self._save_tool_output(tool, command_str, stdout_str, stderr_str, ret_code, dur)
            r = ToolResult(tool=tool, command=command_str,
                           stdout=stdout_str,
                           stderr=stderr_str,
                           returncode=ret_code, duration=dur,
                           output_file=out_f)
            self._cache[key] = r
            return r
        except FileNotFoundError:
            dur = time.time() - t0
            err_msg = f"'{tool}' not found in PATH"
            out_f = self._save_tool_output(tool, command_str, "", "", 127, dur, error=err_msg)
            return ToolResult(tool=tool, command=command_str, stdout="", stderr="",
                              returncode=127, duration=dur, error=err_msg, output_file=out_f)
        except Exception as e:
            dur = time.time() - t0
            err_msg = str(e)
            out_f = self._save_tool_output(tool, command_str, "", "", -1, dur, error=err_msg)
            return ToolResult(tool=tool, command=command_str, stdout="", stderr="",
                              returncode=-1, duration=dur, error=err_msg, output_file=out_f)

    async def execute_tool(self, tool_name: str, args: str, timeout: int = 300, waf_detected: bool = False) -> ToolResult:
        """تشغيل أداة مع تحسين الباراميترات وتثبيتها تلقائياً لو كانت مفقودة"""
        if not self.is_available(tool_name):
            # محاولة تثبيت الأداة تلقائياً
            await self.auto_install_if_missing(tool_name)

        resolved_tool = self.resolve_binary(tool_name)
        from core.parameter_optimizer import ParameterOptimizer
        opt_args = ParameterOptimizer.optimize_tool_command(tool_name, args, waf_detected=waf_detected)
        cmd = f"{resolved_tool} {opt_args}".strip()
        return await self.execute(cmd, timeout=timeout)

    async def execute_with_fallback(self, category: str, primary_tool: str, target: str,
                                    waf_detected: bool = False) -> ToolResult:
        """تشغيل أداة مع التحويل التلقائي للأداة البديلة في حال عدم توفرها أو فشلها"""
        from core.parameter_optimizer import SmartToolFallback
        chain = SmartToolFallback.get_fallback_chain(category)
        tools_to_try = [primary_tool] + [t for t in chain if t != primary_tool]

        last_result = None
        for t in tools_to_try:
            if self.is_available(t):
                res = await self.execute_tool(t, target, waf_detected=waf_detected)
                if res.success:
                    return res
                last_result = res

        return last_result or ToolResult(tool=primary_tool, command=f"{primary_tool} {target}",
                                         stdout="", stderr="", returncode=127, duration=0,
                                         error=f"No working tool found in category: {category}")
