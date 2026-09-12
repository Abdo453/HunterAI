"""
Parameter Optimizer & Smart Tool Fallback Engine (Inspired by HexStrike AI)
تحسين باراميترات الأدوات تلقائياً والتحويل التلقائي بين الأدوات البديلة عند الفشل
"""
import logging
from typing import Dict, Any, List, Optional, Tuple

log = logging.getLogger("parameter_optimizer")


class ParameterOptimizer:
    """
    تحسين باراميترات الأدوات الأمنية حسب:
    - وجود WAF
    - سرعة استجابة السيرفر
    - نوع الهدف (API / Web / Large Enterprise)
    """

    @staticmethod
    def optimize_tool_command(tool_name: str, target: str, waf_detected: bool = False,
                              conservative_mode: bool = False) -> str:
        import os
        t = tool_name.lower().strip()
        use_proxy = os.getenv("USE_PROXY", "false").lower() in ("true", "1")
        proxy = os.getenv("BURPSUITE_PROXY", "127.0.0.1:8080")

        if t == "nmap":
            if waf_detected or conservative_mode:
                return f"-sV -T3 --max-rate 50 --max-retries 1 -Pn {target}"
            return f"-sV -sC -T4 --top-ports 1000 -Pn {target}"

        elif t == "ffuf":
            proxy_flag = f"-x http://{proxy}" if use_proxy else ""
            if waf_detected or conservative_mode:
                return f"-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 5 -p 0.5 -mc 200,301,302,401 {proxy_flag}".strip()
            return f"-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 50 -mc 200,204,301,302,401,403 {proxy_flag}".strip()

        elif t == "katana":
            proxy_flag = f"-proxy http://{proxy}" if use_proxy else ""
            if waf_detected:
                return f"-u {target} -d 2 -jc -c 3 -delay 1 -silent {proxy_flag}".strip()
            return f"-u {target} -d 5 -jc -kf all -headless -silent {proxy_flag}".strip()

        elif t == "sqlmap":
            proxy_flag = f"--proxy=http://{proxy}" if use_proxy else ""
            if waf_detected:
                return f"-u {target} --batch --random-agent --tamper=space2comment,between --level=2 --risk=1 --threads=1 --delay=1 {proxy_flag}".strip()
            return f"-u {target} --batch --random-agent --threads=5 --level=1 --risk=1 {proxy_flag}".strip()

        elif t in ("httpx", "httpx-toolkit"):
            target_clean = target.replace("-title", "").replace("-tech-detect", "").replace("-status-code", "").strip()
            proxy_flag = f"-http-proxy http://{proxy}" if use_proxy else ""
            if waf_detected or conservative_mode:
                return f"-u {target_clean} -status-code -title -tech-detect -silent -rate-limit 10 {proxy_flag}".strip()
            return f"-u {target_clean} -status-code -title -tech-detect -silent {proxy_flag}".strip()

        elif t == "nuclei":
            proxy_flag = f"-proxy http://{proxy}" if use_proxy else ""
            if waf_detected:
                return f"-u {target} -t cves/,vulnerabilities/ -rl 10 -c 5 -silent {proxy_flag}".strip()
            return f"-u {target} -t exposures/,cves/,vulnerabilities/ -c 25 -silent {proxy_flag}".strip()

        return target


class SmartToolFallback:
    """
    سلاسل الأدوات البديلة (Fallback Chains)
    إذا فشلت أداة أو لم تكن مثبتة، ينتقل تلقائياً للأداة التالية في السلسلة!
    """

    FALLBACK_CHAINS = {
        "subdomain_discovery": ["subfinder", "assetfinder", "findomain", "crt_sh_api"],
        "port_scanning": ["rustscan", "naabu", "nmap"],
        "web_crawling": ["katana", "gospider", "gauplus", "waybackurls"],
        "directory_fuzzing": ["ffuf", "feroxbuster", "dirsearch", "gobuster"],
        "parameter_mining": ["arjun", "paramspider", "x8"],
        "sqli_testing": ["sqlmap", "ghauri"],
        "vuln_scanning": ["nuclei", "nikto"]
    }

    @classmethod
    def get_fallback_chain(cls, category: str) -> List[str]:
        return cls.FALLBACK_CHAINS.get(category, [])

    @classmethod
    def get_next_alternate_tool(cls, category: str, failed_tool: str) -> Optional[str]:
        chain = cls.get_fallback_chain(category)
        if failed_tool in chain:
            idx = chain.index(failed_tool)
            if idx + 1 < len(chain):
                return chain[idx + 1]
        return None
