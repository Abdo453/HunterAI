"""
Dynamic Wordlist Manager for HunterAI & PentestAI.

Prioritizes the high-powered SecLists repository located on Kali Linux:
1. /home/kali/wordlist/SecLists
2. ~/wordlist/SecLists
3. /home/kali/wordlist
4. ~/wordlist
5. /usr/share/wordlists/seclists
6. /usr/share/wordlists
7. <project_root>/data/wordlists (local fallback)

Provides profile-aware resolution (e.g. 'safe' vs 'deep'/'hunter') and zero-failure
automatic fallbacks for lab/CI/offline environments.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("hunter_ai.wordlists")


class WordlistManager:
    """
    Intelligent Wordlist Resolver and Manager for HunterAI.
    """

    # Priority order for discovery roots
    DEFAULT_CANDIDATE_ROOTS: List[Path] = [
        Path("/home/kali/wordlist/SecLists"),
        Path.home() / "wordlist" / "SecLists",
        Path("/home/kali/wordlist"),
        Path.home() / "wordlist",
        Path("/usr/share/wordlists/seclists"),
        Path("/usr/share/wordlists"),
    ]

    # Category and profile file candidates (relative to candidate roots)
    WORDLIST_CANDIDATES: Dict[str, Dict[str, List[str]]] = {
        "dns": {
            "deep": [
                "Discovery/DNS/subdomains-top1million-110000.txt",
                "Discovery/DNS/bug-bounty-program-subdomains-trickest-inventory.txt",
                "Discovery/DNS/bitquark-subdomains-top100000.txt",
                "Discovery/DNS/deepmagic.com-prefixes-top50000.txt",
                "Discovery/DNS/subdomains-top1million-20000.txt",
                "Discovery/DNS/dns-Jhaddix.txt",
                "Discovery/DNS/subdomains-top1million-5000.txt",
                "subdomains.txt",
            ],
            "standard": [
                "Discovery/DNS/subdomains-top1million-20000.txt",
                "Discovery/DNS/dns-Jhaddix.txt",
                "Discovery/DNS/bitquark-subdomains-top100000.txt",
                "Discovery/DNS/subdomains-top1million-5000.txt",
                "Discovery/DNS/namelist.txt",
                "subdomains.txt",
            ],
            "safe": [
                "Discovery/DNS/subdomains-top1million-5000.txt",
                "Discovery/DNS/namelist.txt",
                "Discovery/DNS/dns-Jhaddix.txt",
                "subdomains.txt",
            ],
        },
        "directories": {
            "deep": [
                "Discovery/Web-Content/raft-large-directories.txt",
                "Discovery/Web-Content/directory-list-2.3-medium.txt",
                "Discovery/Web-Content/raft-medium-directories.txt",
                "Discovery/Web-Content/common.txt",
                "dirb/common.txt",
                "common.txt",
            ],
            "standard": [
                "Discovery/Web-Content/directory-list-2.3-medium.txt",
                "Discovery/Web-Content/raft-medium-directories.txt",
                "Discovery/Web-Content/common.txt",
                "dirb/common.txt",
                "common.txt",
            ],
            "safe": [
                "Discovery/Web-Content/common.txt",
                "dirb/common.txt",
                "common.txt",
            ],
        },
        "files": {
            "deep": [
                "Discovery/Web-Content/raft-large-files.txt",
                "Discovery/Web-Content/raft-medium-files.txt",
                "Discovery/Web-Content/common.txt",
            ],
            "standard": [
                "Discovery/Web-Content/raft-medium-files.txt",
                "Discovery/Web-Content/common.txt",
            ],
            "safe": [
                "Discovery/Web-Content/raft-medium-files.txt",
                "Discovery/Web-Content/common.txt",
            ],
        },
        "parameters": {
            "deep": [
                "Discovery/Web-Content/burp-parameter-names.txt",
                "Discovery/Web-Content/api/objects.txt",
                "Discovery/Web-Content/api/actions.txt",
                "parameters.txt",
            ],
            "standard": [
                "Discovery/Web-Content/burp-parameter-names.txt",
                "parameters.txt",
            ],
            "safe": [
                "Discovery/Web-Content/burp-parameter-names.txt",
                "parameters.txt",
            ],
        },
        "fuzzing": {
            "deep": [
                "Fuzzing/special-chars.txt",
                "Fuzzing/LFI/LFI-Jhaddix.txt",
                "Fuzzing/XSS/XSS-Jhaddix.txt",
                "Fuzzing/SQLi/Generic-SQLi.txt",
                "fuzzing.txt",
            ],
            "standard": [
                "Fuzzing/special-chars.txt",
                "fuzzing.txt",
            ],
            "safe": [
                "Fuzzing/special-chars.txt",
                "fuzzing.txt",
            ],
        },
        "passwords": {
            "deep": [
                "Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
                "rockyou.txt",
                "passwords.txt",
            ],
            "standard": [
                "Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
                "passwords.txt",
            ],
            "safe": [
                "passwords.txt",
            ],
        },
    }

    def __init__(self, custom_roots: Optional[List[str | Path]] = None):
        self.project_root = Path(__file__).resolve().parent.parent
        self.local_fallback_dir = self.project_root / "data" / "wordlists"
        
        self.roots: List[Path] = []
        if custom_roots:
            self.roots.extend([Path(r) for r in custom_roots])
        
        # Check environment variables for custom SecLists / wordlist paths
        for env_var in ("SECLISTS_PATH", "WORDLISTS_PATH", "KALI_WORDLIST_DIR"):
            env_val = os.getenv(env_var)
            if env_val and Path(env_val) not in self.roots:
                self.roots.append(Path(env_val))
        
        for r in self.DEFAULT_CANDIDATE_ROOTS:
            if r not in self.roots:
                self.roots.append(r)
        
        # Ensure project fallback root is present
        if self.local_fallback_dir not in self.roots:
            self.roots.append(self.local_fallback_dir)
            
        self.ensure_fallbacks()

    def get_active_roots(self) -> List[Path]:
        """Returns list of roots that actually exist on the current filesystem."""
        return [r for r in self.roots if r.exists() and r.is_dir()]

    def ensure_fallbacks(self) -> None:
        """Pre-provisions lightweight bundled fallbacks in data/wordlists if missing."""
        try:
            self.local_fallback_dir.mkdir(parents=True, exist_ok=True)
            
            # 1. common.txt
            common_file = self.local_fallback_dir / "common.txt"
            if not common_file.exists():
                common_paths = [
                    "admin", "login", "api", "dashboard", "portal", "config", "backup",
                    ".git", ".env", "robots.txt", "sitemap.xml", "wp-admin", "console",
                    "secret", "uploads", "dev", "v1", "v2", "phpmyadmin", "test",
                    "server-status", "debug", "swagger", "graphql", "metrics", "actuator",
                    "users", "profile", "settings", "download", "files", "search", "register"
                ]
                common_file.write_text("\n".join(common_paths) + "\n", encoding="utf-8")

            # 2. subdomains.txt
            sub_file = self.local_fallback_dir / "subdomains.txt"
            if not sub_file.exists():
                subdomains = [
                    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
                    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test",
                    "portal", "ns", "ww1", "host", "support", "dev", "api", "stage",
                    "app", "beta", "admin", "gateway", "auth", "static", "cdn"
                ]
                sub_file.write_text("\n".join(subdomains) + "\n", encoding="utf-8")

            # 3. parameters.txt
            param_file = self.local_fallback_dir / "parameters.txt"
            if not param_file.exists():
                params = [
                    "id", "user", "username", "password", "token", "redirect", "url",
                    "file", "path", "page", "query", "q", "search", "cmd", "action",
                    "role", "email", "debug", "view", "key", "api_key", "admin"
                ]
                param_file.write_text("\n".join(params) + "\n", encoding="utf-8")

            # 4. fuzzing.txt
            fuzz_file = self.local_fallback_dir / "fuzzing.txt"
            if not fuzz_file.exists():
                fuzz_items = [
                    "'", "\"", "<!--", "-->", "<script>", "</script>", "sleep(5)",
                    "../", "..\\", "%00", "{{7*7}}", "${7*7}", "1 OR 1=1", "true"
                ]
                fuzz_file.write_text("\n".join(fuzz_items) + "\n", encoding="utf-8")
        except Exception as e:
            logger.warning(f"Could not initialize wordlist fallbacks: {e}")

    def get_wordlist(self, category: str = "directories", profile: str = "standard") -> str:
        """
        Resolves the optimal wordlist path for the given category and profile mode.
        Checks candidate roots in priority order. If none found on disk, returns local fallback.
        """
        # If caller passed a direct existing file path, return it immediately
        if os.path.isfile(category):
            return category

        category_key = category.lower()
        if category_key in ("web_content", "directory", "dir"):
            category_key = "directories"
        elif category_key in ("subdomains", "subdomain"):
            category_key = "dns"
        elif category_key in ("params", "param"):
            category_key = "parameters"

        # Normalize profile mode
        prof = profile.lower()
        if prof in ("deep", "hunter", "aggressive", "full"):
            prof_mode = "deep"
        elif prof in ("safe", "passive", "quick"):
            prof_mode = "safe"
        else:
            prof_mode = "standard"

        cat_candidates = self.WORDLIST_CANDIDATES.get(category_key, {})
        file_list = cat_candidates.get(prof_mode, cat_candidates.get("standard", []))

        # Search across configured roots in priority order
        for root in self.roots:
            for rel_file in file_list:
                candidate_path = root / rel_file
                if candidate_path.is_file():
                    logger.debug(f"Resolved wordlist [{category_key}/{prof_mode}]: {candidate_path}")
                    return str(candidate_path)

        # Fallback to local workspace files
        fallback_file = self.local_fallback_dir / f"{category_key}.txt"
        if fallback_file.is_file():
            return str(fallback_file)

        # Ultimate safety fallback: common.txt
        common_file = self.local_fallback_dir / "common.txt"
        if common_file.is_file():
            return str(common_file)

        return "/home/kali/wordlist/SecLists/Discovery/Web-Content/common.txt"

    def get_all_available_wordlists(self) -> Dict[str, List[str]]:
        """Returns map of discovered wordlists across all active roots."""
        results: Dict[str, List[str]] = {}
        for root in self.get_active_roots():
            root_name = str(root)
            results[root_name] = []
            try:
                for path in root.rglob("*.txt"):
                    if path.is_file():
                        results[root_name].append(str(path))
            except Exception as e:
                logger.warning(f"Error enumerating root {root}: {e}")
        return results


# Global singleton instance
_default_instance: Optional[WordlistManager] = None


def get_wordlist_manager() -> WordlistManager:
    global _default_instance
    if _default_instance is None:
        _default_instance = WordlistManager()
    return _default_instance


def resolve_wordlist(category: str = "directories", profile: str = "standard") -> str:
    """Convenience helper to resolve wordlist directly."""
    return get_wordlist_manager().get_wordlist(category, profile)
