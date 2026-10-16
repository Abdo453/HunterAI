"""Platform Registry — بيانات المنصات المدعومة + القواعد العامة"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Set, Dict, List, Optional
import re


# ─── أسماء المستخدمين العامة التي لا يمكن الاعتماد عليها لوحدها ─────────────
# استخدامها alone في الربط = False Positive محتمل.
GENERIC_USERNAMES: Set[str] = {
    "admin", "administrator", "root", "user", "users", "guest", "demo",
    "test", "tests", "testing", "info", "support", "help", "contact",
    "null", "none", "n/a", "unknown", "anonymous", "anon", "system",
    "systemctl", "webmaster", "mail", "postmaster", "hostmaster",
    "abuse", "security", "noc", "dev", "development", "stage", "staging",
    "prod", "production", "localhost", "default", "superuser", "super",
    "manager", "operator", "service", "services", "api", "app",
    "index", "home", "www", "ftp", "git", "svn", "hg", "bazaar",
    "mysql", "postgres", "redis", "elasticsearch", "docker",
    "kubernetes", "k8s", "jenkins", "ci", "cd", "build", "deploy",
    "backup", "backups", "archive", "tmp", "temp", "cache",
    "public", "private", "internal", "external", "all", "everyone",
    "nobody", "nogroup", "wheel", "sudo", "bin", "daemon", "sync",
    "shutdown", "halt", "mailnull", "uucp", "operator", "games",
    "gopher", "ftp", "nobody4", "noaccess",
}


@dataclass
class PlatformEntry:
    name: str                      # الاسم المعياري (예: "github")
    aliases: List[str]            # أسماء متباينة في مخرجات الأدوات
    detection_method: str         # web_status | mobile_api | password_reset | api_enumeration
    rate_limit_per_min: int       # Maximum queries per minute for this platform
    requires_auth: bool = False   # إذا كان الفحص يتطلب تسجيل دخول (يُتخطى تلقائيًا)
    soft404_patterns: Optional[List[str]] = None  # أنماط HTML تدل على "صفحة غير موجودة" رغم 200

    def canonical_name(self, raw: str) -> str:
        """تحويل الاسم الخام من الأداة إلى الاسم المعياري"""
        raw_lower = raw.strip().lower()
        if raw_lower in {a.lower() for a in self.aliases} or raw_lower == self.name.lower():
            return self.name
        return raw


# سجل المنصات (يمكن توسيعه دون تغيير الكود)
PLATFORMS: Dict[str, PlatformEntry] = {
    "github": PlatformEntry(
        name="github",
        aliases=["github", "com.github", "github.com"],
        detection_method="web_status",
        rate_limit_per_min=30,
        soft404_patterns=["page not found", "repository not found", "the page you're looking for"],
    ),
    "reddit": PlatformEntry(
        name="reddit",
        aliases=["reddit", "www.reddit.com"],
        detection_method="web_status",
        rate_limit_per_min=20,
    ),
    "twitter": PlatformEntry(
        name="twitter",
        aliases=["twitter", "x", "twitter.com", "x.com"],
        detection_method="web_status",
        rate_limit_per_min=20,
    ),
    "instagram": PlatformEntry(
        name="instagram",
        aliases=["instagram", "instagram.com"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "tiktok": PlatformEntry(
        name="tiktok",
        aliases=["tiktok", "tiktok.com"],
        detection_method="mobile_api",
        rate_limit_per_min=10,
    ),
    "telegram": PlatformEntry(
        name="telegram",
        aliases=["telegram", "t.me", "telegram.me"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "linkedin": PlatformEntry(
        name="linkedin",
        aliases=["linkedin", "linkedin.com"],
        detection_method="web_status",
        rate_limit_per_min=10,
        requires_auth=True,   # LinkedIn يحتاج تسجيل دخول للفحص العميق
    ),
    "facebook": PlatformEntry(
        name="facebook",
        aliases=["facebook", "facebook.com", "fb"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "youtube": PlatformEntry(
        name="youtube",
        aliases=["youtube", "youtube.com", "yt"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "pinterest": PlatformEntry(
        name="pinterest",
        aliases=["pinterest", "pinterest.com"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "spotify": PlatformEntry(
        name="spotify",
        aliases=["spotify", "open.spotify.com"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "github_gist": PlatformEntry(
        name="github_gist",
        aliases=["gist", "gist.github.com"],
        detection_method="web_status",
        rate_limit_per_min=30,
    ),
    "stackoverflow": PlatformEntry(
        name="stackoverflow",
        aliases=["stackoverflow", "stackoverflow.com", "stack overflow"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "deviantart": PlatformEntry(
        name="deviantart",
        aliases=["deviantart", "deviantart.com"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "vk": PlatformEntry(
        name="vk",
        aliases=["vk", "vk.com", "vkontakte"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "keybase": PlatformEntry(
        name="keybase",
        aliases=["keybase", "keybase.io"],
        detection_method="web_status",
        rate_limit_per_min=15,
    ),
    "gitlab": PlatformEntry(
        name="gitlab",
        aliases=["gitlab", "gitlab.com"],
        detection_method="web_status",
        rate_limit_per_min=30,
    ),
    "bitbucket": PlatformEntry(
        name="bitbucket",
        aliases=["bitbucket", "bitbucket.org"],
        detection_method="web_status",
        rate_limit_per_min=20,
    ),
}


def is_generic_username(username: str) -> bool:
    """هل الاسم العام (generic) لا يرقى ليكون هوية مميزة؟"""
    return username.strip().lower() in GENERIC_USERNAMES


def canonicalize_platform(raw_name: str) -> str:
    """إرجاع الاسم المعياري للمنصة إن وُجد، وإلا الاسم كما هو (lowercase)."""
    raw_lower = raw_name.strip().lower()
    for entry in PLATFORMS.values():
        if raw_lower == entry.name.lower() or raw_lower in [a.lower() for a in entry.aliases]:
            return entry.name
    return raw_lower


def platform_entry(name: str) -> Optional[PlatformEntry]:
    """استرجاع إدخال المنصة من الاسم المعياري."""
    return PLATFORMS.get(name.lower())


def all_platforms() -> List[str]:
    return list(PLATFORMS.keys())


# ─── أنماط استخراج الروابط العامة ──────────────────────────────────────────
URL_RE = re.compile(r"https?://[^\s\]\)<>\"]+", re.IGNORECASE)


def extract_urls(text: str) -> List[str]:
    """استخراج الروابط من نص الأداة الخام"""
    return URL_RE.findall(text or "")
