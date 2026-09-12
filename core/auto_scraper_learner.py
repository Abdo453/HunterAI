"""
Auto Scraper & Vectorized Skill Learning Engine
محرك الزحف التلقائي وتعلم التقارير وتوليد قاعدة بيانات متجهة (Vector DB)
مدمج من (HackerOne, GitHub, Medium, OWASP, PortSwigger)
مع دعم الموديلات المحلية (Ollama) والـ Cloud APIs (OpenRouter, Gemini, OpenAI)
"""
import os
import re
import json
import time
import math
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Optional, Any

import httpx
from bs4 import BeautifulSoup

log = logging.getLogger("auto_scraper_learner")

SKILLS_DIR = Path("data/skills")
VECTOR_DB_DIR = Path("data/vector_db")
RAW_DATA_DIR = Path("data/raw_writeups")

for d in [SKILLS_DIR, VECTOR_DB_DIR, RAW_DATA_DIR]:
    d.mkdir(parents=True, exist_ok=True)


class WriteupScraper:
    """زاحف تقارير ومقالات الـ Bug Bounty العالمية"""

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    def __init__(self, delay: float = 1.0):
        self.delay = delay

    async def scrape_hackerone(self, limit: int = 15) -> List[Dict]:
        """سحب تقارير HackerOne المنشورة عامة"""
        log.info(f"[*] Scraping HackerOne Hacktivity (limit: {limit})...")
        writeups = []
        url = "https://hackerone.com/hacktivity"

        try:
            async with httpx.AsyncClient(headers=self.HEADERS, timeout=20, follow_redirects=True) as client:
                resp = await client.get(url)
                soup = BeautifulSoup(resp.text, 'html.parser')

                report_links = []
                for link in soup.find_all('a', href=re.compile(r'/reports/\d+')):
                    href = link.get('href', '')
                    if href and href not in [r['url'] for r in report_links]:
                        full_url = urljoin("https://hackerone.com", href)
                        report_links.append({"url": full_url, "title": link.get_text(strip=True)})

                for i, report in enumerate(report_links[:limit]):
                    await asyncio.sleep(self.delay)
                    try:
                        r_resp = await client.get(report['url'])
                        r_soup = BeautifulSoup(r_resp.text, 'html.parser')
                        elem = r_soup.select_one('article, .report-content, .markdown-body')
                        content = elem.get_text(separator='\n', strip=True) if elem else r_soup.get_text(separator='\n', strip=True)[:4000]

                        if content and len(content) > 150:
                            writeups.append({
                                "source": "hackerone",
                                "url": report['url'],
                                "title": report['title'] or f"HackerOne Report {i+1}",
                                "content": content[:6000],
                                "scraped_at": datetime.now().isoformat(),
                                "hash": hashlib.md5(content.encode()).hexdigest()[:12]
                            })
                    except Exception as e:
                        log.warning(f"Error fetching HackerOne report {report['url']}: {e}")

        except Exception as e:
            log.warning(f"HackerOne scraping failed: {e}")

        return writeups

    async def scrape_github_writeups(self, query: str = "bug bounty writeup", limit: int = 15) -> List[Dict]:
        """البحث في مستودعات GitHub عن شروحات وتقارير الثغرات"""
        log.info(f"[*] Searching GitHub for: '{query}'...")
        writeups = []
        search_url = "https://api.github.com/search/repositories"
        params = {"q": query, "sort": "updated", "order": "desc", "per_page": limit}

        try:
            async with httpx.AsyncClient(headers=self.HEADERS, timeout=20) as client:
                resp = await client.get(search_url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    for repo in data.get('items', [])[:limit]:
                        owner = repo['owner']['login']
                        name = repo['name']
                        readme_urls = [
                            f"https://raw.githubusercontent.com/{owner}/{name}/main/README.md",
                            f"https://raw.githubusercontent.com/{owner}/{name}/master/README.md",
                        ]
                        readme_content = ""
                        for ru in readme_urls:
                            try:
                                r_res = await client.get(ru)
                                if r_res.status_code == 200:
                                    readme_content = r_res.text
                                    break
                            except Exception:
                                pass

                        if readme_content and len(readme_content) > 200:
                            writeups.append({
                                "source": "github",
                                "url": repo['html_url'],
                                "title": name.replace('-', ' ').title(),
                                "content": readme_content[:8000],
                                "scraped_at": datetime.now().isoformat(),
                                "hash": hashlib.md5(readme_content.encode()).hexdigest()[:12]
                            })
        except Exception as e:
            log.warning(f"GitHub scraping failed: {e}")

        return writeups

    async def scrape_medium_tag(self, tag: str = "bug-bounty", limit: int = 15) -> List[Dict]:
        """سحب أحدث مقالات Medium عبر الـ RSS Feed"""
        log.info(f"[*] Scraping Medium tag: '{tag}'...")
        writeups = []
        rss_url = f"https://medium.com/feed/tag/{tag}"

        try:
            async with httpx.AsyncClient(headers=self.HEADERS, timeout=20) as client:
                resp = await client.get(rss_url)
                soup = BeautifulSoup(resp.content, 'xml')

                for item in soup.find_all('item')[:limit]:
                    title = item.find('title')
                    link = item.find('link')
                    content = item.find('content:encoded') or item.find('description')

                    if title and link and content:
                        clean_text = BeautifulSoup(content.get_text(), 'html.parser').get_text(separator='\n')
                        writeups.append({
                            "source": "medium",
                            "url": link.get_text(strip=True),
                            "title": title.get_text(strip=True),
                            "content": clean_text[:6000],
                            "scraped_at": datetime.now().isoformat(),
                            "hash": hashlib.md5(clean_text.encode()).hexdigest()[:12]
                        })
        except Exception as e:
            log.warning(f"Medium scraping failed: {e}")

        return writeups

    async def scrape_owasp_cheatsheets(self, limit: int = 15) -> List[Dict]:
        """سحب أوراق إرشادات وقواعد OWASP Cheat Sheets"""
        log.info("[*] Scraping OWASP Cheat Sheets...")
        writeups = []
        base_url = "https://cheatsheetseries.owasp.org/cheatsheets/"

        try:
            async with httpx.AsyncClient(headers=self.HEADERS, timeout=20) as client:
                resp = await client.get(base_url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                links = soup.find_all('a', href=re.compile(r'cheatsheets/.*\.html$'))

                for link in links[:limit]:
                    await asyncio.sleep(self.delay)
                    sheet_url = urljoin(base_url, link['href'])
                    try:
                        s_resp = await client.get(sheet_url)
                        s_soup = BeautifulSoup(s_resp.text, 'html.parser')
                        for nav in s_soup.find_all(['nav', 'header', 'footer']):
                            nav.decompose()
                        content = s_soup.get_text(separator='\n', strip=True)
                        if len(content) > 300:
                            writeups.append({
                                "source": "owasp",
                                "url": sheet_url,
                                "title": link.get_text(strip=True),
                                "content": content[:8000],
                                "scraped_at": datetime.now().isoformat(),
                                "hash": hashlib.md5(content.encode()).hexdigest()[:12]
                            })
                    except Exception:
                        pass
        except Exception as e:
            log.warning(f"OWASP scraping failed: {e}")

        return writeups

    async def scrape_url(self, url: str) -> Optional[Dict]:
        """سحب وتجريد أي رابط صفحة ويب أو مقال مفرد"""
        try:
            async with httpx.AsyncClient(headers=self.HEADERS, timeout=20, follow_redirects=True) as client:
                resp = await client.get(url)
                soup = BeautifulSoup(resp.text, 'html.parser')
                for tag in soup.find_all(['script', 'style', 'nav', 'header', 'footer', 'aside']):
                    tag.decompose()
                title = soup.find('title')
                title_text = title.get_text(strip=True) if title else "Unknown Article"
                content = soup.get_text(separator='\n', strip=True)
                return {
                    "source": "url",
                    "url": url,
                    "title": title_text,
                    "content": content[:10000],
                    "scraped_at": datetime.now().isoformat(),
                    "hash": hashlib.md5(content.encode()).hexdigest()[:12]
                }
        except Exception as e:
            log.warning(f"Failed to scrape URL {url}: {e}")
            return None


class VectorSkillStorage:
    """قاعدة بيانات المهارات المتجهة والبحث الدلالي (Vector DB + Cosine Similarity)"""

    VOCAB = [
        "sql", "injection", "xss", "cross", "script", "idor", "direct", "object",
        "lfi", "local", "file", "rfi", "remote", "rce", "code", "execution",
        "ssrf", "server", "side", "request", "forgery", "csrf", "token",
        "xxe", "xml", "external", "entity", "ssti", "template", "nosql",
        "graphql", "oauth", "jwt", "json", "web", "cors", "clickjacking",
        "redirect", "open", "path", "traversal", "business", "logic", "api",
        "mass", "assignment", "bola", "auth", "authentication", "authorization",
        "disclosure", "information", "race", "condition", "parameter", "input",
        "validation", "cookie", "session", "header", "bypass", "privilege",
        "escalation", "admin", "user", "password", "exploit", "payload",
        "vulnerability", "attack", "vector", "component", "impact", "mitigation"
    ]

    def __init__(self):
        self.skills_file = VECTOR_DB_DIR / "skills_db.json"
        self.embeddings_file = VECTOR_DB_DIR / "embeddings.json"
        self.skills_db: List[Dict] = self._load_json(self.skills_file, [])
        self.embeddings: Dict[str, List[float]] = self._load_json(self.embeddings_file, {})

    def _load_json(self, path: Path, default):
        if path.exists():
            try:
                return json.loads(path.read_text(encoding='utf-8'))
            except Exception:
                return default
        return default

    def _save_json(self, path: Path, data):
        try:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
        except Exception as e:
            log.error(f"Failed to save {path}: {e}")

    def _vectorize(self, text: str) -> List[float]:
        text_lower = text.lower()
        words = text_lower.split()
        total_len = max(len(words), 1)
        return [text_lower.count(w) / total_len for w in self.VOCAB]

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        dot = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(b * b for b in vec2))
        return dot / (norm1 * norm2) if (norm1 > 0 and norm2 > 0) else 0.0

    def add_skill(self, skill: Dict) -> bool:
        skill_hash = skill.get("content_hash", "")
        for existing in self.skills_db:
            if existing.get("content_hash") == skill_hash:
                return False

        searchable_text = f"{skill.get('title','')} {skill.get('category','')} {skill.get('vulnerability_type','')} {' '.join(skill.get('attack_vectors',[]))} {' '.join(skill.get('payloads',[]))}"
        embedding = self._vectorize(searchable_text)

        skill_id = f"skill_{len(self.skills_db)}_{skill_hash}"
        skill["skill_id"] = skill_id

        self.skills_db.append(skill)
        self.embeddings[skill_id] = embedding
        return True

    def save(self):
        self._save_json(self.skills_file, self.skills_db)
        self._save_json(self.embeddings_file, self.embeddings)

    def find_relevant_skills(self, target_data: str, top_k: int = 5) -> List[Dict]:
        if not self.skills_db:
            return []
        target_vec = self._vectorize(target_data)
        scored = []
        for skill in self.skills_db:
            sid = skill.get("skill_id", "")
            if sid in self.embeddings:
                sim = self._cosine_similarity(target_vec, self.embeddings[sid])
                scored.append((sim, skill))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [s for sim, s in scored[:top_k] if sim > 0.04]


class AutoScraperLearner:
    """المنسق الشامل لعمليات الزحف والتعلم وحفظ المهارات المتجهة"""

    def __init__(self):
        self.scraper = WriteupScraper()
        self.storage = VectorSkillStorage()

    async def train_from_source(self, source: str, **kwargs) -> Dict[str, Any]:
        url_input = kwargs.get("url") or kwargs.get("query", "")
        if url_input and (url_input.startswith("http://") or url_input.startswith("https://")):
            source = "url"
            kwargs["url"] = url_input

        log.info(f"[*] Training from source: {source}...")
        writeups = []

        if source == "url":
            res = await self.scraper.scrape_url(kwargs.get("url", ""))
            writeups = [res] if res else []
        elif source == "hackerone":
            writeups = await self.scraper.scrape_hackerone(kwargs.get("limit", 10))
        elif source == "github":
            writeups = await self.scraper.scrape_github_writeups(kwargs.get("query", "bug bounty writeup"), kwargs.get("limit", 10))
        elif source == "medium":
            writeups = await self.scraper.scrape_medium_tag(kwargs.get("tag", "bug-bounty"), kwargs.get("limit", 10))
        elif source == "owasp":
            writeups = await self.scraper.scrape_owasp_cheatsheets(kwargs.get("limit", 10))

        if not writeups:
            return {"status": "no_writeups", "new_skills": 0}

        # معالجة النصوص واستخلاص المهارات
        new_count = 0
        for w in writeups:
            title = w.get("title", "Security Skill")
            content = w.get("content", "")
            cat = self._detect_category(title + " " + content)

            skill = {
                "category": cat,
                "title": title,
                "vulnerability_type": title,
                "attack_vectors": [content[:300]],
                "payloads": [],
                "source_url": w.get("url", ""),
                "content_hash": w.get("hash", ""),
                "processed_at": datetime.now().isoformat()
            }

            if self.storage.add_skill(skill):
                new_count += 1
                # كتابة إلى data/skills/{cat}.txt
                txt_file = SKILLS_DIR / f"{cat}.txt"
                entry = f"\n\n=== Skill: {title} ({w.get('source','Web')}) ===\nSource: {w.get('url','')}\n{content[:600]}\n"
                try:
                    with open(txt_file, "a", encoding="utf-8") as fp:
                        fp.write(entry)
                except Exception:
                    pass

        self.storage.save()
        return {
            "status": "success",
            "source": source,
            "scraped_writeups": len(writeups),
            "new_skills_added": new_count,
            "total_skills_in_db": len(self.storage.skills_db)
        }

    def _detect_category(self, text: str) -> str:
        t = text.lower()
        if "sql" in t or "union select" in t: return "sqli"
        if "xss" in t or "script" in t or "dom" in t: return "xss"
        if "idor" in t or "object reference" in t or "bola" in t: return "idor"
        if "ssrf" in t or "169.254" in t: return "ssrf"
        if "jwt" in t or "token" in t or "auth" in t: return "jwt_broken_auth"
        if "cors" in t or "origin" in t: return "cors_misconfiguration"
        if "graphql" in t or "mutation" in t: return "graphql_security"
        if "oauth" in t or "redirect_uri" in t: return "oauth_flaws"
        if "upload" in t or "shell" in t: return "file_upload"
        return "general_vulnerability"
