"""
Threat Intelligence & CVE Learning Feed Engine
محرك استيراد وتعلم الثغرات الحديثة من NIST NVD وقواعد البيانات العالمية
يتيح للـ AI فهم أحدث الثغرات المنشورة، شرح آلياتها التقنية، وتقديم حلول الترقيع
"""
import asyncio
import json
import time
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import httpx

log = logging.getLogger("cve_learner")


class CVEFeedLearner:
    """
    محرك التعلم واستيراد الثغرات الحديثة (Threat Intelligence Ingestion):
    - يجلب أحدث ثغرات الـ CVE المنشورة من مصادر موثوقة (NIST NVD / CIRCL / CISA)
    - يفهرس التفاصيل الفنية، درجات الخطورة (CVSS)، وأنواع الـ CWE
    - يوفر سياقاً معرفياً للموديلات لشرح وتحليل الثغرات فور صدورها
    """

    def __init__(self, storage_file: str = "data/cve_knowledge_base.json"):
        self.storage_path = Path(storage_file)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.db: Dict[str, Dict[str, Any]] = {}
        self.load_local_db()

    def load_local_db(self):
        """تحميل قاعدة المعرفة المحلية للثغرات المحفوظة"""
        if self.storage_path.exists():
            try:
                self.db = json.loads(self.storage_path.read_text(encoding="utf-8"))
            except Exception as e:
                log.warning(f"Failed to load CVE database: {e}")
                self.db = {}

    def save_local_db(self):
        """حفظ التحديثات في الملف المحلي"""
        try:
            self.storage_path.write_text(json.dumps(self.db, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            log.error(f"Failed to save CVE database: {e}")

    async def fetch_recent_cves(self, limit: int = 15) -> List[Dict[str, Any]]:
        """جلب أحدث ثغرات الـ CVE المنشورة حديثاً من واجهة CIRCL / Open Feed"""
        url = "https://cve.circl.lu/api/last"
        new_cves = []

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url)
                if r.status_code == 200:
                    data = r.json()
                    for item in data[:limit]:
                        cve_id = item.get("id", "")
                        if not cve_id:
                            continue

                        summary = item.get("summary", "")
                        cvss = float(item.get("cvss", 0.0) or 0.0)
                        cwe = item.get("cwe", "Unknown")
                        published = item.get("Published", "")

                        entry = {
                            "cve_id": cve_id,
                            "summary": summary,
                            "cvss": cvss,
                            "cwe": cwe,
                            "published": published,
                            "references": item.get("references", [])[:3],
                            "last_updated": time.time()
                        }

                        self.db[cve_id] = entry
                        new_cves.append(entry)

                    self.save_local_db()
                    log.info(f"Learned {len(new_cves)} recent CVEs successfully.")
        except Exception as e:
            log.warning(f"Error fetching latest CVE feed: {e}")

        return new_cves

    def search_cve(self, query: str) -> List[Dict[str, Any]]:
        """البحث في المعرفة المخزنة عن CVE أو تقنية معينة"""
        q = query.lower().strip()
        matches = []
        for cve_id, data in self.db.items():
            if q in cve_id.lower() or q in data.get("summary", "").lower() or q in data.get("cwe", "").lower():
                matches.append(data)
        return matches

    def get_cve_detail(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """استرجاع بيانات CVE محددة"""
        return self.db.get(cve_id.upper().strip())

    def format_cve_explanation_prompt(self, cve_id: str) -> Optional[str]:
        """تجهيز سياق تعليمي للموديل ليشرح الثغرة هندسياً وتقنياً"""
        entry = self.get_cve_detail(cve_id)
        if not entry:
            return None

        prompt = f"""### CVE Technical Briefing: {entry['cve_id']}
- **Summary:** {entry['summary']}
- **CVSS Base Score:** {entry['cvss']}
- **Weakness Category (CWE):** {entry['cwe']}
- **Publication Date:** {entry['published']}

Please provide a structured technical breakdown:
1. **Root Cause Analysis:** Explain the underlying code/architecture flaw causing this vulnerability.
2. **Affected Components & Preconditions:** What conditions make a target vulnerable?
3. **Auditing & Detection:** How can security analysts identify if an asset is exposed?
4. **Remediation & Hardening:** Official patches, configuration changes, or defensive mitigations.
"""
        return prompt
