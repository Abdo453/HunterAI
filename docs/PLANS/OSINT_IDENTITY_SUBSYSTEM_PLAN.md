# خطة OSINT Identity Subsystem — HunterAI
> **موصفات جاهزة للتنفيذ (Codex-Ready Spec)**
> الإصدار: 1.0 | التاريخ: 2026-09-30 | الحالة: PROPOSED

---

## 1. الملخص التنفيذي (Executive Summary)

إضافة **OSINT Identity Subsystem** كامل لـ HunterAI: نظام اكتشاف الهوية الرقمية (Digital Identity) متعدد المتجهات (Username + Email + GitHub + Domains + Breach Indicators)، ينتهي بـ **Evidence Graph** و **Identity Correlation Engine** يحسب درجة ثقة لكل ربط هوية.

**المبدأ الحاكم (مستخلص من النقاش):**

```text
نتائج الـ OSINT = Evidence فقط، وليست Findings مؤكدة أبدًا.
"وجود نفس الـ username وحده لا يثبت أن الحسابات لنفس الشخص."
درجة الثقة يحددها Correlation Engine حصريًا — ليس الـ LLM، وليس الأداة.
```

هذا المبدأ **متوافق 100%** مع الـ Invariant الموجود في `ARCHITECTURE.md`:
> *Zero LLM Heuristic Confirmation* — الـ LLM يعمل كـ Hypothesis Generator فقط.

---

## 2. الفجوة الحالية (Gap Analysis)

| الموجود حاليًا | أين | المشكلة |
|:---|:---|:---|
| `OSINTTools.sherlock(username)` | `tools/osint_tools.py` | تنفيذ خام (raw execution) — بدون normalize أو تفسير أو confidence |
| `CorrelationEngine` | `hunter_ai/pipeline/correlation.py` | مخصص للـ endpoints/secrets — لا يعرف الهوية إطلاقًا |
| `IdentityGraph` (مذكور) | `ARCHITECTURE.md` — Layer 2 | **لا يوجد أي module يغذيه** بـ identity evidence حقيقي |
| `BugBountyMethodology.generate_dorks()` | `core/playbooks/` | passive dorks فقط — لا يربط النتائج بحسابات فعلية |

**الخلاصة:** عندنا أدوات مفككة بلا عقل. المطلوب Agent يعرف **إمتى** يستخدم OSINT، **إيه** الـ input، **إزاي** يفسر النتائج، و**إزاي** يمنع الـ false positives.

---

## 3. المبادئ الحاكمة (Governing Principles)

### P-OSINT-1: Evidence ≠ Finding
كل نتيجة username/email match تُسجل كـ `IdentityEvidenceRecord` بمستوى **E0 (Observation)** كحد أقصى **E1 (Corroborated)**. لا يمكن أن تصل E2 (Repro) إلا عبر:
- فحص فعلي للحساب المكتشف (صفحة/محتوى/API) بواسطة Browser Worker أو أداة second-source.
- مرورها على الـ **Adversarial Evidence Court** كأي finding آخر.

### P-OSINT-2: Multi-Tool Fan-Out — لا قلب واحد للنظام
الأداة الموجودة في المقالات (CB UserHunter وأمثالها) **قديمة** مقارنة بأدوات 2026 مثل `user-scanner v1.5.1` (مئات الـ vectors + cross-scanning بين username/email + استخدام mobile app APIs بدل web status codes فقط). لذلك:

```text
                HunterAI
                   │
          ┌────────┴────────┐
          │                 │
     Username OSINT      Email OSINT
          │                 │
     ┌────┼────┐        ┌───┼────┐
     │    │    │        │   │    │
   Tool1 Tool2 Tool3   Tool1 Tool2 Tool3
     │    │    │        │   │    │
     └────┴────┘        └───┴────┘
             │
             ▼
      Evidence Normalizer   ← كل الأدوات تُصب في schema واحد
             │
             ▼
      Identity Correlation
             │
             ▼
        Evidence Graph
```

- كل vector يشغّل 2-3 أدوات على الأقل؛ الأداة الواحدة لا تصدّق أبدًا وحدها.
- الأدوات **قابلة للاستبدال** (pluggable) — لو ظهر أداة أحدث، نضيف adapter بدون تغيير الـ pipeline.

### P-OSINT-3: Scope & Egress Governance (P0 Constitution)
الـ OSINT يلمس خدمات خارجية (GitHub, Reddit, Instagram...). لذلك:
- كل query خارجي يمر عبر **Policy Gate** ويُسجل في Negative Space Ledger (`PROBED_EXTERNAL`, `SKIPPED_POLICY_RESTRICTION`).
- حظر أي فحص خارج نطاق الـ authorization scope المعلن (P0: Zero Out-of-Scope Egress).
- Rate limiting إجباري per-platform لحظر الـ abuse والكشف.

### P-OSINT-4: الوكيل يعرف السياق (Agent Epistemics)
الـ Agent (وليس الأداة) يحدد: متى يشغّل الفحص، بأي input، كيف يقرأ النتيجة، وكيف يمنع الـ false positives — عبر reasoning rules صريحة (القسم 8).

---

## 4. المعمارية (Architecture)

```text
┌─────────────────────────────────────────────────────────────────┐
│                     OSINT IDENTITY SUBSYSTEM                     │
│                                                                  │
│  ┌──────────────┐   ┌───────────────────────────────────────┐  │
│  │ Trigger      │   │  VECTOR FAN-OUT LAYER                  │  │
│  │ Conditions   │──▶│                                       │  │
│  │ (Agent rules)│   │  Username Vector:                     │  │
│  └──────────────┘   │    sherlock + maigret + blackbird     │  │
│                     │  Email Vector:                         │  │
│  ┌──────────────┐   │    holehe + ghunt + h8mail(indicator)  │  │
│  │ Input        │──▶│  GitHub Vector:                        │  │
│  │ Contract     │   │    github-dorks + enumerepo + API     │  │
│  └──────────────┘   │  Domain Vector:                        │  │
│                     │    whois + DNS + cert transparency      │  │
│                     └───────────────────┬───────────────────┘  │
│                                         ▼                      │
│                     ┌───────────────────────────────────────┐  │
│                     │  EVIDENCE NORMALIZER (canonical schema)│  │
│                     │  normalize → dedupe → E0 tagging       │  │
│                     └───────────────────┬───────────────────┘  │
│                                         ▼                      │
│                     ┌───────────────────────────────────────┐  │
│                     │  IDENTITY CORRELATION ENGINE          │  │
│                     │  cross-vector matching + weighted     │  │
│                     │  confidence scoring (0.0 → 1.0)       │  │
│                     └───────────────────┬───────────────────┘  │
│                                         ▼                      │
│                     ┌───────────────────────────────────────┐  │
│                     │  IDENTITY EVIDENCE GRAPH               │  │
│                     │  → يغذي IdentityGraph (Layer 2)        │  │
│                     │  → Evidence Court (Layer 5)            │  │
│                     │  → Evidence Graph (control plane)      │  │
│                     └───────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 5. المكونات والتغييرات على مستوى الملفات (File-Level Changes)

### 5.1 حزمة جديدة: `core/osint/`

```
core/osint/
├── __init__.py
├── schemas.py               # IdentityEvidenceRecord, IdentityCluster, ...
├── evidence_normalizer.py   # توحيد مخرجات كل الأدوات في schema واحد
├── identity_correlation.py  # محرك الربط + confidence scoring
├── confidence_model.py      # أوزان الإشارات (Signal Weights)
├── fp_guards.py             # قواعد منع الـ False Positives
└── platform_registry.py     # قائمة المنصات + متطلبات كل منصة
```

### 5.2 توسيع `tools/osint_tools.py` (نفس نمط الأدوات الموجود)

```python
# ── Username Vector ──────────────────────────────────────────
async def maigret(self, username: str) -> ToolResult:
    """مئات المواقع + cloudflare bypass — أقوى من sherlock في 2026"""

async def blackbird(self, username: str) -> ToolResult:
    """Fast username scan across APIs"""

# ── Email Vector ─────────────────────────────────────────────
async def holehe(self, email: str) -> ToolResult:
    """يكتشف على أي منصة الـ email مسجل (uses password-reset flows)"""

async def ghunt(self, email: str) -> ToolResult:
    """Google account enumeration من الـ email"""

# ── Breach Indicators (metadata فقط — انظر القسم 11) ─────────
async def breach_indicator(self, email_or_username: str) -> ToolResult:
    """فحص سطحي لبعضان الظهور في breaches معروفة — بدون تنزيل بيانات"""

# ── Cross-Scan (user-scanner style) ──────────────────────────
async def cross_scan(self, username: str, email: str) -> ToolResult:
    """استخراج username من email والعكس + فحص مزدوج — v1.5.1 style"""
```

### 5.3 Agent جديد: `agents/osint_identity_agent.py`

يتبع نفس نمط `BaseAgent` / `AgentTask` / `AgentResult` الموجود:

```python
class OSINTIdentityAgent(BaseAgent):
    """
    OSINT Identity Agent — اكتشاف الهوية الرقمية + ربط الحسابات.
    يُنتج IdentityEvidence (E0/E1) فقط — أبدًا Findings مؤكدة.
    """
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "osint_identity_agent",
            "OSINT Identity — username/email enumeration + correlation",
            mgr, cb
        )
        self.osint = OSINTTools(mgr)

    async def run(self, task: AgentTask) -> AgentResult:
        # task.extra: {"username": str?, "email": str?, "source": str}
        # 1. التحقق من trigger conditions + policy gate (P0)
        # 2. Fan-out على المتجهات المتاحة
        # 3. Normalize → Correlate → Score
        # 4. إخراج IdentityCluster(s) كـ evidence findings (severity=Info)
        ...
```

### 5.4 ربط الـ Subsystem بالـ Pipeline الحالي

| نقطة الربط | الملف | التغيير |
|:---|:---|:---|
| Schemas | `hunter_ai/pipeline/schemas.py` | إضافة `IdentityEvidenceRecord` + `IdentityCluster` |
| Correlation | `hunter_ai/pipeline/correlation.py` | دالة `correlate_identity_evidence()` بجانب الموجود |
| Capabilities | `hunter_ai/agents/capabilities.py` | إضافة `OSINT_IDENTITY = auto()` |
| Registry | `hunter_ai/agents/registry.py` | تسجيل `OSINTIdentityAgent` |
| Task Classifier | `orchestrator/task_classifier.py` | كلمات مفتاحية: `username`, `email osint`, `identity`, `holehe`, `maigret` |
| Playbook | `core/playbooks/master_recon_playbook.md` | مرحلة "Public Identity Discovery" بعد الـ Recon |
| CLI | `cli/hunter_cli.py` | أمر `hunter osint-identity` |

---

## 6. Data Schemas (Canonical)

```python
@dataclass
class IdentityEvidenceRecord:
    """نتيجة واحدة من أداة واحدة على منصة واحدة — E0 دائمًا."""
    record_id: str                  # uuid
    vector: str                     # "username" | "email" | "github" | "domain" | "breach"
    platform: str                   # "github" | "reddit" | "tiktok" | ...
    query_value: str                # القيمة المفحوصة
    match_url: str                  # رابط الحساب/الصفحة المكتشفة
    detection_method: str           # "web_status" | "mobile_api" | "password_reset" | "api_enumeration"
    raw_response_digest: str        # hash من الـ response (لا نحتفظ بـ PII زائدة)
    tool_name: str                  # "sherlock" | "maigret" | "holehe" | ...
    evidence_level: str = "E0"     # E0 Observation — الافتراضي دائمًا
    captured_at: float              # timestamp
    validation_note: str = ""       # ملاحظات الفحص (soft-404? redirect?)

@dataclass
class IdentityCluster:
    """مجموعة evidence مرتبطة بنفس الهوية الافتراضية."""
    cluster_id: str
    anchor: str                     # username أو email المرجعي
    members: List[IdentityEvidenceRecord]
    correlation_signals: Dict[str, float]   # الإشارات المكتشفة وأوزانها
    confidence: float                # 0.0 → 1.0 (يحددها Correlation Engine فقط)
    confidence_label: str            # "weak" | "possible" | "probable" | "strong"
    open_questions: List[str]        # أسئلة غير محسومة → Negative Space Ledger
```

**قاعدة صارمة:** `confidence_label != "strong"` → لا يدخل تقرير النتائج كـ finding؛ يبقى evidence في الـ graph للاستكشاف اللاحق.

---

## 7. نموذج الـ Confidence Scoring (Correlation Signals)

الـ Correlation Engine يجمع إشارات من الحسابات المكتشفة ويحسب وزنًا مركبًا:

| الإشارة | الوزن | طريقة الالتقاط |
|:---|:---:|:---|
| Username exact match | +0.15 | أساس كل شيء — **ضعيف وحده** |
| Display name match | +0.10 | مقارنة الاسم الظاهر عبر المنصات |
| Bio cross-links (حساب يذكر الآخر) | +0.25 | أقوى إشارة — ربط صريح |
| Avatar similarity (pHash) | +0.20 | perceptual hash بين صور البروفايل |
| Linked website مشترك | +0.20 | نفس الـ URL في bio أكثر من منصة |
| GitHub references (commit emails, org overlap) | +0.15 | ربط تقني عالي الثقة |
| Email → Username cross-scan hit | +0.15 | user-scanner style cross-validation |
| Registration date proximity | +0.05 | إشارة مساندة فقط |
| **إشارات سالبة (خصم):** | | |
| Generic username (admin/test/user/...) | −0.30 | قائمة blacklist |
| Soft-404 / generic profile page | −0.50 | دلالة عدم موثوقية |
| منصة واحدة فقط بلا تأكيد ثانٍ | −0.20 | single-source penalty |

```text
Score = Σ(positive signals) − Σ(negative signals)
Label mapping:
  0.00 – 0.25 → weak       (evidence only — لا يُعرض في التقرير)
  0.25 – 0.50 → possible   (evidence + open question)
  0.50 – 0.75 → probable   (candidate for E1 corroboration)
  0.75 – 1.00 → strong     (مسموح بالعرض كـ "probable identity link" — ليس "confirmed")
```

> **ملاحظة مهمة:** حتى `strong` لا يعني CONFIRMED بمعنى HunterAI (اللي يتطلب E2+ reproducible proof) — يعني فقط أن الـ correlation قوي بما يكفي لعرضه كـ **identity intelligence**.

---

## 8. قواعد عقل الوكيل (Agent Reasoning Rules)

الوكيل (وليس الأداة) يطبق هذه القواعد الصريحة:

### 8.1 متى يشغّل OSINT Identity؟ (Trigger Conditions)
```text
TRIGGER إذا توفر واحد على الأقل:
  T1. username ظهر في recon (git commits, JS author tags, package.json authors, HTML meta)
  T2. email ظهر في crawled JS / leaked strings / DNS TXT / whois registrant
  T3. المهمة صراحةً طلبت identity mapping (scope يشمل "employees" أو "public identities")
  T4. correlation مبدئي: نفس الـ identifier ظهر في أكثر من أصل (asset) من أصول الهدف

لا يشغّل أبدًا:
  X1. بدون policy gate يسمح بالـ external egress (P0)
  X2. على أهداف خارج الـ scope
  X3. كـ "fishing expedition" عشوائي بلا trigger
```

### 8.2 الـ Input Contract
```python
task.extra = {
    "username": "abdo453",          # اختياري
    "email": "abdo@example.com",    # اختياري
    "source": "git_commit_metadata", # إلزامي — مصدر الاكتشاف (يذهب للـ provenance)
    "vectors": ["username", "email"],  # اختياري — افتراضيًا كل المتاحة
    "max_platforms": 60             # حد أقصى للمنصات (rate-limit governance)
}
```

### 8.3 كيف يفسر النتائج؟ (Interpretation)
```text
R1. كل match = E0 observation حتى إشعار آخر.
R2. وجود نفس الـ username في N منصة ≠ نفس الشخص — هذه فرضية (H) وليست استنتاجًا.
R3. النتيجة تُصاغ كـ: "Hypothesis: accounts X, Y, Z may share an operator —
    confidence: possible (0.42) — signals: display_name(+0.10), avatar_phash(+0.20)..."
R4. أي حساب اكتُشف يدخل في Negative Space Ledger لو لم يُفحص محتواه:
    "ACCOUNT_DISCOVERED_NOT_VERIFIED: github.com/abdo453 (reason: content scan pending)"
R5. الـ LLM ممنوع من رفع confidence لأي cluster — التعديل يمر حصريًا عبر
    إشارات correlation جديدة (deterministic).
```

### 8.4 كيف يمنع الـ False Positives؟ (FP Guards — `fp_guards.py`)
```text
G1. Generic-username blacklist: admin, test, user, info, root, support, null, ...
G2. Soft-404 detection: صفحات تعيد 200 مع "profile not found" → تُرفض.
G3. Status-code unreliability: بعض المنصات ترجع 200 دائمًا (react SPA) →
    نثق فقط في mobile app APIs أو password-reset flows حيثما توفرت.
G4. Redirect chains: أي match انتهى في redirect لصفحة رئيسية = غير صالح.
G5. Single-source rule: أي cluster من منصة واحدة لا يتجاوز label=weak أبدًا.
G6. Rate limiting per platform: حد أقصى N queries/minute — يمنع الـ false bans
    التي تنتج matches كاذبة (anti-bot pages).
```

---

## 9. ربط الـ Evidence Levels بنظام HunterAI

```text
E0 (Observation)      ← كل tool match فور الاكتشاف (الافتراضي)
E1 (Corroborated)     ← match صُدّق من second source مختلف تمامًا
                         (مثال: maigret + فحص فعلي للـ profile بالـ browser)
E2 (Repro)           ← ⚠️ نادر ومقصود: فقط لو فحص المحتوى أثبت ربطًا
                         (نفس avatar bytes + bio links متبادلة) — يتطلب Court
E3+                   ← غير قابل للوصول عبر OSINT وحده — يتطلب تفاعلًا فعليًا
                         مع الحسابات وهو خارج non-goals (القسم 11)
```

---

## 10. المراحل (Phases) + معايير القبول

### Phase 1 — Username Vector + Evidence Normalizer
- إضافة `core/osint/schemas.py` + `evidence_normalizer.py`
- توسيع `OSINTTools` (maigret, blackbird) + تحويل sherlock إلى normalizer
- إضافة `agents/osint_identity_agent.py` (نسخة أولية)
- ✅ **Acceptance:** تشغيل username واحد → ملف evidence موحد (JSON) من 2+ أدوات، بلا نتائج منصات مكررة، وكل سجل E0.

### Phase 2 — Email Vector + Cross-Scanning
- إضافة holehe + ghunt adapters + `cross_scan()`
- استخراج username من email والعكس (regex + heuristics)
- ✅ **Acceptance:** فحص email واحد يُنتج vector records + cross-scan hits تدخل نفس الـ cluster graph.

### Phase 3 — Identity Correlation + Confidence Scoring
- بناء `identity_correlation.py` + `confidence_model.py` + `fp_guards.py`
- pHash للمقارنة بين الـ avatars، مقارنة bio cross-links
- ✅ **Acceptance:** على مجموعة اختبار معروفة (test identities): 
  - الـ clusters الصحيحة (نفس الشخص) ≥ 0.5 score
  - الـ clusters الخاطئة (أشخاص مختلفون بنفس الاسم) ≤ 0.25
  - zero generic usernames تتجاوز weak.

### Phase 4 — تكامل World Model + Evidence Court
- إرسال الـ clusters إلى `IdentityGraph` (Layer 2) و `Evidence Graph` (control plane)
- توليد hypotheses تلقائيًا من الـ clusters للـ investigation loop
- ✅ **Acceptance:** فتح `hunter trace --last` يظهر قرار الـ Agent بمتى/لماذا شغّل الـ OSINT، وكل cluster يظهر بـ confidence + signals + open questions.

### Phase 5 — MCP Tools + CLI + التوثيق
- MCP tools: `osint_username_scan`, `osint_email_scan`, `osint_identity_correlate`
- CLI: `hunter osint-identity --username X --email Y --vectors all`
- تحديث `AGENT_CONTEXT.md` (قسم جديد: OSINT Identity Subsystem) + `ARCHITECTURE.md`
- ✅ **Acceptance:** كل أمر MCP/CLI يعمل standalone ويُعيد نفس canonical schema.

---

## 11. Non-Goals & حدود قانونية/أخلاقية

```text
NG1. لا تنزيل أو تخزين بيانات breaches (كلمات سر/بيانات شخصية) —
     breach indicators فقط (نعم/لا + مصدر المؤشر) بدون محتوى.
NG2. لا تفاعل مع الحسابات المكتشفة (login, follow, message) — E3+ خارج النطاق.
NG3. لا OSINT على أشخاص بدون صلة بالـ scope المصرح به (P0 constitution).
NG4. احترام ToS للمنصات: التزام بـ rate limits، عدم scraping عنيف،
     تفضيل mobile/public APIs المشروعة على HTML scraping.
NG5. لا عرض "confirmed identity" أبدًا في أي تقرير — الحد الأقصى
     "probable identity link (correlation-based)".
NG6. الـ PII المجموعة (avatars, bios) تُخزن digests/hashes حيثما أمكن،
     وتُحذف مع نهاية الـ engagement (retention policy).
```

---

## 12. Test Plan (مختصر)

| الاختبار | النوع | الملف المقترح |
|:---|:---|:---|
| Normalizer يوحد مخرجات 3 أدوات مختلفة بلا فقد بيانات | unit | `tests/test_osint_normalizer.py` |
| Generic usernames لا تتجاوز weak أبدًا | unit | `tests/test_fp_guards.py` |
| Soft-404 يُرفض ولا يُحسب match | unit | `tests/test_fp_guards.py` |
| Cluster صحيح (نفس الشخص عبر منصات) يتجاوز 0.5 | integration | `tests/test_identity_correlation.py` |
| Policy gate يمنع فحص خارج scope | integration | `tests/test_osint_policy.py` |
| E2E: username → clusters → evidence graph → hypotheses | e2e | `tests/test_osint_e2e.py` |

---

## 13. المراجع (من النقاش)

- **CB UserHunter** (أداة المقال): فكرة username enumeration عبر عشرات المواقع — **ليست قلب النظام**، مجرد إشارة في fan-out layer.
- **user-scanner v1.5.1 (2026)**: مئات username/email scan vectors + automated cross-scanning + native MCP support + mobile app API vectors — نموذج معماري نستلهم منه الـ vectors وcross-scan.
- **arXiv:1101.5578** — *How Unique and Traceable are Usernames?*: الأساس العلمي — إعادة استخدام الـ usernames قابلة للتتبع لكنها ليست إثباتًا.
- hunterAI invariants: `ARCHITECTURE.md` (Zero LLM Heuristic Confirmation, E0→E5, P0-P4, Negative Space Ledger).

---

> **جاهزة للتسليم لـ Codex** — هذه المواصفات self-contained: كل ما يحتاجه المنفذ من context (المسارات، الأنماط، الأنماط المعمارية الموجودة، معايير القبول) موجود أعلاه أو مُشار إليه بملفاته في الـ repo.
