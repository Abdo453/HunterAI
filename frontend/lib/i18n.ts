"use client";

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import catalogData from "./catalog.json";

export type Lang = "ar" | "en";

export const LANG_STORAGE_KEY = "hunterai_lang";

type NestedDict = { [key: string]: string | NestedDict };

const AR_ARTEX: NestedDict = {
  brand: {
    name: "ARTEX-Pro",
    engineTag: "Go Core + Hub",
    subtitle: "مركز القيادة السيبراني الموحد واكتشاف الأصول",
    footer: "معمارية ARTEX-Pro الموحدة · محرك Go المتزامن + PostgreSQL + FastAPI Hub + Next.js",
  },
  nav: {
    allEngagements: "جميع المشاريع / الأهداف",
    engagementLabel: "المشروع النشط",
    targetPlaceholder: "نطاق الهدف (مثال: example.com)",
    launchMission: "إطلاق الفحص",
    launching: "جارِ الإرسال...",
    scopeInvalidEmpty: "يرجى إدخال نطاق أو رابط هدف صالح.",
    scopeInvalidLocal: "محظور بواسطة حراسة النطاق: عناوين Localhost والشبكات الداخلية وميتاداتا السحابة غير مسموحة.",
    scopeOutOfScope: "الهدف مستثنى في قواعد النطاق (Out-of-Scope) للمشروع النشط.",
    scopeNotInScope: "الهدف خارج النطاق المصرح به (In-Scope) للمشروع النشط.",
    scopeFormatHint: "أدخل اسم نطاق أو رابط HTTP(S) صالحاً (مثال: example.com).",
    goCore: "نواة Go",
    hunterHub: "مركز Hunter Hub",
    controlCenter: "لوحة التحكم",
    opencodeIde: "استوديو OpenCode",
    copilotBtn: "المساعد الذكي",
    menuBtn: "القائمة",
    lastSynced: "آخر مزامنة",
  },
  status: {
    connected: "متصل",
    degraded: "متأثر (DB)",
    offline: "غير متصل",
    checking: "جارِ الفحص",
    standby: "في وضع الاستعداد",
    never: "لم تتم المزامنة بعد",
    goOfflineBanner: "نواة Go Core (127.0.0.1:7071) غير متاحة حالياً. يتم عرض حالة حقيقية دون بيانات وهمية.",
    goDegradedBanner: "نواة Go Core متصلة لكن قاعدة بيانات PostgreSQL غير متصلة أو متأثرة.",
    hubOfflineBanner: "مركز FastAPI Hub (127.0.0.1:8000) غير متاح حالياً. ميزات الموافقات والتشغيلات والمحادثة المباشرة متوقفة مؤقتاً.",
  },
  stats: {
    assetsLabel: "الأصول المفهرسة",
    assetsDesc: "عقد PostgreSQL asset_nodes",
    endpointsLabel: "نقاط النهاية الحية",
    endpointsDesc: "مضيفات وروابط HTTP مستجيبة",
    findingsLabel: "الثغرات المصنفة",
    findingsDesc: "نتائج موثقة ومحققة",
    runsLabel: "التشغيلات والمهام النشطة",
    runsDesc: "مهام Go ومحرك FastAPI الحية",
  },
  graph: {
    title: "طوبولوجيا سطح الهجوم والجدول المزدوج",
    rootLabel: "الهدف الجذري",
    topologyView: "رسم الطوبولوجيا",
    tableView: "عرض الجدول",
    searchPlaceholder: "بحث في الأصول والقيم والعناوين...",
    allKinds: "كل الأنواع",
    showingWindow: "عرض {shown} من {total}",
    expandCluster: "توسيع الكل ({count})",
    collapseCluster: "طي ({count})",
    resetView: "إعادة ضبط العرض",
    emptyTitle: "لا توجد عقد أصول مسجلة حالياً.",
    emptySub: "أطلق مهمة استطلاع عبر الشريط العلوي أو تحقق من اتصال نواة Go.",
    colKind: "النوع",
    colValue: "القيمة / المسار",
    colStatus: "الحالة",
    colTitle: "العنوان / التقنية",
    colSeen: "وقت الرصد",
    prevPage: "السابق",
    nextPage: "التالي",
    pageOf: "صفحة {page} من {total}",
    inspectorTitle: "مفتش الأصل التفصيلي",
    attributesJson: "خصائص JSON الكاملة (Attributes)",
    openUrl: "فتح الرابط",
    noAttributes: "لا توجد خصائص إضافية مسجلة.",
  },
  findings: {
    title: "سجل الثغرات الموثقة وبوابة التحقق",
    searchPlaceholder: "بحث في العنوان، التصنيف، أو المسار...",
    sortByCvss: "ترتيب: CVSS",
    sortByConfidence: "ترتيب: الثقة",
    downloadJson: "تصدير JSON",
    downloadMd: "تصدير Markdown",
    emptyTitle: "لا توجد ثغرات مسجلة بعد.",
    emptySub: "ستظهر الثغرات الموثقة فور اكتشافها والتحقق منها.",
    detailTitle: "تفاصيل الثغرة وإثبات التنفيذ",
    endpointLabel: "نقطة النهاية المتأثرة",
    vulnClassLabel: "تصنيف الثغرة",
    cvssLabel: "تقييم CVSS",
    confidenceLabel: "درجة الثقة",
    evidenceLabel: "الأدلة وخطوات الإثبات (PoC)",
    noEvidence: "لم يتم تسجيل تفاصيل إثبات نصية لهذه الثغرة.",
  },
  approvals: {
    title: "بوابة الموافقات الحية",
    pendingBadge: "معلقة",
    historyBadge: "السجل",
    notePlaceholder: "ملاحظة المراجع (اختياري)...",
    approveBtn: "موافقة",
    rejectBtn: "رفض",
    deciding: "جارِ التنفيذ...",
    emptyPending: "لا توجد طلبات موافقة معلقة حالياً.",
    offlineNotice: "مركز FastAPI Hub غير متصل — تعذر جلب طلبات الموافقة.",
  },
  console: {
    title: "وحدة التحكم المباشرة وسجل التدقيق (Go Audit & Stream)",
    pauseStream: "إيقاف البث مؤقتاً",
    resumeStream: "استئناف البث",
    pausedLabel: "متوقف مؤقتاً",
    clearBtn: "مسح",
    levelAll: "الكل",
    emptyLogs: "لا توجد أحداث مسجلة في الجلسة الحالية.",
  },
  copilot: {
    title: "مساعد HunterAI الذكي",
    newSession: "جلسة جديدة",
    deleteSession: "حذف الجلسة",
    modeLabel: "النمط",
    modelLabel: "النموذج",
    placeholder: "اسأل عن الأصول أو الثغرات أو اطلب تحليلاً أمنياً...",
    sendBtn: "إرسال",
    sending: "جارِ البث...",
    attachBtn: "إرفاق ملف",
    expandWidth: "توسيع العرض",
    restoreWidth: "استعادة العرض",
    offlineBanner: "مركز FastAPI Hub غير متاح — تعذر الاتصال بخدمة Copilot.",
    fallbackTag: "وضع استدلال محلي (بدون LLM متصل)",
    refsTitle: "المراجع المرتبطة",
    approvalQueued: "تم إنشاء طلب موافقة",
    policyBlocked: "محظور بواسطة محرك السياسات",
    noConversations: "ابدأ محادثة جديدة لتحليل الأصول والثغرات أثناء تشغيل الفحوصات.",
    refMissing: "السجل المشار إليه غير محمّل في العرض الحالي.",
  },
};

const EN_ARTEX: NestedDict = {
  brand: {
    name: "ARTEX-Pro",
    engineTag: "Go Core + Hub",
    subtitle: "Unified Cyber Command Center & Attack Surface Graph",
    footer: "ARTEX-Pro Unified Architecture · Go Concurrency Engine + PostgreSQL + FastAPI Hub + Next.js",
  },
  nav: {
    allEngagements: "All Engagements",
    engagementLabel: "Active Engagement",
    targetPlaceholder: "Target domain (e.g. example.com)",
    launchMission: "Launch Mission",
    launching: "Dispatching...",
    scopeInvalidEmpty: "Enter a target domain or URL to scan.",
    scopeInvalidLocal: "Blocked by ScopeGuard: localhost, loopback, private ranges, and cloud metadata hosts are prohibited.",
    scopeOutOfScope: "Target matches an Out-of-Scope exclusion on the active engagement.",
    scopeNotInScope: "Target falls outside the active engagement's In-Scope boundary.",
    scopeFormatHint: "Provide a valid domain or HTTP(S) target (e.g. example.com).",
    goCore: "Go Core",
    hunterHub: "Hunter Hub",
    controlCenter: "Control Center",
    opencodeIde: "OpenCode IDE",
    copilotBtn: "Copilot",
    menuBtn: "Menu",
    lastSynced: "Last synced",
  },
  status: {
    connected: "Connected",
    degraded: "Degraded (DB)",
    offline: "Offline",
    checking: "Checking",
    standby: "Standby",
    never: "Not synced yet",
    goOfflineBanner: "Go Core API (127.0.0.1:7071) is currently unreachable. Displaying truthful offline telemetry.",
    goDegradedBanner: "Go Core API is reachable, but PostgreSQL reported disconnected/degraded health.",
    hubOfflineBanner: "FastAPI Platform Hub (127.0.0.1:8000) is offline. Approvals, managed runs, and live Copilot streaming are paused.",
  },
  stats: {
    assetsLabel: "Indexed Assets",
    assetsDesc: "PostgreSQL asset_nodes",
    endpointsLabel: "Live HTTP Endpoints",
    endpointsDesc: "Verified responsive hosts",
    findingsLabel: "Triaged Findings",
    findingsDesc: "Recorded vulnerability leads",
    runsLabel: "Active Runs & Tasks",
    runsDesc: "Live Hub runs & Go worker tasks",
  },
  graph: {
    title: "Attack Surface Topology & Dual View",
    rootLabel: "Root Target",
    topologyView: "Topology Graph",
    tableView: "Table View",
    searchPlaceholder: "Search assets, titles, or tech...",
    allKinds: "All Kinds",
    showingWindow: "Showing {shown} of {total}",
    expandCluster: "Expand all ({count})",
    collapseCluster: "Collapse ({count})",
    resetView: "Fit View",
    emptyTitle: "No asset nodes indexed yet.",
    emptySub: "Launch a mission from the navbar or verify Go Core connectivity.",
    colKind: "Kind",
    colValue: "Value / Endpoint",
    colStatus: "Status",
    colTitle: "Title / Tech",
    colSeen: "First Seen",
    prevPage: "Previous",
    nextPage: "Next",
    pageOf: "Page {page} of {total}",
    inspectorTitle: "Asset Inspector",
    attributesJson: "Full Attributes JSON",
    openUrl: "Open URL",
    noAttributes: "No structured attributes recorded.",
  },
  findings: {
    title: "Validated Findings & Dossier",
    searchPlaceholder: "Search title, class, or endpoint...",
    sortByCvss: "Sort: CVSS",
    sortByConfidence: "Sort: Confidence",
    downloadJson: "Export JSON",
    downloadMd: "Export Markdown",
    emptyTitle: "No vulnerability findings recorded yet.",
    emptySub: "Verified findings will appear here as workers complete.",
    detailTitle: "Finding Detail & Proof",
    endpointLabel: "Affected Endpoint",
    vulnClassLabel: "Vulnerability Class",
    cvssLabel: "CVSS Score",
    confidenceLabel: "Confidence",
    evidenceLabel: "Evidence & PoC",
    noEvidence: "No textual evidence or PoC payload recorded.",
  },
  approvals: {
    title: "Live Policy Approvals",
    pendingBadge: "Pending",
    historyBadge: "Recent",
    notePlaceholder: "Decision rationale (optional)...",
    approveBtn: "Approve",
    rejectBtn: "Reject",
    deciding: "Applying...",
    emptyPending: "No pending approval requests.",
    offlineNotice: "FastAPI Hub is offline — approvals queue unavailable.",
  },
  console: {
    title: "Live Execution Console & Go Audit Log",
    pauseStream: "Pause Stream",
    resumeStream: "Resume Stream",
    pausedLabel: "Paused",
    clearBtn: "Clear",
    levelAll: "All",
    emptyLogs: "No events recorded in this session yet.",
  },
  copilot: {
    title: "HunterAI Copilot",
    newSession: "New Session",
    deleteSession: "Delete Session",
    modeLabel: "Mode",
    modelLabel: "Model",
    placeholder: "Ask about assets, findings, or security verification...",
    sendBtn: "Send",
    sending: "Streaming...",
    attachBtn: "Attach",
    expandWidth: "Full Width",
    restoreWidth: "Side Panel",
    offlineBanner: "FastAPI Hub is unreachable — Copilot service unavailable.",
    fallbackTag: "Offline Heuristic Fallback (No live LLM)",
    refsTitle: "Referenced Records",
    approvalQueued: "Approval Request Created",
    policyBlocked: "Blocked by PolicyEngine",
    noConversations: "Start a session to query live telemetry concurrently while scans execute.",
    refMissing: "Referenced record is not loaded in the current Go dataset.",
  },
};

const EXTRA_DICT: Record<Lang, NestedDict> = {
  ar: AR_ARTEX,
  en: EN_ARTEX,
};

function lookupNested(obj: unknown, path: string): string | undefined {
  if (!obj || typeof obj !== "object") return undefined;
  const parts = path.split(".");
  let cur: unknown = obj;
  for (const part of parts) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return typeof cur === "string" ? cur : undefined;
}

function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (match, key: string) =>
    Object.prototype.hasOwnProperty.call(vars, key) ? String(vars[key]) : match
  );
}

export function translate(
  lang: Lang,
  key: string,
  fallbackOrVars?: string | Record<string, string | number>,
  maybeVars?: Record<string, string | number>
): string {
  const fallback = typeof fallbackOrVars === "string" ? fallbackOrVars : key;
  const vars = typeof fallbackOrVars === "object" && fallbackOrVars !== null ? fallbackOrVars : maybeVars;

  const catalog = catalogData as Record<Lang, NestedDict>;
  const resolved =
    lookupNested(EXTRA_DICT[lang], key) ??
    lookupNested(catalog[lang], key) ??
    lookupNested(EXTRA_DICT.en, key) ??
    lookupNested(catalog.en, key) ??
    fallback;

  return interpolate(resolved, vars);
}

export function normalizeLang(value: string | null | undefined): Lang | null {
  if (!value) return null;
  const norm = value.trim().toLowerCase();
  if (norm === "ar" || norm === "en") return norm;
  return null;
}

interface I18nContextValue {
  lang: Lang;
  dir: "rtl" | "ltr";
  setLang: (next: Lang) => void;
  toggleLang: () => void;
  t: (
    key: string,
    fallbackOrVars?: string | Record<string, string | number>,
    maybeVars?: Record<string, string | number>
  ) => string;
}

const I18nContext = createContext<I18nContextValue | null>(null);

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>("en");

  const applyDomLang = useCallback((next: Lang) => {
    if (typeof document !== "undefined") {
      document.documentElement.setAttribute("lang", next);
      document.documentElement.setAttribute("dir", next === "ar" ? "rtl" : "ltr");
    }
  }, []);

  useEffect(() => {
    let resolved: Lang = "en";
    try {
      const params = new URLSearchParams(window.location.search);
      const qLang = normalizeLang(params.get("lang"));
      const stored = normalizeLang(window.localStorage.getItem(LANG_STORAGE_KEY));
      if (qLang) {
        resolved = qLang;
        window.localStorage.setItem(LANG_STORAGE_KEY, qLang);
      } else if (stored) {
        resolved = stored;
      }
    } catch {
      resolved = "en";
    }
    setLangState(resolved);
    applyDomLang(resolved);

    const onStorage = (ev: StorageEvent) => {
      if (ev.key === LANG_STORAGE_KEY) {
        const next = normalizeLang(ev.newValue);
        if (next) {
          setLangState(next);
          applyDomLang(next);
        }
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [applyDomLang]);

  const setLang = useCallback(
    (next: Lang) => {
      setLangState(next);
      applyDomLang(next);
      try {
        window.localStorage.setItem(LANG_STORAGE_KEY, next);
        const url = new URL(window.location.href);
        url.searchParams.set("lang", next);
        window.history.replaceState(null, "", url.toString());
      } catch {
        // Ignore storage or history errors in restricted contexts
      }
    },
    [applyDomLang]
  );

  const toggleLang = useCallback(() => {
    setLang(lang === "ar" ? "en" : "ar");
  }, [lang, setLang]);

  const t = useCallback(
    (
      key: string,
      fallbackOrVars?: string | Record<string, string | number>,
      maybeVars?: Record<string, string | number>
    ) => translate(lang, key, fallbackOrVars, maybeVars),
    [lang]
  );

  const value = useMemo<I18nContextValue>(
    () => ({
      lang,
      dir: lang === "ar" ? "rtl" : "ltr",
      setLang,
      toggleLang,
      t,
    }),
    [lang, setLang, toggleLang, t]
  );

  return React.createElement(I18nContext.Provider, { value }, children);
}

export function useI18n(): I18nContextValue {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error("useI18n must be used within I18nProvider");
  }
  return ctx;
}
