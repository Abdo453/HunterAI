export type TargetPresetCategory = "public_demo" | "local_lab";

export interface TargetPreset {
  id: string;
  label: string;
  target: string;
  inScope: string[];
  category: TargetPresetCategory;
  descriptionEn: string;
  descriptionAr: string;
  tags: string[];
}

/**
 * Shared authorized practice targets and local pentest lab presets.
 * Used across Navbar autocomplete/popover, Overview Mission Launcher, and Operations Targets.
 */
export const TARGET_PRESETS: TargetPreset[] = [
  {
    id: "testphp-vulnweb",
    label: "Acunetix TestPHP",
    target: "http://testphp.vulnweb.com",
    inScope: ["testphp.vulnweb.com"],
    category: "public_demo",
    descriptionEn: "SQLi, XSS, and LFI classic web vulnerability demo",
    descriptionAr: "تطبيق تجريبي كلاسيكي لثغرات SQLi و XSS و LFI",
    tags: ["SQLi", "XSS", "LFI"],
  },
  {
    id: "testhtml5-vulnweb",
    label: "Acunetix TestHTML5",
    target: "http://testhtml5.vulnweb.com",
    inScope: ["testhtml5.vulnweb.com"],
    category: "public_demo",
    descriptionEn: "SPA, DOM XSS, and REST API practice demo",
    descriptionAr: "تطبيق SPA لاختبار DOM XSS وواجهات REST",
    tags: ["SPA", "DOM XSS", "REST"],
  },
  {
    id: "owasp-juice-shop-online",
    label: "OWASP Juice Shop Online",
    target: "https://juice-shop.herokuapp.com",
    inScope: ["juice-shop.herokuapp.com"],
    category: "public_demo",
    descriptionEn: "OWASP Top 10 modern web security training shop",
    descriptionAr: "متجر OWASP Top 10 التدريبي الحديث على السحابة",
    tags: ["OWASP Top 10", "API", "Auth"],
  },
  {
    id: "altoro-mutual",
    label: "Altoro Mutual",
    target: "https://demo.testfire.net",
    inScope: ["demo.testfire.net"],
    category: "public_demo",
    descriptionEn: "Auth and business-logic demo banking target",
    descriptionAr: "تطبيق بنكي تجريبي لاختبار المصادقة ومنطق الأعمال",
    tags: ["Auth", "Logic", "Banking"],
  },
  {
    id: "iana-example",
    label: "Example.com Baseline",
    target: "https://example.com",
    inScope: ["example.com"],
    category: "public_demo",
    descriptionEn: "IANA safe connectivity and HTTP header baseline",
    descriptionAr: "نطاق IANA الآمن لاختبار الاتصال وترويسات HTTP",
    tags: ["Baseline", "Headers", "TLS"],
  },
  {
    id: "local-juice-shop",
    label: "Local Juice Shop (:3001)",
    target: "http://127.0.0.1:3001",
    inScope: ["127.0.0.1", "127.0.0.1:3001"],
    category: "local_lab",
    descriptionEn: "Local OWASP Juice Shop container on :3001",
    descriptionAr: "مختبر OWASP Juice Shop المحلي على المنفذ 3001",
    tags: ["Local", "OWASP", ":3001"],
  },
  {
    id: "local-dvwa-burp",
    label: "Local DVWA / Burp Lab (:8080)",
    target: "http://127.0.0.1:8080",
    inScope: ["127.0.0.1", "127.0.0.1:8080"],
    category: "local_lab",
    descriptionEn: "Local DVWA or Burp practice lab on :8080",
    descriptionAr: "مختبر DVWA أو Burp المحلي على المنفذ 8080",
    tags: ["Local", "DVWA", ":8080"],
  },
  {
    id: "local-webgoat",
    label: "Local WebGoat / Docker (:8081)",
    target: "http://localhost:8081",
    inScope: ["localhost", "localhost:8081"],
    category: "local_lab",
    descriptionEn: "Local WebGoat / Docker sandbox on :8081",
    descriptionAr: "بيئة WebGoat / Docker المحلية على المنفذ 8081",
    tags: ["Local", "Docker", ":8081"],
  },
];

export function findPresetById(id: string): TargetPreset | undefined {
  return TARGET_PRESETS.find((preset) => preset.id === id);
}

export function getPresetDescription(preset: TargetPreset, lang: "ar" | "en"): string {
  return lang === "ar" ? preset.descriptionAr : preset.descriptionEn;
}

export function getPresetCategoryBadgeClasses(category: TargetPresetCategory): string {
  return category === "public_demo"
    ? "border-sentinel-primary/35 bg-sentinel-primary/15 text-sentinel-primary"
    : "border-sentinel-warning/35 bg-sentinel-warning/15 text-sentinel-warning";
}
