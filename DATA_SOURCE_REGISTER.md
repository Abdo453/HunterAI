# HunterAI — Data Source Register

**Date:** 2026-10-26
**Purpose:** record every vulnerability-intelligence source HunterAI may use, its access method, constraints, expected historical coverage, licensing status, and connector status.

> **Honesty rule:** this register records what is *known or expected* before implementation. License/terms and rate limits must be re-verified against the source's current documentation before a connector is enabled in production. No source is claimed to provide complete 2000–2026 coverage.

---

## 1. Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Connector implemented and tested (mocked) |
| 🟡 | Connector implemented, limited scope |
| ⬜ | Planned, not implemented |
| 🔒 | Requires credentials/approval |
| ⚠️ | Terms/robots/coverage need verification before use |

---

## 2. Source matrix

| ID | Source | Authority | Primary endpoint / method | Format | Auth | Documented rate limit | Expected historical depth | Update cadence | License / terms (verify) | Raw storage | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| SRC-NVD | NIST National Vulnerability Database | U.S. NIST; authoritative CVE enrichment | `https://services.nvd.nist.gov/rest/json/cves/2.0` | JSON | Optional `apiKey` | 5 req/30s anonymous; 50 req/30s keyed (per NVD docs) | Mostly 2002→present; sparse earlier | Continuous | NVD site terms; CVE content may carry MITRE terms ⚠️ | Normalized + hash by default; raw only if permitted | 🟡 (this increment) |
| SRC-CVE | CVE Program (MITRE) | Authoritative CVE IDs/descriptions | `https://cveawg.mitre.org/api/` (CVE Services) | JSON | Optional/reserved | Per CVE Services policy ⚠️ | 1999→present | Continuous | CVE Terms of Use ⚠️ | Normalized + provenance | ⬜ |
| SRC-GHSA | GitHub Security Advisories | Curated advisory DB + ecosystem mappings | GraphQL `securityAdvisories`; repo `github/advisory-database` | JSON/GraphQL | `GITHUB_TOKEN` recommended | GitHub API limits (higher authenticated) | ~2017→present (varies) | Continuous | Advisory DB license (commonly CC BY 4.0) ⚠️ verify | Normalized + provenance | ⬜ |
| SRC-OSV | OSV.dev | Aggregates ecosystem advisories (PyPI, npm, Go, Maven, crates, Composer, etc.) | `https://api.osv.dev/v1/query`, `https://api.osv.dev/v1/vulns/{id}`, GCS export | JSON | None | Public API; be polite ⚠️ | Ecosystem-dependent; many 2017→present, some older | Continuous | Per-record source licenses vary; OSV project Apache-2.0 ⚠️ | Normalized; raw per source license | ⬜ |
| SRC-PHP | PHP.net security & release notes | Official PHP runtime/extension advisories | `https://www.php.net/security/`, release changelogs, PHP releases API/feeds where available | HTML/JSON/RSS | None | Respect robots/terms; low frequency | PHP 4/5/7/8 era → present, but not every issue has an advisory | Per release | PHP.net terms ⚠️ | Normalized + link; avoid full-page scraping if feed exists | ⬜ |
| SRC-COMPOSER | Composer / Packagist security advisories | Composer ecosystem | `https://packagist.org/api/security-advisories/`, `composer audit` | JSON | None | Public API; polite | Package-dependent, mostly recent | Continuous | Packagist terms ⚠️ | Normalized | ⬜ |
| SRC-LARAVEL | Laravel security releases/advisories | Framework maintainer | Laravel release notes, GitHub advisories, Laravel security page | HTML/JSON | None | Low frequency | Laravel 4→present (varies) | Per release | Laravel terms / repo license ⚠️ | Normalized + link | ⬜ |
| SRC-SYMFONY | Symfony security advisories | Framework maintainer | `https://symfony.com/security`, CVE reports, GitHub advisories | HTML/JSON | None | Low frequency | Symfony 2→present (varies) | Per release | Symfony terms ⚠️ | Normalized + link | ⬜ |
| SRC-WORDPRESS | WordPress security releases | CMS maintainer | `https://wordpress.org/news/category/security/`, core/plugin/theme APIs | HTML/JSON | None | Low frequency | WordPress 1.x→present (varies) | Per release | WordPress terms ⚠️ | Normalized + link | ⬜ |
| SRC-DRUPAL | Drupal security advisories | CMS maintainer | `https://www.drupal.org/security`, advisory RSS/JSON | HTML/RSS | None | Low frequency | Drupal 6→present (varies) | Per release | Drupal terms ⚠️ | Normalized + link | ⬜ |
| SRC-MAGENTO | Adobe Commerce / Magento security bulletins | Vendor | Adobe Security Bulletin (APSB) pages, Adobe advisory API if available | HTML/JSON | None | Low frequency | Magento 1/2, Commerce → present | Monthly/quarterly | Adobe terms ⚠️ | Normalized + link | ⬜ |
| SRC-CISA-KEV | CISA Known Exploited Vulnerabilities | U.S. CISA | `https://www.cisa.gov/known-exploited-vulnerabilities-catalog` (JSON/CSV) | JSON/CSV | None | Public download | 2021→present (catalog creation) | Continuous | CISA terms ⚠️ | Normalized + provenance | ⬜ |
| SRC-CERTCC | CERT/CC Vulnerability Notes | Carnegie Mellon CERT/CC | `https://www.kb.cert.org/vuls/` | HTML/JSON | None | Respect robots ⚠️ | 1990s→present (varies) | Continuous | CERT/CC terms ⚠️ | Normalized + link | ⬜ |
| SRC-OWASP | OWASP documentation | Community guidance | `https://owasp.org/` (WSTG, Top 10, Cheat Sheets) | HTML/Markdown | None | Low frequency | Guidance, not CVE records | Periodic | OWASP content licenses (often CC BY-SA) ⚠️ | Store references, not bulk content | ⬜ |
| SRC-EXPLOITDB | Exploit-DB | Offensive Security | `https://www.exploit-db.com/` | HTML/CSV | None | **Do not scrape without permission** ⚠️ | 1999→present (varies) | Continuous | Exploit-DB terms ⚠️ | Do not store PoC; reference only | ⬜ |
| SRC-VENDOR | Vendor security bulletins (generic) | Vendors | Per-vendor pages/APIs | Varies | Varies | Per vendor | Varies | Varies | Per vendor ⚠️ | Reference + normalized | ⬜ |

**Notes**

- "Expected historical depth" is an expectation, not a measured fact. It must be verified by the connector's coverage report.
- A source may contain records outside its nominal range (e.g., NVD enrichment of older CVEs). Coverage is measured per source and per year.
- "Raw storage" defaults to **not storing full payloads** unless the source's terms clearly permit it. Normalized records, URLs, and hashes are always stored.

---

## 3. Per-source details

### 3.1 NVD (SRC-NVD) — first connector

**Why first:** authoritative, structured JSON, date-filterable, widely used, and directly satisfies the "at least one authoritative source can be synchronized" criterion.

**Endpoint**

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
  ?pubStartDate=2000-01-01T00:00:00.000Z
  &pubEndDate=2000-01-31T23:59:59.999Z
  &startIndex=0
  &resultsPerPage=2000
```

**Constraints**

- `resultsPerPage` maximum 2000.
- Date range maximum 120 days per request (NVD documentation); the sync engine must chunk ranges.
- Anonymous rate limit 5 requests / 30 seconds; API key 50 / 30 seconds.
- `startIndex + resultsPerPage` pagination; `totalResults` is authoritative for the window.
- Use `lastModStartDate` / `lastModEndDate` for incremental updates (separate from publication date).
- A record can be `rejected` or `withdrawn`; preserve the status.

**Normalization notes**

- Prefer English description; preserve original language variants as references if needed.
- CVSS preference: v4.0 > v3.1 > v3.0 > v2.0; store the chosen version and vector.
- CWE: collect all `weaknesses[].description[].value` where `lang == en`.
- Affected packages: parse `configurations[].nodes[].cpeMatch[]`; extract `criteria` (CPE 2.3), `vulnerable`, `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`. Do not invent ranges absent from the data.
- References: URL + tags; mark advisory/patch/exploit carefully (tags come from NVD, not inference).
- `published` and `lastModified` are source timestamps; `imported_at` is ours.

**Coverage caveats**

- NVD's coverage of pre-2002 CVEs is sparse; the CVE Program itself began in 1999.
- Enrichment (CVSS/CPE) may lag publication; `lastModified` changes are expected.
- 2026 is in progress; the dataset is never "complete" for the current year.

**Status:** implemented in this increment with mocked tests. A bounded live verification was performed on 2026-10-26 (2024-01-15, 68 records, 0 errors); see `LIVE_NVD_VERIFICATION.md`. The automated live test is opt-in (`RUN_LIVE_NVD=1`) and skipped by default.

---

### 3.2 CVE Program (SRC-CVE)

- Authoritative CVE IDs and descriptions, including records not yet enriched by NVD.
- CVE Services API requires adherence to its terms and may require a reserved account for writes (we only read).
- Useful for alias validation and for records missing from NVD.
- **Status:** planned. Do not scrape `cve.org` HTML.

---

### 3.3 GitHub Security Advisories (SRC-GHSA)

- GraphQL `securityAdvisories` supports ecosystem/severity/date filters and `identifier` lookup.
- The `github/advisory-database` repository provides OSV-format JSON; cloning is heavy and must be rate-limited.
- `GITHUB_TOKEN` is optional but strongly recommended; use the narrowest read-only scope.
- **Status:** planned. No write operations.

---

### 3.4 OSV.dev (SRC-OSV)

- `POST https://api.osv.dev/v1/query` with `{package: {name, ecosystem}, version}` or `{commit}`.
- `GET https://api.osv.dev/v1/vulns/{id}` for a single record.
- Bulk export via GCS (`gs://osv-vulnerabilities/...`) is available but requires `gsutil`/GCS access; do not assume it in CI.
- OSV aggregates sources with different licenses; preserve per-record source and license metadata.
- **Status:** planned. First use case: Composer/PHP package advisories and project triage.

---

### 3.5 PHP.net (SRC-PHP)

- PHP security page lists releases with security fixes; release notes/changelogs contain details.
- Prefer official feeds/APIs if available; avoid brittle HTML scraping. If scraping is necessary, respect robots and cache aggressively.
- Not every PHP bug has a CVE; distinguish "security release note" from "CVE advisory".
- Supported-version information is essential for triage (EOL versions are not "fixed").
- **Status:** planned. Requires a parser with fixtures and a clear "no advisory ≠ not vulnerable" caveat.

---

### 3.6 Composer / Packagist (SRC-COMPOSER)

- `composer audit` uses Packagist's security advisories API; we can call the API directly or parse `composer audit --format=json` when Composer is available.
- Advisories include affected package names, version constraints, CVE/GHSA IDs, and links.
- Composer version constraints (`^`, `~`, `||`, stability flags) must be evaluated with a Composer-aware comparator, not plain `packaging.version`.
- **Status:** planned. Do not auto-install Composer; detect and report availability.

---

### 3.7 Frameworks and CMS (SRC-LARAVEL, SRC-SYMFONY, SRC-WORDPRESS, SRC-DRUPAL, SRC-MAGENTO)

- Prefer maintainer advisory pages/feeds and GitHub advisories.
- Map package names: `laravel/framework`, `symfony/*`, `wordpress/wordpress` (core), `drupal/core`, `magento/*`.
- WordPress plugins/themes require the WordPress.org API and a separate namespace; do not confuse core with plugins.
- Adobe Commerce bulletins often bundle multiple CVEs; preserve the bulletin ID and per-CVE mapping.
- **Status:** planned. Each needs fixtures; no generic HTML scraper.

---

### 3.8 CISA KEV (SRC-CISA-KEV)

- Adds "known exploited" status; do not infer exploitation from a CVE's existence.
- The catalog starts in 2021; it is not a historical exploitation record for 2000–2020.
- **Status:** planned. High value for prioritization.

---

### 3.9 CERT/CC (SRC-CERTCC)

- Vulnerability notes with vendor coordination; useful for older and multi-vendor issues.
- HTML/JSON access varies; respect terms.
- **Status:** planned.

---

### 3.10 OWASP (SRC-OWASP)

- Guidance (WSTG, Top 10, Cheat Sheets), not a CVE feed.
- Use for CWE/OWASP mapping and remediation guidance, with attribution.
- **Status:** planned. Store references/snippets only as permitted.

---

### 3.11 Exploit-DB (SRC-EXPLOITDB)

- **Do not scrape or bulk-download without permission.**
- Reference only; never auto-download or execute PoCs.
- A public exploit is not authorization and not proof of applicability.
- **Status:** not planned for automation. Manual reference only.

---

## 4. Source priority and corroboration

| Field | Preferred source | Fallback | Rule |
|---|---|---|---|
| CVE ID/description | CVE Program | NVD | Preserve both; NVD description may be enriched |
| CVSS | NVD (v4/v3.1/v3.0/v2) | Vendor/GHSA | Never compute a score ourselves |
| CWE | NVD | Vendor/GHSA | Keep all; do not pick one silently |
| Affected versions | OSV / vendor / GHSA | NVD CPE | Prefer machine-readable ranges; CPE is not semver |
| Fixed version | Vendor / OSV | NVD CPE | Only if explicitly stated |
| Known exploited | CISA KEV | Vendor | Absence ≠ not exploited |
| PHP runtime | PHP.net | NVD | Distinguish runtime vs extension |
| Composer packages | Packagist/OSV | GHSA | Composer constraint semantics |
| Framework | Maintainer/GHSA | NVD | Map package names carefully |

**Corroboration:** a claim is `CONFIRMED_BY_AUTHORITATIVE_SOURCE` only when an authoritative source states it. Multiple secondary sources may yield `STRONGLY_SUPPORTED`. A single unverified source is `PROVISIONAL`.

---

## 5. Coverage expectations (honest)

| Period | Expectation | Caveat |
|---|---|---|
| 1999–2001 | Sparse CVE records | CVE Program early years; NVD enrichment limited |
| 2002–2010 | Moderate | NVD coverage improves; CPE/CVSS may be retrofitted |
| 2011–2019 | Good for NVD | Some vendors publish only on their own sites |
| 2020–2025 | Good, but volume is high | Enrichment lag; rejected/withdrawn records |
| 2026 | **In progress** | Never claim complete; continuous updates |

**Measurement:** the coverage report computes, per source and per month, whether at least one record exists and how many. It also reports the requested range, the measured range, gaps, and source limitations. `complete=true` is only possible when a defined denominator (e.g., a source-provided total count for a closed date range) is fully accounted for. For open-ended/current data, `complete=false` always.

---

## 6. Licensing and storage policy (defaults)

| Source | Default raw storage | Rationale |
|---|---|---|
| NVD | Hash + normalized; raw only if terms permit | Avoid redistributing restricted content |
| CVE Program | Hash + normalized + link | Terms of Use |
| GHSA | Hash + normalized + link; raw if CC BY 4.0 confirmed | Attribution required |
| OSV | Normalized + per-record license metadata | Aggregated licenses vary |
| PHP.net | Link + normalized facts; no full-page copies | Terms/robots |
| Packagist | Normalized + link | Terms |
| Vendor bulletins | Link + normalized facts | Vendor terms |
| CISA KEV | Normalized + link (public dataset) | Government publication |
| CERT/CC | Link + normalized facts | Terms |
| OWASP | Reference/snippet with attribution | CC BY-SA likely |
| Exploit-DB | Reference only, no PoC storage | Terms + safety |

**Retention (default):** raw snapshots 90 days; sync reports 2 years; normalized records indefinite (until superseded); AI analyses tied to source version.

---

## 7. Connector requirements checklist

Every connector must implement:

- [ ] `SourceMetadata` with id, name, base URL, license/terms URL, rate limit, historical depth note.
- [ ] Request validation (date range, page size, package/ecosystem).
- [ ] Rate limiting (per source, configurable, jitter).
- [ ] Retry with exponential backoff; honor `Retry-After`; cap attempts.
- [ ] Pagination (cursor/token/startIndex).
- [ ] Incremental sync (last-modified or checkpoint window).
- [ ] Response validation (shape, required fields, size cap).
- [ ] Timestamp normalization to UTC; preserve original strings.
- [ ] Error classification and reporting.
- [ ] Provenance (URL, retrieved_at, raw hash).
- [ ] Dedupe (source ID + aliases + content hash).
- [ ] Checkpoint persistence.
- [ ] License/usage check before enabling.
- [ ] Fixtures + mocked tests; opt-in live test.
- [ ] Documentation of unsupported fields and gaps.

---

## 8. Explicit non-goals

- No authentication bypass, paywall circumvention, or anti-abuse evasion.
- No aggressive polling.
- No scraping where an API/feed exists.
- No bulk download of PoCs.
- No claim of complete historical coverage without a measured denominator.
- No use of a source whose terms prohibit automated access.

---

## 9. Verification log

| Date | Source | Action | Result | Artifact |
|---|---|---|---|---|
| 2026-10-26 | — | Register created | No live source contacted | this file |
| 2026-10-26 | NVD | Connector implemented + mocked tests | 134 new hermetic tests green | `tests/vuln_intel/` |
| 2026-10-26 | NVD | Live probe (`RUN_LIVE_NVD=1`) | 1 passed; real NVD 2.0 response normalized | `tests/integration/test_vuln_intel_nvd_live.py` |
| 2026-10-26 | NVD | Manual bounded sync | 2024-01-15: 1 page, 68 retrieved/inserted, 0 errors; coverage `complete=false` | `LIVE_NVD_VERIFICATION.md` |

> When a live sync is performed, append the exact command, HTTP status, record count, date range, and elapsed time. Do not write "success" without these details.
