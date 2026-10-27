# Live OSV/GHSA Verification

**Date:** 2026-10-27
**Host:** Windows, Python 3.11, no proxy
**Scope:** read-only queries against the public OSV.dev API (`https://api.osv.dev`).
No tool was installed, executed, or pointed at a target.

This file records a **bounded** live check. It is not a claim of complete
coverage: OSV only returns the advisories it has mirrored for the queried
package, and an empty result is not proof that no advisory exists.

---

## 1. What was run

```powershell
python -m core.vuln_intel.cli osv-query `
  --package symfony/http-kernel `
  --ecosystem Packagist `
  --db .tmp_live_osv.sqlite3
```

The CLI issued `POST https://api.osv.dev/v1/query` with:

```json
{"package": {"name": "symfony/http-kernel", "ecosystem": "Packagist"}}
```

**Result:** `source=osv count=8 stored=8`, exit code `0`, 0 errors.

---

## 2. Stored records

| Canonical ID | OSV/GHSA ID | Severity | CWE | Affected ranges |
|---|---|---|---|---|
| CVE-2015-2308 | GHSA-5c58-w9xc-qcj9 | medium | CWE-94 | 6 |
| CVE-2026-45075 | GHSA-6439-2f28-8p8q | high | CWE-863 | 6 |
| CVE-2020-15094 | GHSA-754h-5r27-7x3r | high | CWE-212 | 4 |
| CVE-2022-24894 | GHSA-h7vf-5wrv-9fhv | medium | CWE-285 | 10 |
| CVE-2021-41267 | GHSA-q3j3-w37x-hq2q | medium | CWE-444 | 2 |
| CVE-2019-18887 | GHSA-q8hg-pf8v-cxrv | high | CWE-203 | 8 |
| CVE-2015-4050 | GHSA-qmqw-mpqp-mr54 | medium | CWE-284 | 8 |
| CVE-2014-5245 | GHSA-wvjv-p5rr-mmqm | high | CWE-200 | 6 |

Observations:

- Every record is a GHSA advisory with a CVE alias. The normalizer stored the
  **CVE as the canonical id** and kept the GHSA id as an alias, so the same CVE
  from NVD would update this record instead of duplicating it.
- Severity was computed from the CVSS v3.1 vector shipped by OSV, not copied
  from a free-text label. `CVE-2022-24894` carries
  `CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:L/A:L` → base score 5.3 → `medium`,
  even though the GitHub label is `MODERATE`.
- `CVE-2026-45075` is a 2026 advisory: the data is current, not a static corpus.

---

## 3. Store statistics

```powershell
python -m core.vuln_intel.cli init --db .tmp_live_osv.sqlite3 --json
```

```json
{
  "db": ".tmp_live_osv.sqlite3",
  "schema_version": 1,
  "vulnerabilities": 8,
  "aliases": 19,
  "affected_packages": 50,
  "references": 72,
  "sync_runs": 0
}
```

- File size after the run: **184,320 bytes**
- SHA-256: `1D5809976768EEEAF053F4D5A3F504D4A3D7F12EA9D989A0FFF6D7EE4D7C4A67`

> SQLite may rewrite the file (and its sidecars) when a later command opens the
> database, so the hash identifies this snapshot, not a stable artifact.

`sync_runs = 0` is expected: OSV is query-based and does not use the
date-window `SyncEngine`.

---

## 4. Triage against a real project inventory

Project file:

```json
{
  "project_id": "live-osv-demo",
  "packages": [
    {"name": "symfony/http-kernel", "version": "5.4.0", "ecosystem": "packagist"}
  ],
  "php_version": "8.1.0",
  "inventory_complete": true
}
```

```powershell
python -m core.vuln_intel.cli triage `
  --db .tmp_live_osv.sqlite3 `
  --project .tmp_live_osv_project.json `
  --vuln CVE-2022-24894 --json
```

```json
{
  "vuln_id": "CVE-2022-24894",
  "classification": "CONFIRMED_APPLICABLE",
  "confidence": "CONFIRMED_BY_AUTHORITATIVE_SOURCE",
  "reasons": ["installed version 5.4.0 falls inside the advisory range"],
  "evidence": [
    "project package 'symfony/http-kernel' matched advisory component 'symfony/http-kernel'",
    "advisory fixed version: 5.4.20"
  ],
  "matched_packages": ["symfony/http-kernel@5.4.0"],
  "fixed_versions": ["4.4.50", "5.4.20", "6.0.20", "6.1.12", "6.2.6"]
}
```

The other 7 advisories in this package were `NOT_APPLICABLE` for version
`5.4.0`, because the installed version is at or above the fixed version or
outside the advisory range. That is the triage layer refusing to inflate
findings.

---

## 5. Tool selection (plan only)

```powershell
# authorized, high risk ceiling, nuclei + semgrep assumed installed
python -m core.vuln_intel.cli select-tools `
  --db .tmp_live_osv.sqlite3 --vuln CVE-2022-24894 `
  --project .tmp_live_osv_project.json --authorized --max-risk high `
  --assume-available nuclei --assume-available semgrep --json

# same, but no authorization
python -m core.vuln_intel.cli select-tools `
  --db .tmp_live_osv.sqlite3 --vuln CVE-2022-24894 `
  --project .tmp_live_osv_project.json `
  --assume-available nuclei --assume-available semgrep --json
```

| Scope | Status | Selected | Rejected (first reason) |
|---|---|---|---|
| Authorized, `max-risk=high` | `selected` | `semgrep` (71.0, low), `nuclei` (62.0, high) | `arjun`: availability is `unknown`; not verified as installed |
| Not authorized | `selected` | `semgrep` (71.0, low) only | `dalfox`: active testing requires explicit authorization |

- Class evidence: `CWE-285 → authorization_flaw` (machine-readable CWE).
- `semgrep` is passive/static, so it is selectable without authorization.
- `nuclei` is active, so it disappears the moment authorization is missing.
- **No tool was executed.** The output is a plan; the CLI never spawns a process.

---

## 6. Opt-in automated live test

```powershell
$env:RUN_LIVE_OSV="1"
python -m pytest tests/integration/test_vuln_intel_osv_live.py -q
```

Result: **2 passed** (package query + single-advisory normalization).
The test is skipped by default so the normal suite stays hermetic.

---

## 7. Limits of this verification

- One package (`symfony/http-kernel`) and one ecosystem (`Packagist`). It proves
  the connector, normalizer, alias merge, triage and selection paths work on
  real data; it does **not** prove coverage of all ecosystems.
- OSV results depend on the upstream databases OSV has mirrored. A missing
  advisory is not evidence of absence.
- `GIT` ranges are preserved in metadata but never interpreted as version
  ranges; advisories that only have Git ranges yield no version match.
- CVSS v4 vectors are stored but not scored (the calculator implements v3.x
  base scores only).
- `availability` in the built-in tool catalog is `unknown` by design; the
  `--assume-available` flag was used explicitly for this demonstration and does
  not mean the binaries are installed.
