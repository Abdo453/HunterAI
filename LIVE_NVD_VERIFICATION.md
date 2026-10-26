# Live NVD verification — 2026-10-26

This is a **bounded manual verification**, not a claim of historical
completeness. It proves that the NVD connector, normalizer, SQLite store,
coverage report, PHP classifier, and triage path work together against the real
NVD 2.0 API.

## Environment

- Repository: `E:\Agant\PentestAI-Unified`
- Python: 3.11.9 (Windows)
- Test database: `.tmp_live_nvd.sqlite3` (local, not committed)
- Database SHA-256 immediately after sync: `3AA549E97D7E294C1865496C8BE666FDCDB050C48624FDBE060AA330305A4CF4`
- Database size after sync: 397,312 bytes
- Note: SQLite may rewrite the file when it checkpoints WAL on a later open, so the file hash is not a stable artifact. The sync/coverage reports below are the stable evidence.
- NVD source: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- No NVD API key was used (anonymous rate limit).

## 1. Sync one historical day

```powershell
python -m core.vuln_intel.cli sync `
  --db .tmp_live_nvd.sqlite3 `
  --start 2024-01-15 --end 2024-01-15 `
  --page-size 2000 --json
```

Observed result:

```json
{
  "run_id": "0367f9cb85584a289d3ccd740783991a",
  "source_id": "nvd",
  "status": "completed",
  "pages_fetched": 1,
  "records_retrieved": 68,
  "inserted": 68,
  "updated": 0,
  "unchanged": 0,
  "duplicates": 0,
  "rejected": 0,
  "errors": 0,
  "coverage_by_year": {"2024": 68},
  "missing_intervals": []
}
```

## 2. Measured coverage

```powershell
python -m core.vuln_intel.cli coverage `
  --db .tmp_live_nvd.sqlite3 `
  --start 2024-01-01 --end 2024-01-31 --json
```

Observed result:

```json
{
  "source_id": "nvd",
  "records_total": 68,
  "months_requested": 1,
  "months_covered": 1,
  "missing_months": [],
  "by_year": {"2024": 68},
  "complete": false,
  "notes": [
    "No denominator was supplied, so completeness cannot be asserted. Use a source-provided total for a closed range to measure completeness."
  ]
}
```

`complete=false` is intentional. The run measured one day, not the whole
2000–2026 history.

## 3. Search, PHP classification, and triage

A search for `PHP` (limit 5) returned five stored records, including:

- `CVE-2023-6049` — Estatik Real Estate WordPress plugin, PHP Object Injection
  (`CWE-502`), affected before `4.1.1`.
- `CVE-2024-0558` — DedeBIZ `/admin/makehtml_freelist_action.php`, SQL injection
  (`CWE-89`).

PHP classification:

```json
// CVE-2023-6049
{
  "involves_php": true,
  "component_type": "package",
  "component_names": ["wordpress plugin/module"],
  "confidence": "PROVISIONAL",
  "evidence": ["framework name with plugin/theme/module context in advisory text"]
}
```

```json
// CVE-2024-0558
{
  "involves_php": true,
  "component_type": "application",
  "component_names": ["PHP application"],
  "confidence": "PROVISIONAL",
  "evidence": ["web-application CWE with PHP context: CWE-89"]
}
```

Project inventory used for triage:

```json
{
  "project_id": "live-demo",
  "php_version": "8.1.10",
  "inventory_complete": true,
  "packages": [{"name": "estatik", "version": "4.0.0"}]
}
```

Triage results:

```json
[
  {
    "vuln_id": "CVE-2023-6049",
    "classification": "CONFIRMED_APPLICABLE",
    "confidence": "CONFIRMED_BY_AUTHORITATIVE_SOURCE",
    "matched_packages": ["estatik@4.0.0"],
    "reasons": ["installed version 4.0.0 falls inside the advisory range"]
  },
  {
    "vuln_id": "CVE-2024-0558",
    "classification": "NOT_APPLICABLE",
    "confidence": "STRONGLY_SUPPORTED",
    "matched_packages": [],
    "reasons": ["no project package matches the advisory's affected components"]
  }
]
```

The second result is a **negative against a declared complete inventory**, not a
claim that the target is safe in general.

## Limits of this proof

- One NVD day (2024-01-15) only: 68 records. It is not the 2000–2026 corpus.
- No OSV, GHSA, vendor advisory, exploit-feed, or CISA KEV sync was performed.
- NVD's CPE data is a lead, not proof of a specific deployment's configuration.
- The temporary database is local evidence and is not part of the commit; NVD
  terms apply to any redistribution.
- The default test suite remains hermetic. The live NVD test is opt-in with
  `RUN_LIVE_NVD=1`.
