# HunterAI Vulnerability Intelligence (`core/vuln_intel`)

A small, evidence-first vertical slice for historical vulnerability intelligence.
It is deliberately **read-only**: it does not scan, exploit, or test a target.
Any active action must go through the existing authorization/sandbox layers.

## What it does

- Normalizes advisories into typed records (`VulnerabilityRecord`).
- Stores them in a separate SQLite database with versioned migrations.
- Syncs from NVD 2.0 with rate limiting, retries, date-window splitting,
  per-page checkpoints, and resumable runs.
- Queries OSV.dev on demand for a package/version or a single advisory; OSV also
  exposes GitHub (GHSA) advisories and their CVE aliases.
- Computes CVSS v3.0/v3.1 base scores from vectors instead of trusting labels.
- Measures coverage month by month instead of claiming a complete corpus.
- Classifies the PHP component of an advisory (runtime, extension, framework,
  Composer package, application, server configuration) with evidence.
- Triages an advisory against a project inventory with deterministic version
  comparison and five applicability levels.
- Selects tools deterministically for an advisory, inside an explicit
  authorization/risk scope. **Selection is a plan; nothing is executed.**
- Exports JSON/CSV and exposes a CLI.

## Quick start

```bash
# Create/migrate the database (no network)
python -m core.vuln_intel.cli init

# List source metadata and limitations
python -m core.vuln_intel.cli sources

# Sync a bounded historical window (network; NVD rate limits apply)
python -m core.vuln_intel.cli sync --start 2024-01-01 --end 2024-01-31

# Measure what is actually stored
python -m core.vuln_intel.cli coverage --start 2024-01-01 --end 2024-01-31

# Search and inspect
python -m core.vuln_intel.cli search --cwe CWE-79 --limit 20
python -m core.vuln_intel.cli show --id CVE-2024-1234

# PHP classification
python -m core.vuln_intel.cli classify-php --id CVE-2024-1234

# Project-aware triage
python -m core.vuln_intel.cli triage --project project.json --all

# OSV.dev / GHSA (query-based; network)
python -m core.vuln_intel.cli osv-query --package symfony/http-kernel --ecosystem Packagist
python -m core.vuln_intel.cli osv-get --id GHSA-h7vf-5wrv-9fhv

# Tool selection (a plan; never executes anything)
python -m core.vuln_intel.cli select-tools --vuln CVE-2022-24894 --authorized --max-risk high
```

A project inventory is a JSON object:

```json
{
  "project_id": "shop",
  "name": "Example shop",
  "ecosystem": "composer",
  "php_version": "8.1.10",
  "inventory_complete": true,
  "packages": [
    {"name": "laravel/framework", "version": "10.1.0", "ecosystem": "composer"},
    {"name": "monolog/monolog", "version": "3.0.0", "ecosystem": "composer"}
  ]
}
```

## Applicability levels

| Level | Meaning |
|---|---|
| `CONFIRMED_APPLICABLE` | The installed version falls inside a machine-readable advisory range. |
| `LIKELY_APPLICABLE` | The installed version matches an exact CPE version; configuration may differ. |
| `POSSIBLY_APPLICABLE` | The component matches but the installed version is unknown. |
| `NOT_APPLICABLE` | The installed version is outside the range, at/above the fixed version, or no package matches a complete inventory. |
| `INSUFFICIENT_EVIDENCE` | The advisory or inventory lacks the data needed to decide. Never treated as confirmed. |

A fixed version at or below the installed version yields `NOT_APPLICABLE`.
An empty or incomplete inventory never produces a confident negative.

## PHP classification

The classifier does not treat the word "PHP" as evidence of a vulnerability.
It labels a component only when it finds:

- structured evidence (CPE vendor/product, Composer package, ecosystem), or
- a concrete text signal (an explicit extension phrase such as "the exif
  extension", a framework name, an application context) together with a PHP
  context.

A bare extension word such as `xml` is not enough. A WordPress plugin is a
package, not the WordPress framework. Adobe products other than Commerce are
not mapped to Adobe Commerce.

## Coverage honesty

`coverage` counts records actually present in the database for the requested
months. It reports:

- requested vs. covered months and every missing month,
- the first and last measured month,
- per-year totals,
- source limitations (NVD rate limits, pre-2002 sparsity, current-year work in
  progress).

`complete` is `false` unless the caller supplies a source-provided denominator
and every month is covered and the counts match. A range that includes the
current year is always `complete=false`.

The default test suite is hermetic. A **bounded** live NVD check was performed
manually on 2026-10-26: one day (2024-01-15), 68 records, 0 errors. It is not a
2000–2026 backfill and does not support a completeness claim. Full details and
the exact commands are in [`LIVE_NVD_VERIFICATION.md`](../../LIVE_NVD_VERIFICATION.md).

A bounded live OSV check was performed on 2026-10-27: `symfony/http-kernel`
(Packagist) → 8 advisories stored, 0 errors, GHSA→CVE alias merge verified.
Details: [`LIVE_OSV_VERIFICATION.md`](../../LIVE_OSV_VERIFICATION.md).

The automated live tests are opt-in:

```powershell
$env:RUN_LIVE_NVD = "1"
python -m pytest tests/integration/test_vuln_intel_nvd_live.py -q

$env:RUN_LIVE_OSV = "1"
python -m pytest tests/integration/test_vuln_intel_osv_live.py -q
```

## Tool selection (P6)

`select-tools` answers: *given this advisory, this project, and this
authorization scope, which tools may test it?*

- Vulnerability class comes from CWEs (primary) plus explicit advisory phrases
  (supporting). A bare word is never enough. No class evidence →
  `insufficient_evidence`, nothing selected.
- Active tools are rejected unless `--authorized` is passed.
- Risk above `--max-risk` is rejected.
- A tool whose availability is `unknown` is rejected unless the caller relaxes
  it (`--allow-unavailable`) or marks it for this run (`--assume-available`).
- Ecosystem and input-type mismatches are rejected.
- `NOT_APPLICABLE` triage results block selection entirely.
- Every decision has a reason; ordering is deterministic (`score`, then
  `tool_id`).
- The built-in catalog ships **every** tool as `availability=unknown` and
  `last_validated=None`: this repository does not verify installed binaries.
- No tool is installed or executed by this package. A test monkeypatches
  `subprocess` to prove the selection path never spawns a process.

## Safety properties

- All SQL uses bound parameters; advisory text is never interpolated into SQL.
- Advisory text is data: it is never executed or interpreted as an instruction.
- HTTP responses are size-capped; redirects to hosts outside the source
  allowlist are rejected; TLS verification is never disabled.
- NVD API keys are sent as a request header and are not logged.
- The package performs no active testing and does not bypass authorization.
- Raw payload storage is opt-in (`--store-raw` or `VulnerabilityStore(..., store_raw=True)`).

## Data model

- `vulnerabilities`: one normalized record per canonical identifier.
- `vulnerability_aliases`: CVE/GHSA/OSV identifiers pointing to a record.
- `affected_packages`: CPE/Composer ranges, versions, and fixed versions.
- `vulnerability_cwes`, `vulnerability_references`: child tables.
- `sync_runs`, `sync_checkpoints`, `sync_errors`: resumability and audit.
- `raw_records`: optional raw payloads, content-addressed by SHA-256.

The store is separate from the engagement knowledge DB and the legacy JSON CVE
cache. It does not claim that the legacy cache is a historical corpus.

## Tests

```bash
python -m pytest tests/vuln_intel -q
# 214 passed
```

The suite covers models, version comparison, store idempotency and SQL-injection
safety, NVD normalization/pagination, resumable sync, coverage gaps, PHP
classification, triage boundaries, CLI JSON contracts, prompt-injection
handling, HTTP retry/redirect/size limits, OSV/GHSA normalization and alias
merging, CVSS v3 scoring, vulnerability-class extraction, deterministic tool
selection and its authorization/risk/availability gates, plus opt-in live NVD
and OSV smoke tests.

## Known limitations

- NVD 2.0 and OSV.dev are implemented. Vendor advisories (PHP.net, Laravel,
  Symfony, Packagist) and exploit intelligence are not yet connected; GHSA is
  reachable through OSV, but a direct GitHub GraphQL connector is future work.
- OSV is query-based and has no date-range pagination; it is not part of
  `SyncEngine`, and an empty OSV result is not proof that no advisory exists.
- CVSS v4 vectors are stored but not scored (only v3.x base scores are computed).
- The version comparator is not a full Composer/npm semver implementation; it
  handles numeric cores and common suffixes and returns "unknown" rather than
  guessing.
- NVD's CPE data is not a complete package inventory. A CPE match is a lead, not
  proof that a specific deployment is vulnerable.
- Coverage measures stored records, not the universe of all vulnerabilities.
- Tool selection only plans; it does not verify a tool is installed and does not
  execute it. The built-in capability catalog is a curated starting point, not a
  guarantee of tool behavior.
- The CLI is intentionally small; it is not a replacement for the existing
  orchestrator or reporting pipeline.
