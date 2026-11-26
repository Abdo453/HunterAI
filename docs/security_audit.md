# HunterAI Security Audit & Hardening Verification Log

This document records verified security audit findings and remediation status across the HunterAI service plane (`hunter_backend/`, `core/platform_store.py`, `core/burp_gateway/`, `backend/`, `bughunter/`, and `opencode.json`).

---

## 1. Reconciled Audit Status (Verified Controls)

Prior documentation included unverified external certification claims and overstated pre-hardening verdicts for unimplemented or unhardened subsystems. Those overstated claims have been removed; the table below reflects only source-verified and test-verified controls.

| Surface | Remediation Implemented | Verification Suite |
| :--- | :--- | :--- |
| **Django Control Plane Auth** (`hunter_backend/auth.py`, `middleware.py`) | CSPRNG local bearer token (`HUNTER_API_TOKEN` / `.api_token` `0o600`), PBKDF2-SHA512 domain-separated KDF, `sgn` session revocation, `userTier` vs `tokenTier` enforcement, `LoginGuard` rate-limiting, `TRUSTED_PROXIES` IP extraction. | `tests/security/test_p1_service_hardening.py` |
| **CSRF, Origin, WS & CSP** (`hunter_backend/middleware.py`, `websocket.py`, `settings.py`) | Closed JSON POST CSRF bypass (valid bearer OR trusted `Origin` + double-submit `X-CSRFToken`), fail-closed `is_ws_origin_allowed(None)` without bearer auth, removed `'unsafe-inline'` and `'unsafe-eval'` from `CSP_POLICY`. | `tests/security/test_p1_service_hardening.py`, `tests/test_security_boundaries_django.py` |
| **HTTP Editor Write Containment** (`hunter_backend/apps/intelligence_api.py`) | Removed `core`, `scripts`, `tools`, `agents`, `bughunter` from `EDITOR_ALLOWED_ROOTS`; restricted strictly to `skills`, `data/reports`, `scratch` via `is_relative_to`. | `tests/security/test_p1_service_hardening.py` |
| **Subprocess Allowlist & Repeater Proxy** (`hunter_backend/apps/common.py`, `arsenal_api.py`) | Enforced strict security-tool binary allowlist (blocking `python`, `python3`, `node`, `sh`, `bash`, `cmd`, `powershell`, `pwsh`, `curl`, `wget`) and metacharacter filtering on `str` and `list` commands; fixed unawaited `SandboxRunView.post`; blocked internal/metadata/non-HTTP(S) proxies in `burp_repeater_send_view`. | `tests/security/test_p1_service_hardening.py` |
| **Chat Auto-Exec & Settings** (`hunter_backend/apps/copilot_api.py`) | Defaulted `allow_exec=False`, `authorized=False`; routed eligible LLM commands to approval queue instead of auto-execution; expanded `_FORBIDDEN_CHAT_TOOLS`; locked `SettingsSaveView.post` to `userTier` with `OLLAMA_HOST` URL validation. | `tests/security/test_p1_service_hardening.py` |
| **Approval Queue Integrity** (`core/platform_store.py`, `platform_api.py`, `runtime.py`) | Bound `decided_by` to authenticated `userTier` identity; separated redacted display fields from raw execution fields; computed & verified immutable SHA-256 `proposal_digest`; allowlisted `payload["kind"]` and `payload["mode"]`. | `tests/security/test_p1_service_hardening.py` |
| **Burp Gateway** (`core/burp_gateway/gateway.py`) | Enforced loopback bind (`127.0.0.1`) by default and timing-safe (`hmac.compare_digest`) `X-Hunter-Token` / `Authorization: Bearer` middleware. | `tests/security/test_p1_service_hardening.py`, `tests/test_burp_gateway.py` |
| **Go ARTEX-Pro** (`backend/`) | Default loopback bind `127.0.0.1:7071` (`ARTEX_BIND_ADDR`), `subtle.ConstantTimeCompare` bearer auth on `/api/v1/scan`, strict CORS allowlist (no `*`), fail-closed IPv4/IPv6 private/metadata SSRF check (`ARTEX_ALLOW_LOCAL_SCAN=1` opt-in), removed hardcoded DB password default, configurable `sslmode`. | `cd backend && go test -race ./...` |
| **BugHunter MCP, Brain & Shell Tools** (`bughunter/`) | Removed `args["approve"]` bypass and `scope_domains` mutation in `bughunter-mcp/policy/engine.py`, switched to `hmac.compare_digest`; replaced `shell=True` in `bughunter/brain.py` with `subprocess.run(..., shell=False)` + `_EXPLOIT_ENV_ALLOWLIST`; removed default `curl -k` from 4 shell scanners. | `tests/security/test_p1_service_hardening.py` |
| **MCP & Installer Supply Chain** (`opencode.json`, `install_agent.ps1`) | Replaced hardcoded machine-specific paths with portable workspace paths, disabled remote MCP servers (`context7`, `gh_grep`) by default, and pinned npm MCP package versions. | `tests/security/test_p1_service_hardening.py`, `tests/test_web_api_exhaustive.py` |

---

## 2. Operational Limitations & Scope Notes

- Local bearer authentication protects localhost/LAN control-plane boundaries; exposing HunterAI on untrusted networks additionally requires TLS termination at a reverse proxy explicitly listed in `HUNTERAI_TRUSTED_PROXIES`.
- External third-party binaries invoked through the allowlisted tool registry (e.g., `nmap`, `nuclei`, `subfinder`) execute under the local OS user account unless deployed inside an isolated container sandbox.
