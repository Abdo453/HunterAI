# HunterAI — Verified Security Architecture & Controls

This document describes the concrete security controls implemented and verified in the HunterAI repository (`hunter_backend/`, `core/`, `backend/`, `bughunter/`, and `opencode.json`). It omits unverified or external compliance claims and reflects only behavior backed by source code and automated tests.

---

## 1. Control Plane Authentication, Session Revocation & CSRF (`hunter_backend/`)

| Control | Implementation | Verification |
| :--- | :--- | :--- |
| **Local Bearer Authentication** | `hunter_backend/auth.py` + `LocalAuthMiddleware` (`hunter_backend/middleware.py`). Generates a 32-byte CSPRNG local bearer token (`HUNTER_API_TOKEN` or `data/root_controller/.api_token`, `0o600`). Protected `/api/*` endpoints fail closed with `401 Unauthorized` when unauthenticated; only `/api/health`, `/api/csrf`, `/api/platform/artex/health`, and top-level UI redirects are publicly readable. | `tests/security/test_p1_service_hardening.py` |
| **PBKDF2-SHA512 Key Derivation** | `derive_domain_key()` derives domain-separated keys via `hashlib.pbkdf2_hmac("sha512", ...)` for operator session signing, agent token signing, and constant-time HMAC token verification. | `tests/security/test_p1_service_hardening.py` |
| **Session Generation (`sgn`) Revocation** | Signed `hunter_session` cookies and `hnt1.*` bearer tokens embed a monotonic session generation counter (`sgn`). Calling `POST /api/auth/revoke` (or `revoke_all_sessions()`) increments `sgn` and invalidates all prior sessions immediately. | `tests/security/test_p1_service_hardening.py` |
| **Privilege Tier Separation** | `userTier` (human operator bearer or CSRF-verified session) vs `tokenTier` (agent/read token). Approval decisions (`/api/platform/approvals/<id>/decide`), `.env` settings writes (`/api/settings/save`), red-team grant issuance/revocation, and editor writes require `userTier`; `tokenTier` receives `403 Forbidden`. | `tests/security/test_p1_service_hardening.py` |
| **Brute-Force Protection & Trusted Proxies** | `LoginGuard` rate-limits repeated invalid auth attempts (`429 Too Many Requests` + `Retry-After`) keyed by `extract_client_ip()`, which ignores `X-Forwarded-For` unless `REMOTE_ADDR` is explicitly listed in `TRUSTED_PROXIES` (`HUNTERAI_TRUSTED_PROXIES`). | `tests/security/test_p1_service_hardening.py` |
| **CSRF & Origin Guard** | `ApiCsrfAndJsonGuardMiddleware` rejects untrusted `Origin`, `Sec-Fetch-Site: cross-site`, simple `text/plain` / `application/x-www-form-urlencoded` mutations, and non-allowlisted multipart uploads. Non-bearer state-changing requests (including `application/json` POSTs) MUST include both a trusted `Origin` and a valid double-submit `X-CSRFToken`. | `tests/security/test_p1_service_hardening.py`, `tests/test_security_boundaries_django.py` |
| **WebSocket Origin & Auth Guard** | `hunter_backend/websocket.py`: `is_ws_origin_allowed(origin, has_valid_bearer=...)` fails closed (`False`) when `origin is None` without valid bearer auth, rejects untrusted origins (`4403`) and invalid credentials (`4401`), and requires `userTier` for run control actions (`pause`/`resume`/`stop`). | `tests/security/test_p1_service_hardening.py`, `tests/test_security_boundaries_django.py` |
| **Strict Content-Security-Policy** | `SecurityHeadersMiddleware` sets `Content-Security-Policy` (`hunter_backend/settings.py`) without `'unsafe-inline'` or `'unsafe-eval'`, plus `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, and `Referrer-Policy`. | `tests/security/test_p1_service_hardening.py` |

---

## 2. Execution Containment, SSRF & Approval Integrity

- **HTTP Editor Sandbox (`hunter_backend/apps/intelligence_api.py`):** `EDITOR_ALLOWED_ROOTS` is restricted strictly to non-code workspace roots (`skills/`, `data/reports/`, `scratch/`) verified with `Path.is_relative_to`. Executable source trees (`core/`, `scripts/`, `tools/`, `agents/`, `bughunter/`) and sensitive files (`.env*`, `.git/`, `.api_token`, `.policy_secret`, private keys) return `403 Forbidden`.
- **Shell-Free Subprocess Allowlist (`hunter_backend/apps/common.py`, `arsenal_api.py`):** `run_command_no_shell`, `arsenal_run_view`, `run_tool_view`, `control_tools_test_view`, and `SandboxRunView` execute via `create_subprocess_exec` (`shell=False`), validate BOTH `str` and `list` commands against `_SHELL_META_TOKENS` / `_TOOL_SHELL_META_RE` (including `(`, `)`, `\n`, `;`, `|`, `&`, `$`, `` ` ``), and enforce a strict security-tool binary allowlist that blocks interpreters, shells, and downloaders (`python`, `python3`, `node`, `sh`, `bash`, `cmd`, `powershell`, `pwsh`, `curl`, `wget`).
- **Chat Auto-Execution Disabled (`hunter_backend/apps/copilot_api.py`):** `legacy_api_chat_view` defaults `allow_exec=False` and `authorized=False`, expands `_FORBIDDEN_CHAT_TOOLS`, and never auto-executes LLM markdown ```` ```bash ``` ```` blocks—allowlisted proposals are queued into the HITL approval store instead. `SettingsSaveView.post` requires `userTier` and validates `OLLAMA_HOST` against SSRF/metadata/scheme injection.
- **Approval Identity Binding & Tamper Detection (`core/platform_store.py`, `platform_api.py`, `runtime.py`):** `create_approval()` computes an immutable SHA-256 `proposal_digest` over canonical JSON (`action_type`, `tool_name`, `target`, `raw_command_args`, `engagement_id`, `scope`) and stores redacted `display_target`/`display_command_args` separately from raw execution fields. `platform_approval_decide_view` binds `decided_by` to the authenticated `userTier` caller and rejects tampered digests (`403`). `execute_approved_action()` re-verifies `proposal_digest` and enforces strict allowlists on `payload["kind"]` and `payload["mode"]`.
- **SSRF & Outbound Proxy Validation:** `validate_http_url_ssrf_and_scope` and `validate_proxy_url` enforce `http`/`https` schemes, block cloud metadata (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, `metadata.google.internal`, `metadata.internal`, `instance-data`), link-local, unspecified (`0.0.0.0`, `::`), and DNS-rebound internal targets. `burp_repeater_send_view` blocks internal/metadata/non-HTTP(S) proxies unless explicitly allowlisted via `HUNTER_ALLOWED_PROXIES`.

---

## 3. Service Plane: Burp Gateway, Go ARTEX-Pro & BugHunter MCP

- **Burp Gateway (`core/burp_gateway/gateway.py`):** Refuses non-loopback binds unless `HUNTER_BURP_GATEWAY_ALLOW_REMOTE=1`, auto-generates a CSPRNG bearer token on `start()`, and validates `X-Hunter-Token` / `Authorization: Bearer` with `hmac.compare_digest` whenever a token is configured or generated.
- **Go ARTEX-Pro (`backend/cmd/server/main.go`, `backend/internal/api/server.go`, `backend/internal/database/db.go`):**
  - Binds `127.0.0.1:7071` by default (configurable via `ARTEX_BIND_ADDR`).
  - Enforces constant-time bearer auth (`subtle.ConstantTimeCompare` against `ARTEX_API_TOKEN` / `HUNTER_API_TOKEN` / CSPRNG startup fallback) on `/api/v1/scan`.
  - Restricts CORS strictly to allowlisted local origins (`127.0.0.1:3000`, `localhost:3000`, `127.0.0.1:8000`, `localhost:8000` or `ARTEX_ALLOWED_ORIGINS`), rejecting wildcards `*` and `null`.
  - Blocks private/loopback IPv4/IPv6 (including IPv4-mapped, ULA `fc00::/7`, NAT64 `64:ff9b::/96`, CGNAT) and cloud metadata targets by default (`ARTEX_ALLOW_LOCAL_SCAN=1` opt-in for local labs; metadata remains non-overridable).
  - Removes hardcoded database password defaults and supports configurable PostgreSQL `sslmode` (`ARTEX_DB_SSLMODE`, defaulting to `require` for non-loopback hosts).
- **BugHunter MCP & Shell Tools (`bughunter/`):**
  - `bughunter/mcp/bughunter-mcp/policy/engine.py` removes untrusted `args["approve"]` self-approval and `args["scope_domains"]` scope mutation, and verifies `approval_token` using `hmac.compare_digest`.
  - `bughunter/brain.py` executes commands via `subprocess.run(..., shell=False)` with `_EXPLOIT_ENV_ALLOWLIST`.
  - `bughunter/tools/{bypass_403,secrets_hunter,takeover_scanner,vuln_scanner}.sh` verify TLS certificates by default (insecure `-k` requires explicit `--insecure` or `HUNTER_LAB_INSECURE_TLS=1`).
- **OpenCode MCP Supply Chain (`opencode.json`, `install_agent.ps1`):** Uses portable relative workspace paths, disables remote MCP servers (`context7`, `gh_grep`) by default, and pins npm MCP package versions instead of `@latest`.
