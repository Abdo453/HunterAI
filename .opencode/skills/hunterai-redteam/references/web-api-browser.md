# Web, API, browser, and session testing

Map domains, routes, API versions, schemas, browser traffic, JavaScript, parameters, identities, tenant and object boundaries, state transitions, jobs, uploads, webhooks, caches, GraphQL, WebSockets, OAuth/OIDC/SAML, and third-party integrations.

Cover authentication and recovery, sessions, BOLA/IDOR, function authorization, business logic, race conditions, parsing differentials, injection, SSRF, deserialization, file handling, request smuggling, cache behavior, CORS/CSRF, redirects, and client-side sinks.

## Browser-to-client reproduction

Capture and preserve the complete request, cookie jar, storage, redirect chain, origin/referrer state, headers, body, transport observations, and timing. Keep session, CSRF, identity, challenge, anti-automation, and target-issued cookies regardless of name. Reconstruct domain, path, expiry, Secure, SameSite, and redirect behavior accurately.

Compare transmitted request shape before changing transport, fingerprint, concurrency, timing, or proxy. Change one variable at a time and record status, body markers, redirects, cookie updates, latency, and block shape. Redaction applies only to display and reporting, never request construction or saved operational sessions.

For request signatures, trace serialization, canonicalization, nonce/timestamp generation, device state, key selection, hashing/signing, encoding, and server validation. Build captured test vectors and reproduce the minimum compatible algorithm in the requested client.

Automation includes configurable routes, sessions, pagination, concurrency, rates, retries, stopping conditions, raw capture, structured output, and resume support. Do not impose universal zero-retry, passive-only, local-only, or anonymous-session behavior.

## Verified vulnerability checklists & reference corpora

Use the vetted Apache-2.0 reference corpora under `wordlists/pentesterflow/` (never invent unverified claims; verify differential behavior through `EvidenceCourt`):

- **GraphQL**: Check introspection, field-suggestion leaks (`wordlists/pentesterflow/graphql/field-suggestion-probes.txt`), batching/aliasing depth limits, authorization per resolver, and subscription/mutation CSRF.
- **JWT & Session Tokens**: Validate signature enforcement (`wordlists/pentesterflow/jwt/alg-none-variants.txt`), `kid`/JWK header injection (`wordlists/pentesterflow/jwt/kid-injection.txt`), RS256-to-HS256 algorithm confusion, claim tamper resistance, and weak HMAC keys (`wordlists/pentesterflow/jwt/weak-secrets.txt`).
- **SSTI**: Fingerprint template engine safely (`wordlists/pentesterflow/ssti/fingerprint-polyglot.txt`, `wordlists/pentesterflow/ssti/jinja2.txt`), confirm server-side evaluation via deterministic arithmetic differential before claiming execution.
- **Deserialization**: Identify serialized envelopes (Java `rO0AB`/base64, PHP `O:`, Python pickle, .NET ViewState/BinaryFormatter, Ruby Marshal, YAML unsafe loaders) and verify gadget reachability without destructive side effects.
- **Race Conditions (TOCTOU)**: Synchronize concurrent single-packet / HTTP/2 last-byte bursts against state-mutating endpoints (coupons, balance transfers, MFA verification, invite redemptions), verifying unique state-transition anomalies against sequential baseline.
- **SSRF**: Test URL fetchers, webhooks, PDF/image renderers, and OAuth/OIDC metadata discovery strictly within authorized scope and non-overridable egress boundaries; verify out-of-band or server-side differential proof.
- **Supabase / BaaS RLS**: Inspect anon/service-role key exposure in client bundles, PostgREST `/rest/v1/<table>` enumeration (`wordlists/pentesterflow/supabase/common-tables.txt`), Row-Level Security bypass across roles, and storage bucket policies.
