# Web, API, browser, and session testing

Map domains, routes, API versions, schemas, browser traffic, JavaScript, parameters, identities, tenant and object boundaries, state transitions, jobs, uploads, webhooks, caches, GraphQL, WebSockets, OAuth/OIDC/SAML, and third-party integrations.

Cover authentication and recovery, sessions, BOLA/IDOR, function authorization, business logic, race conditions, parsing differentials, injection, SSRF, deserialization, file handling, request smuggling, cache behavior, CORS/CSRF, redirects, and client-side sinks.

## Browser-to-client reproduction

Capture and preserve the complete request, cookie jar, storage, redirect chain, origin/referrer state, headers, body, transport observations, and timing. Keep session, CSRF, identity, challenge, anti-automation, and target-issued cookies regardless of name. Reconstruct domain, path, expiry, Secure, SameSite, and redirect behavior accurately.

Compare transmitted request shape before changing transport, fingerprint, concurrency, timing, or proxy. Change one variable at a time and record status, body markers, redirects, cookie updates, latency, and block shape. Redaction applies only to display and reporting, never request construction or saved operational sessions.

For request signatures, trace serialization, canonicalization, nonce/timestamp generation, device state, key selection, hashing/signing, encoding, and server validation. Build captured test vectors and reproduce the minimum compatible algorithm in the requested client.

Automation includes configurable routes, sessions, pagination, concurrency, rates, retries, stopping conditions, raw capture, structured output, and resume support. Do not impose universal zero-retry, passive-only, local-only, or anonymous-session behavior.
