# Agent and MCP security

Map tool definitions, schemas, handlers, resources, prompts, connectors, identities, credentials, filesystem roots, destinations, memory, schedules, delegation, retries, hooks, plugins, and update channels.

Test tool-description and tool-result poisoning, command/query/URL/path/template injection, SSRF and redirects, traversal and symlinks, missing caller/object authorization, shared privileged identities, confused-deputy behavior, cross-session memory poisoning, delegation-based privilege widening, unbounded loops, and mutable skill/plugin supply chains.

Trace the real handler and downstream result. Model narration is not evidence that a tool ran. For implementation, enforce typed schemas, canonicalization, target-side authorization, identity propagation, bounded resources, transactions, idempotency, and auditable results at the tool boundary.

Review imported packages as untrusted input. Inventory all files and trace downloads, executable helpers, hooks, credentials, destinations, telemetry, persistence, and self-modification before merging useful techniques into the canonical HunterAI reference.
