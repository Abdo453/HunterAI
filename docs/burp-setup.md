# Burp Adapter Integration Setup — Phase F

## Overview

`core/burp_adapter.py` provides a stable interface for integrating with **Burp Suite Professional/Community**, layered over `core/burp_gateway/` (local gateway on `127.0.0.1:8085`, traffic store, findings exporter, and provenance engine).

## Integration Architecture

> **Burp Suite does not expose an official public REST API** callable directly from Python. Burp's official API is the **Java Extension API (BApp / `IBurpExtenderCallbacks`)**.

The integration uses this flow:
1. Install the Burp Suite extension (BApp) in Burp (see `agents/burp_agent/integrations/burp_extension/`).
2. The extension forwards captured HTTP traffic (Proxy / Repeater) to the local HunterAI gateway (`BurpGateway` on `127.0.0.1:8085`).
3. `BurpAdapter` reads from the gateway over local HTTP and exposes a stable interface to the coordinator.

## Files

| File | Role |
|---|---|
| `core/burp_adapter.py` | Burp adapter (9 stable operations) + shared `GLOBAL_BURP_ADAPTER` instance |
| `core/burp_gateway/` | Existing infrastructure: gateway, traffic store, findings exporter, provenance engine |
| `config/burp.example.json` | Example configuration (no real secrets) |
| `docs/burp-setup.md` | This document |
| `tests/test_burp_adapter.py` | Unit tests (mocked, no external systems) |

## Supported Operations

| Operation | Description |
|---|---|
| `health_check` | Check Burp gateway reachability and responsiveness |
| `get_available_capabilities` | Discover supported capabilities without claiming unsupported ones |
| `retrieve_authorized_http_history` | Retrieve authorized HTTP traffic after scope checks |
| `retrieve_request` / `retrieve_response` | Retrieve a specific sanitized transaction |
| `submit_supported_analysis_job` | Submit a supported analysis job (e.g., passive scan) |
| `retrieve_analysis_results` | Retrieve analysis job results |
| `import_supported_findings` | Import findings with recorded provenance |
| `export_supported_findings` | Export findings to Burp `IScanIssue` JSON format |

## Setup (Local)

1. Install the Hunter Burp Suite extension (BApp) in Burp.
2. Start the local HunterAI gateway (`BurpGateway` on `127.0.0.1:8085`).
3. Edit `config/burp.example.json` and set `gateway_base_url` and the authorized scope.
4. Load the configuration in your application:
   ```python
   from core.burp_adapter import BurpAdapter, BurpAdapterConfig

   cfg = BurpAdapterConfig(gateway_base_url="http://127.0.0.1:8085")
   adapter = BurpAdapter(config=cfg)
   await adapter.health_check()
   ```

## Security

- Cookies, `Authorization` headers, and tokens are redacted before sending any traffic to an external model.
- Provenance is recorded for every finding imported from Burp.
- A finding is never marked as confirmed unless explicitly verified by Burp (`verified_by_burp`).
- All operations pass through scope enforcement (`ScopeEnforcer`) before retrieving external traffic.
- Cloud metadata services and loopback / RFC1918 addresses are blocked unless explicitly authorized.

## Degraded Mode

If the Burp extension is not installed or Burp is unreachable, the adapter falls back to degraded mode:
- Every operation returns an `"unavailable"` error without crashing.
- `health_check` returns `available: false`.
- Users can continue other tasks without system disruption.

## Limitations

- Integration works through the Burp extension (BApp) forwarding traffic to the local gateway, not an official Burp REST API.
- GUI scraping is not used as a default integration mechanism.
- For testing against a live Burp instance, use an isolated environment with an approved extension.
