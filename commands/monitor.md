---
description: Continuous monitor mode for a target — baseline passive subdomain surface (crt.sh) + homepage JS bundle hashes, then diff on schedule; new subs / retired subs / changed bundles append to artifacts/<target>/monitor/alerts.jsonl. Usage /monitor baseline target.com | /monitor check target.com | /monitor watch target.com --interval 3600
---

# /monitor

## Usage

```
/monitor baseline target.com     # snapshot once (passive only — no active probing)
/monitor check target.com        # one diff cycle, prints delta groups
/monitor watch target.com        # loop every 3600s (Ctrl-C to stop)
```

Backing script: `scripts/monitor_surface.py` (stdlib-only). State lives in
`artifacts/<target>/monitor/`. Alert-worthy deltas: new subdomain, new JS
bundle, changed bundle hash (JS change = new attack surface to re-grep for
secrets). Feed deltas into hunt memory:

```
python pentest.py memory-write event <target> <delta-summary>
```

Never widen authorization scope because monitoring found a new asset — check
the grant first (`scripts/authorize_full_power.py check --target`).
