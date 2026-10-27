# Authorized Red-Team Mode

`core/policy/red_team.py` is the zero-friction execution policy for engagements
where the operator holds **explicit, signed authorization**.

It exists because "authorized" should not mean "clicking Approve 400 times".
It does **not** exist to remove the boundaries that make a pentest legal and
safe.

## Profiles

| Profile | Allowed action classes | Risk ceiling | Approval |
|---|---|---|---|
| `safe` | `read_only` | low | none |
| `standard` | `read_only`, `active_test`, `proof_write`, `exploit_proof` | high | `exploit_proof` |
| `red_team` | `read_only`, `active_test`, `proof_write`, `exploit_proof` | **critical** | **none** |

`red_team` is the mode for an authorized engagement: no prompts, critical-risk
actions allowed, every catalog tool eligible.

## Hard invariants (denied in every profile, every grant)

These are enforced before the grant is even checked:

| Forbidden action | Examples |
|---|---|
| `BACKDOOR`, `PERSISTENCE` | webshells, cron/systemd/registry persistence, SSH key injection |
| `C2` | reverse shells, bind shells, beaconing |
| `LATERAL_MOVEMENT` | pivoting to hosts outside the grant |
| `DESTRUCTIVE_WRITE` | SQL `DELETE`/`UPDATE`/`DROP`/`TRUNCATE`, `rm -rf`, disk format, shutdown |
| `EVASION` | log clearing, disabling audit/EDR, timestomping |
| `DATA_EXFILTRATION` | bulk copying real user data |
| `CREDENTIAL_DUMP` | dumping password stores or hashes at scale |

A signed grant is a legal permission to test a target. It is not a permission
to turn the target into malware infrastructure. Proof is still fully allowed:

- SQL injection → read-only boolean/time-based proof, never a write.
- RCE → `id` / `whoami`, never persistence.
- SSRF → an operator-owned out-of-band listener.
- IDOR → two-account differential testing with canary data.

## Create a grant

The signing secret comes from `HUNTERAI_POLICY_SECRET`; keep it out of the
repository.

```powershell
$env:HUNTERAI_POLICY_SECRET = "<engagement secret>"

python -m core.policy.red_team grant `
  --scope example.com `
  --scope api.example.com `
  --days 7 `
  --authorized-by "Acme Security (signed SOW #123)" `
  --out authorization_grant.json
```

The grant is an HMAC-SHA256-signed JSON document:

```json
{
  "grant_id": "ENG-33eda86e",
  "authorized_by": "Acme Security (signed SOW #123)",
  "scope": [{"kind": "domain", "value": "example.com"}],
  "not_before": 1793131600.0,
  "not_after": 1793736400.0,
  "profiles": ["red_team"],
  "signature": "..."
}
```

Editing the scope, dates, or profiles invalidates the signature.

## Check an action

```powershell
python -m core.policy.red_team check `
  --grant authorization_grant.json `
  --target https://api.example.com/login `
  --class exploit_proof `
  --risk critical
```

Allowed:

```json
{
  "allowed": true,
  "requires_approval": false,
  "reason": "authorized by grant 'ENG-33eda86e' (Acme Security) under profile 'red_team'"
}
```

Denied (hard invariant):

```json
{
  "allowed": false,
  "reason": "hard invariant: persistence/backdoor/reverse-shell pattern detected"
}
```

Denied (out of scope):

```json
{
  "allowed": false,
  "reason": "target 'https://example.org/' is outside the authorized scope"
}
```

## Use it in code

```python
from core.policy.red_team import (
    ActionClass,
    ActionRequest,
    AuditLog,
    Profile,
    RedTeamPolicyEngine,
    load_grant,
)

grant = load_grant("authorization_grant.json")
engine = RedTeamPolicyEngine(
    grant,
    Profile.RED_TEAM,
    secret=os.environ["HUNTERAI_POLICY_SECRET"].encode(),
    audit_log=AuditLog("data/audit/engagement.jsonl"),
)

decision = engine.evaluate(
    ActionRequest(
        target="https://api.example.com/login",
        action_class=ActionClass.EXPLOIT_PROOF,
        tool_id="sqlmap",
        risk_level="critical",
        operation="boolean-based read-only proof",
    )
)
if not decision.allowed:
    raise PermissionError(decision.reason)
```

## Audit trail

Every decision is appended to a JSONL hash chain. Each record contains the
previous record's hash, so deleting or editing an entry breaks `AuditLog.verify()`.

## Scope matching

| Kind | Match rule |
|---|---|
| `domain` | exact host or any subdomain (`example.com` matches `api.example.com`, never `evilexample.com`) |
| `host` | exact host, port ignored |
| `cidr` | IP membership in the network |
| `url` | scheme + host + port + path prefix |

## Tests

```powershell
python -m pytest tests/test_red_team_policy.py -q
# 30 passed
```
