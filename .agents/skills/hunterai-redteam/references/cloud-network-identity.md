# Cloud, identity, network, host, container, and CI/CD testing

Inventory users, roles, groups, service and workload identities, keys, tokens, federation, trust policies, ACLs, delegated permissions, cross-account paths, and automation identities. Resolve effective permissions from every policy and condition.

Map cloud organizations/projects/accounts/subscriptions, IAM, storage, compute, serverless, secrets, KMS, registries, networking, metadata and managed identities, logging, Kubernetes, containers, hosts, CI/CD, and deployment authority. For Active Directory, include forests, trusts, delegation, certificate services, service accounts, ACLs, GPOs, authentication protocols, and management services.

Test credential reach, role assumption, impersonation, pass-role, policy mutation, storage and secret access, metadata paths, container privilege, host mounts, cluster RBAC, untrusted build input, runner isolation, cache/artifact poisoning, AD ticket and relay paths, certificates, segmentation, DNS, proxies, TLS, and management interfaces.

Record the initiating identity, exact permission or trust edge, request or command, resource, observed result, and resulting state. Do not infer a later step in a chain from an earlier permission without execution or source evidence.

## Subdomain takeover & BaaS/cloud exposure checklist

- **Subdomain Takeover**: Resolve dangling `CNAME`, `NS`, and `A` records against verified provider signatures in `wordlists/pentesterflow/takeover/fingerprints.json`. Confirm unclaimed service fingerprint AND exact claimability condition before elevating beyond `CANDIDATE`.
- **Managed BaaS & Object Storage**: Audit public buckets (S3, GCS, Azure Blob, Supabase Storage) and PostgREST tables (`wordlists/pentesterflow/supabase/common-tables.txt`) for unauthorized read/write/list access and overly permissive RLS/IAM policies.
- **Metadata & Container Boundaries**: Verify IMDSv2 hop limits, workload-identity token scoping, `CapDrop: ALL`, `no-new-privileges`, read-only rootfs, and absence of host socket/namespace escapes.
